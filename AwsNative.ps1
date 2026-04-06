#Requires -Version 7.0
<#
.SYNOPSIS
    Native PowerShell AWS SigV4 signing and SSM API client.
    Replaces the AWS CLI dependency for SSM API calls.
#>

# ── INI File Parser ─────────────────────────────────────────────────────────

function Read-IniFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return @{} }
    $sections = [ordered]@{}
    $current = ''
    foreach ($line in (Get-Content $Path)) {
        $line = $line.Trim()
        if ($line -eq '' -or $line.StartsWith('#') -or $line.StartsWith(';')) { continue }
        if ($line -match '^\[(.+)\]$') {
            $current = $Matches[1].Trim()
            if (-not $sections.Contains($current)) { $sections[$current] = @{} }
        } elseif ($current -ne '' -and $line -match '^([^=]+?)\s*=\s*(.*)$') {
            $sections[$current][$Matches[1].Trim().ToLower()] = $Matches[2].Trim()
        }
    }
    $sections
}

# ── Credential Resolution ───────────────────────────────────────────────────

function Get-AwsRegion {
    param([string]$Region, [string]$Profile)
    if ($Region) { return $Region }
    if ($env:AWS_REGION) { return $env:AWS_REGION }
    if ($env:AWS_DEFAULT_REGION) { return $env:AWS_DEFAULT_REGION }

    $configPath = if ($env:AWS_CONFIG_FILE) { $env:AWS_CONFIG_FILE } else { Join-Path $HOME '.aws/config' }
    $cfg = Read-IniFile $configPath
    $profName = if ($Profile -and $Profile -ne 'default') { "profile $Profile" } else { 'default' }
    if ($cfg.Contains($profName) -and $cfg[$profName].ContainsKey('region')) {
        return $cfg[$profName]['region']
    }
    if ($profName -ne 'default' -and $cfg.Contains('default') -and $cfg['default'].ContainsKey('region')) {
        return $cfg['default']['region']
    }
    throw 'No AWS region found. Set -Region parameter, AWS_REGION env var, or region in ~/.aws/config.'
}

function Get-AwsSsoCredential {
    param(
        [System.Collections.Specialized.OrderedDictionary]$Config,
        [string]$ProfileSection
    )
    $prof = $Config[$ProfileSection]
    $accountId = $prof['sso_account_id']
    $roleName  = $prof['sso_role_name']

    # Get SSO session info
    $ssoRegion = $null; $startUrl = $null
    if ($prof.ContainsKey('sso_session')) {
        $sessName = $prof['sso_session']
        $sessKey = "sso-session $sessName"
        if ($Config.Contains($sessKey)) {
            $ssoRegion = $Config[$sessKey]['sso_region']
            $startUrl  = $Config[$sessKey]['sso_start_url']
        }
    }
    if (-not $ssoRegion) { $ssoRegion = $prof['sso_region'] }
    if (-not $startUrl)  { $startUrl  = $prof['sso_start_url'] }
    if (-not $ssoRegion -or -not $startUrl) {
        throw "SSO profile '$ProfileSection' missing sso_region or sso_start_url."
    }

    # Find the SSO token from cache (search all cache files for matching startUrl with valid accessToken)
    $cacheDir = Join-Path $HOME '.aws/sso/cache'
    $accessToken = $null
    if (Test-Path $cacheDir) {
        foreach ($f in (Get-ChildItem $cacheDir -Filter '*.json')) {
            try {
                $cached = ConvertFrom-Json (Get-Content $f.FullName -Raw)
                if ($cached.startUrl -eq $startUrl -and $cached.accessToken) {
                    $expires = [DateTime]::Parse($cached.expiresAt).ToUniversalTime()
                    if ($expires -gt [DateTime]::UtcNow) {
                        $accessToken = $cached.accessToken
                        break
                    }
                }
            } catch { continue }
        }
    }
    if (-not $accessToken) {
        throw "No valid SSO token found for '$startUrl'. Run: aws sso login --profile $($ProfileSection -replace '^profile ','')"
    }

    # Call SSO GetRoleCredentials API (unauthenticated - uses Bearer token)
    $ssoEndpoint = "https://portal.sso.$ssoRegion.amazonaws.com/federation/credentials"
    $queryParams = "account_id=$([uri]::EscapeDataString($accountId))&role_name=$([uri]::EscapeDataString($roleName))"
    $resp = Invoke-WebRequest -Uri "$ssoEndpoint`?$queryParams" -Method GET `
        -Headers @{ 'x-amz-sso_bearer_token' = $accessToken } -UseBasicParsing
    $rc = ConvertFrom-Json $resp.Content
    [PSCustomObject]@{
        AccessKeyId     = $rc.roleCredentials.accessKeyId
        SecretAccessKey  = $rc.roleCredentials.secretAccessKey
        SessionToken     = $rc.roleCredentials.sessionToken
    }
}

function Get-AwsCredential {
    param([string]$Profile)
    # 1. Environment variables
    if ($env:AWS_ACCESS_KEY_ID -and $env:AWS_SECRET_ACCESS_KEY) {
        return [PSCustomObject]@{
            AccessKeyId     = $env:AWS_ACCESS_KEY_ID
            SecretAccessKey  = $env:AWS_SECRET_ACCESS_KEY
            SessionToken     = $env:AWS_SESSION_TOKEN
        }
    }
    # 2. Credentials file
    $credPath = if ($env:AWS_SHARED_CREDENTIALS_FILE) { $env:AWS_SHARED_CREDENTIALS_FILE } else { Join-Path $HOME '.aws/credentials' }
    $creds = Read-IniFile $credPath
    $profKey = if ($Profile) { $Profile } else { 'default' }
    if ($creds.Contains($profKey) -and $creds[$profKey].ContainsKey('aws_access_key_id')) {
        $s = $creds[$profKey]
        return [PSCustomObject]@{
            AccessKeyId     = $s['aws_access_key_id']
            SecretAccessKey  = $s['aws_secret_access_key']
            SessionToken     = if ($s.ContainsKey('aws_session_token')) { $s['aws_session_token'] } else { $null }
        }
    }
    # 3. Config file (static credentials)
    $configPath = if ($env:AWS_CONFIG_FILE) { $env:AWS_CONFIG_FILE } else { Join-Path $HOME '.aws/config' }
    $cfg = Read-IniFile $configPath
    $cfgKey = if ($profKey -eq 'default') { 'default' } else { "profile $profKey" }
    if ($cfg.Contains($cfgKey) -and $cfg[$cfgKey].ContainsKey('aws_access_key_id')) {
        $s = $cfg[$cfgKey]
        return [PSCustomObject]@{
            AccessKeyId     = $s['aws_access_key_id']
            SecretAccessKey  = $s['aws_secret_access_key']
            SessionToken     = if ($s.ContainsKey('aws_session_token')) { $s['aws_session_token'] } else { $null }
        }
    }
    # 4. SSO credentials
    if ($cfg.Contains($cfgKey) -and $cfg[$cfgKey].ContainsKey('sso_account_id')) {
        return Get-AwsSsoCredential -Config $cfg -ProfileSection $cfgKey
    }
    throw "No AWS credentials found. Checked: environment variables, $credPath [$profKey], $configPath [$cfgKey]."
}

# ── SigV4 Signing ──────────────────────────────────────────────────────────

function _BytesToHex([byte[]]$b) {
    $sb = [System.Text.StringBuilder]::new($b.Length * 2)
    foreach ($byte in $b) { $null = $sb.Append($byte.ToString('x2')) }
    $sb.ToString()
}

function _HmacSha256([byte[]]$Key, [byte[]]$Data) {
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try { $hmac.ComputeHash($Data) } finally { $hmac.Dispose() }
}

function ConvertTo-SigV4Auth {
    param(
        [string]$Method,
        [uri]$Uri,
        [System.Collections.Specialized.OrderedDictionary]$Headers,
        [string]$Body,
        [string]$Service,
        [string]$Region,
        [PSCustomObject]$Cred
    )
    $enc = [System.Text.Encoding]::UTF8
    $now = [DateTime]::UtcNow
    $dateStamp = $now.ToString('yyyyMMdd')
    $dateTime  = $now.ToString('yyyyMMddTHHmmssZ')

    # Add date header
    $Headers['x-amz-date'] = $dateTime
    if ($Cred.SessionToken) {
        $Headers['x-amz-security-token'] = $Cred.SessionToken
    }

    # Canonical headers (sorted lowercase keys)
    $sortedKeys = @($Headers.Keys | Sort-Object { $_.ToLower() })
    $canonHeaders = ($sortedKeys | ForEach-Object { "$($_.ToLower()):$($Headers[$_].Trim())" }) -join "`n"
    $signedHeaders = ($sortedKeys | ForEach-Object { $_.ToLower() }) -join ';'

    # Payload hash
    $payloadHash = _BytesToHex ([System.Security.Cryptography.SHA256]::HashData($enc.GetBytes($Body)))

    # Canonical request
    $canonReq = "$Method`n$($Uri.AbsolutePath)`n`n$canonHeaders`n`n$signedHeaders`n$payloadHash"
    $canonReqHash = _BytesToHex ([System.Security.Cryptography.SHA256]::HashData($enc.GetBytes($canonReq)))

    # Credential scope
    $scope = "$dateStamp/$Region/$Service/aws4_request"

    # String to sign
    $stringToSign = "AWS4-HMAC-SHA256`n$dateTime`n$scope`n$canonReqHash"

    # Signing key
    $kDate    = _HmacSha256 ($enc.GetBytes("AWS4$($Cred.SecretAccessKey)")) ($enc.GetBytes($dateStamp))
    $kRegion  = _HmacSha256 $kDate ($enc.GetBytes($Region))
    $kService = _HmacSha256 $kRegion ($enc.GetBytes($Service))
    $kSigning = _HmacSha256 $kService ($enc.GetBytes('aws4_request'))

    # Signature
    $sig = _BytesToHex (_HmacSha256 $kSigning ($enc.GetBytes($stringToSign)))

    # Authorization header
    $auth = "AWS4-HMAC-SHA256 Credential=$($Cred.AccessKeyId)/$scope, SignedHeaders=$signedHeaders, Signature=$sig"
    $Headers['Authorization'] = $auth
    $Headers
}

# ── SSM API Client ──────────────────────────────────────────────────────────

function Invoke-AwsSsmApi {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][hashtable]$Body,
        [string]$Profile,
        [string]$Region
    )
    $resolvedRegion = Get-AwsRegion -Region $Region -Profile $Profile
    $cred = Get-AwsCredential -Profile $Profile
    $endpoint = "https://ssm.$resolvedRegion.amazonaws.com"
    $jsonBody = ConvertTo-Json $Body -Compress -Depth 20
    $host_ = "ssm.$resolvedRegion.amazonaws.com"

    $headers = [ordered]@{
        'content-type' = 'application/x-amz-json-1.1'
        'host'         = $host_
        'x-amz-target' = "AmazonSSM.$Action"
    }

    $signed = ConvertTo-SigV4Auth -Method 'POST' -Uri ([uri]$endpoint) -Headers $headers `
        -Body $jsonBody -Service 'ssm' -Region $resolvedRegion -Cred $cred

    # Build headers for Invoke-WebRequest (exclude 'host' as it's set automatically)
    $reqHeaders = @{}
    foreach ($k in $signed.Keys) {
        if ($k -ne 'host') { $reqHeaders[$k] = $signed[$k] }
    }

    $resp = Invoke-WebRequest -Uri "$endpoint/" -Method POST -Headers $reqHeaders `
        -Body $jsonBody -ContentType 'application/x-amz-json-1.1' -UseBasicParsing -SkipHeaderValidation
    $body_ = if ($resp.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($resp.Content) } else { $resp.Content }
    ConvertFrom-Json $body_
}

function Invoke-AwsSsmApiNoFail {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][hashtable]$Body,
        [string]$Profile,
        [string]$Region
    )
    try {
        Invoke-AwsSsmApi -Action $Action -Body $Body -Profile $Profile -Region $Region
    } catch {
        [Console]::Error.WriteLine("SSM $Action (non-fatal): $_")
        $null
    }
}

# ── Generic AWS API Client (for STS etc.) ───────────────────────────────────

function Invoke-AwsApi {
    param(
        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][string]$Action,
        [string]$TargetPrefix,
        [hashtable]$Body = @{},
        [string]$Profile,
        [string]$Region
    )
    $resolvedRegion = Get-AwsRegion -Region $Region -Profile $Profile
    $cred = Get-AwsCredential -Profile $Profile
    $endpoint = "https://$Service.$resolvedRegion.amazonaws.com"
    $jsonBody = ConvertTo-Json $Body -Compress -Depth 20
    $host_ = "$Service.$resolvedRegion.amazonaws.com"

    $headers = [ordered]@{
        'content-type' = 'application/x-amz-json-1.1'
        'host'         = $host_
    }
    if ($TargetPrefix) { $headers['x-amz-target'] = "$TargetPrefix.$Action" }

    $signed = ConvertTo-SigV4Auth -Method 'POST' -Uri ([uri]$endpoint) -Headers $headers `
        -Body $jsonBody -Service $Service -Region $resolvedRegion -Cred $cred

    $reqHeaders = @{}
    foreach ($k in $signed.Keys) {
        if ($k -ne 'host') { $reqHeaders[$k] = $signed[$k] }
    }

    $resp = Invoke-WebRequest -Uri "$endpoint/" -Method POST -Headers $reqHeaders `
        -Body $jsonBody -ContentType 'application/x-amz-json-1.1' -UseBasicParsing -SkipHeaderValidation
    $body_ = if ($resp.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($resp.Content) } else { $resp.Content }
    ConvertFrom-Json $body_
}
