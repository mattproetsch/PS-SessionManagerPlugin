#Requires -Version 5.1
<#
.SYNOPSIS
    Native PowerShell AWS SigV4 signing and SSM API client.
    Replaces the AWS CLI dependency for SSM API calls.
    Compatible with PowerShell 5.1 / .NET Framework 4.7.2+.
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

    $ssoRegion = $null; $startUrl = $null
    if ($prof.ContainsKey('sso_session')) {
        $sessKey = "sso-session $($prof['sso_session'])"
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

    $content = _HttpGet "https://portal.sso.$ssoRegion.amazonaws.com/federation/credentials?account_id=$([uri]::EscapeDataString($accountId))&role_name=$([uri]::EscapeDataString($roleName))" @{ 'x-amz-sso_bearer_token' = $accessToken }
    $rc = ConvertFrom-Json $content
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

# ── HTTP Helpers (PS 5.1 compatible — no -SkipHeaderValidation) ─────────────

function _Sha256([byte[]]$data) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ,$sha.ComputeHash($data) } finally { $sha.Dispose() }
}

function _BytesToHex([byte[]]$b) {
    $sb = [System.Text.StringBuilder]::new($b.Length * 2)
    foreach ($byte in $b) { $null = $sb.Append($byte.ToString('x2')) }
    $sb.ToString()
}

function _HmacSha256([byte[]]$Key, [byte[]]$Data) {
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try { ,$hmac.ComputeHash($Data) } finally { $hmac.Dispose() }
}

function _HttpPost([string]$Uri, [hashtable]$Headers, [string]$Body) {
    # Use HttpWebRequest directly — PS 5.1's Invoke-WebRequest rejects the
    # AWS SigV4 Authorization header value.
    $req = [System.Net.HttpWebRequest]::Create($Uri)
    $req.Method = 'POST'
    $req.ContentType = $Headers['content-type']
    foreach ($k in $Headers.Keys) {
        if ($k -eq 'content-type') { continue }
        if ($k -eq 'host') { $req.Host = $Headers[$k]; continue }
        $req.Headers.Add($k, $Headers[$k])
    }
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $req.ContentLength = $bodyBytes.Length
    $rs = $req.GetRequestStream()
    $rs.Write($bodyBytes, 0, $bodyBytes.Length)
    $rs.Close()

    try {
        $resp = $req.GetResponse()
    } catch [System.Net.WebException] {
        $errResp = $_.Exception.Response
        if ($errResp) {
            $sr = New-Object System.IO.StreamReader($errResp.GetResponseStream())
            $errBody = $sr.ReadToEnd(); $sr.Close(); $errResp.Close()
            throw $errBody
        }
        throw
    }
    $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
    $content = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
    $content
}

function _HttpGet([string]$Uri, [hashtable]$Headers) {
    $req = [System.Net.HttpWebRequest]::Create($Uri)
    $req.Method = 'GET'
    foreach ($k in $Headers.Keys) {
        $req.Headers.Add($k, $Headers[$k])
    }
    $resp = $req.GetResponse()
    $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
    $content = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
    $content
}

# ── SigV4 Signing ──────────────────────────────────────────────────────────

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

    $Headers['x-amz-date'] = $dateTime
    if ($Cred.SessionToken) {
        $Headers['x-amz-security-token'] = $Cred.SessionToken
    }

    $sortedKeys = @($Headers.Keys | Sort-Object { $_.ToLower() })
    $canonHeaders = ($sortedKeys | ForEach-Object { "$($_.ToLower()):$($Headers[$_].Trim())" }) -join "`n"
    $signedHeaders = ($sortedKeys | ForEach-Object { $_.ToLower() }) -join ';'

    $payloadHash = _BytesToHex (_Sha256 $enc.GetBytes($Body))

    $canonReq = "$Method`n$($Uri.AbsolutePath)`n`n$canonHeaders`n`n$signedHeaders`n$payloadHash"
    $canonReqHash = _BytesToHex (_Sha256 $enc.GetBytes($canonReq))

    $scope = "$dateStamp/$Region/$Service/aws4_request"
    $stringToSign = "AWS4-HMAC-SHA256`n$dateTime`n$scope`n$canonReqHash"

    $kDate    = _HmacSha256 ($enc.GetBytes("AWS4$($Cred.SecretAccessKey)")) ($enc.GetBytes($dateStamp))
    $kRegion  = _HmacSha256 $kDate ($enc.GetBytes($Region))
    $kService = _HmacSha256 $kRegion ($enc.GetBytes($Service))
    $kSigning = _HmacSha256 $kService ($enc.GetBytes('aws4_request'))

    $sig = _BytesToHex (_HmacSha256 $kSigning ($enc.GetBytes($stringToSign)))

    $Headers['Authorization'] = "AWS4-HMAC-SHA256 Credential=$($Cred.AccessKeyId)/$scope, SignedHeaders=$signedHeaders, Signature=$sig"
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
    $host_ = "ssm.$resolvedRegion.amazonaws.com"
    $jsonBody = ConvertTo-Json $Body -Compress -Depth 20

    $headers = [ordered]@{
        'content-type' = 'application/x-amz-json-1.1'
        'host'         = $host_
        'x-amz-target' = "AmazonSSM.$Action"
    }
    $null = ConvertTo-SigV4Auth -Method 'POST' -Uri ([uri]"https://$host_") -Headers $headers `
        -Body $jsonBody -Service 'ssm' -Region $resolvedRegion -Cred $cred

    $content = _HttpPost "https://$host_/" $headers $jsonBody
    ConvertFrom-Json $content
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
