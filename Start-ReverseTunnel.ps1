#Requires -Version 7.0
<#
.SYNOPSIS
    Reverse port forward through AWS SSM: binds a port on a remote EC2 instance
    to a port on your local machine. All access goes through SSM - no direct
    network path or SSH access required.

.DESCRIPTION
    Idempotently handles all prerequisites:
    - Creates the SSM session document (if missing)
    - Generates a local SSH key pair (if missing)
    - Deploys the public key to the instance via SSM Run Command
    - Configures sshd to allow gateway ports (so the remote port is reachable)
    - Opens SSH -R tunnel through SSM

    No external binaries required - pure PowerShell implementation.
    Uses native AWS SigV4 signing (no AWS CLI) and in-process SSH client (no ssh binary).

.EXAMPLE
    .\Start-ReverseTunnel.ps1 -InstanceId i-0123456789abcdef0 -RemotePort 8080 -LocalPort 3000

.EXAMPLE
    .\Start-ReverseTunnel.ps1 -InstanceId i-0123456789abcdef0 -RemotePort 8080 -LocalPort 3000 -Profile myprofile -Region us-west-2
#>
param(
    [Parameter(Mandatory)][string]$InstanceId,
    [int]$RemotePort = 8080,
    [int]$LocalPort = 3000,
    [string]$SshUser = 'ec2-user',
    [string]$Profile,
    [string]$Region,
    [string]$SshKeyPath,
    [string]$DocumentName = 'SSM-StartSSHSession'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ── Load native modules ────────────────────────────────────────────────────

. "$ScriptDir/AwsNative.ps1"
. "$ScriptDir/SshClient.ps1"

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Step([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }

# ── 1. Ensure SSM Session Document ──────────────────────────────────────────

Write-Step "Checking SSM document '$DocumentName'..."

$docExists = $false
try {
    $docInfo = Invoke-AwsSsmApiNoFail -Action 'DescribeDocument' -Body @{
        Name = $DocumentName
    } -Profile $Profile -Region $Region
    if ($docInfo -and $docInfo.Document.Status -eq 'Active') { $docExists = $true }
} catch {}

if ($docExists) {
    Write-Ok "Document '$DocumentName' already exists."
} else {
    Write-Step "Creating SSM document '$DocumentName'..."
    $docContent = @'
{
  "schemaVersion": "1.0",
  "description": "SSH session through Session Manager for reverse port forwarding.",
  "sessionType": "Port",
  "parameters": {
    "portNumber": {
      "type": "String",
      "description": "Port number of the SSH server on the instance",
      "allowedPattern": "^([1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$",
      "default": "22"
    }
  },
  "properties": {
    "portNumber": "{{ portNumber }}"
  }
}
'@
    try {
        Invoke-AwsSsmApi -Action 'CreateDocument' -Body @{
            Name           = $DocumentName
            DocumentType   = 'Session'
            DocumentFormat = 'JSON'
            Content        = $docContent
        } -Profile $Profile -Region $Region | Out-Null
        Write-Ok "Document created."
    } catch {
        if ($_ -match 'DocumentAlreadyExists') {
            Write-Ok "Document '$DocumentName' already exists (race)."
        } else { throw }
    }
}

# ── 2. Ensure SSH Key Pair ──────────────────────────────────────────────────

if (-not $SshKeyPath) {
    $sshDir = Join-Path $HOME '.ssh'
    # Use a dedicated key for SSM tunneling to avoid encrypted/incompatible user keys
    $SshKeyPath = Join-Path $sshDir 'id_rsa_ssm_tunnel'
}

if (-not (Test-Path $SshKeyPath)) {
    $sshDir = Split-Path $SshKeyPath
    if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir -Force | Out-Null }
    Write-Step "Generating RSA-4096 key pair at $SshKeyPath..."
    $kp = New-SshRsaKeyPair -KeyBits 4096 -Comment "$SshUser@ssm-tunnel"
    Set-Content -Path $SshKeyPath -Value $kp.PrivateKeyPem -NoNewline
    if ($IsLinux -or $IsMacOS) {
        chmod 600 $SshKeyPath 2>$null
    }
    Set-Content -Path "$SshKeyPath.pub" -Value $kp.PublicKeyLine -NoNewline
    Write-Ok "Key pair generated."
} else {
    Write-Ok "Using SSH key: $SshKeyPath"
}

$pubKeyPath = "$SshKeyPath.pub"
if (-not (Test-Path $pubKeyPath)) {
    # Generate .pub from the private key
    Write-Step "Extracting public key from $SshKeyPath..."
    $rsa = Import-SshPrivateKey $SshKeyPath
    $pubLine = Export-SshPublicKey $rsa "$SshUser@ssm-tunnel"
    Set-Content -Path $pubKeyPath -Value $pubLine -NoNewline
    $rsa.Dispose()
}
$pubKey = (Get-Content $pubKeyPath -Raw).Trim()

# ── 3. Deploy SSH Key & Configure sshd via Run Command ─────────────────────

Write-Step "Deploying SSH key to $InstanceId via SSM Run Command..."

$cmds = @(
    'set -e',
    "SSH_USER=`"$SshUser`"",
    "PUBKEY=`"$pubKey`"",
    'HOME_DIR=$(eval echo ~$SSH_USER)',
    'SSH_DIR=$HOME_DIR/.ssh',
    'AUTH_KEYS=$SSH_DIR/authorized_keys',
    'mkdir -p $SSH_DIR',
    'touch $AUTH_KEYS',
    'if ! grep -qF "$PUBKEY" $AUTH_KEYS 2>/dev/null; then',
    '  echo "$PUBKEY" >> $AUTH_KEYS',
    '  echo Key_added',
    'else',
    '  echo Key_already_present',
    'fi',
    'chmod 700 $SSH_DIR && chmod 600 $AUTH_KEYS',
    'chown -R $SSH_USER:$SSH_USER $SSH_DIR',
    'CONF=/etc/ssh/sshd_config',
    'if ! grep -qE "^[[:space:]]*GatewayPorts[[:space:]]+clientspecified" $CONF; then',
    '  sudo sed -i "/^[[:space:]]*#\?[[:space:]]*GatewayPorts/d" $CONF',
    '  echo "GatewayPorts clientspecified" | sudo tee -a $CONF > /dev/null',
    '  sudo systemctl restart sshd 2>/dev/null || sudo systemctl restart ssh 2>/dev/null',
    '  echo sshd_restarted',
    'else',
    '  echo GatewayPorts_already_set',
    'fi',
    'echo SETUP_COMPLETE'
)

$cmdResult = Invoke-AwsSsmApi -Action 'SendCommand' -Body @{
    InstanceIds  = @($InstanceId)
    DocumentName = 'AWS-RunShellScript'
    Parameters   = @{ commands = $cmds }
} -Profile $Profile -Region $Region
$cmdId = $cmdResult.Command.CommandId

Write-Step "Waiting for Run Command $cmdId..."
$maxWait = 60
for ($i = 0; $i -lt $maxWait; $i++) {
    Start-Sleep -Seconds 2
    $invResult = Invoke-AwsSsmApiNoFail -Action 'GetCommandInvocation' -Body @{
        CommandId  = $cmdId
        InstanceId = $InstanceId
    } -Profile $Profile -Region $Region
    $status = if ($invResult) { $invResult.Status } else { '' }
    if ($status -eq 'Success') {
        $output = $invResult.StandardOutputContent
        if ($output -match 'SETUP_COMPLETE') {
            Write-Ok "Instance setup complete."
            $output.Trim().Split("`n") | ForEach-Object {
                if ($_ -and $_ -ne 'SETUP_COMPLETE') { Write-Host "    $_" }
            }
        } else {
            Write-Warn "Setup may be incomplete. Output: $output"
        }
        break
    } elseif ($status -eq 'Failed' -or $status -eq 'TimedOut' -or $status -eq 'Cancelled') {
        $errOut = if ($invResult) { $invResult.StandardErrorContent } else { 'unknown' }
        throw "Run Command failed ($status): $errOut"
    }
}
if ($i -ge $maxWait) { throw "Run Command timed out after $($maxWait*2) seconds." }

# ── 4. Start Reverse Tunnel ─────────────────────────────────────────────────

Write-Host ""
Write-Step "Starting reverse tunnel: $InstanceId`:$RemotePort --> localhost:$LocalPort"
Write-Host "    Press Ctrl+C to stop."
Write-Host ""

# Start SSM session natively
$resolvedRegion = Get-AwsRegion -Region $Region -Profile $Profile
$sess = Invoke-AwsSsmApi -Action 'StartSession' -Body @{
    Target       = $InstanceId
    DocumentName = 'AWS-StartPortForwardingSession'
    Parameters   = @{ portNumber = @('22'); localPortNumber = @('0') }
} -Profile $Profile -Region $Region
$sessJson = ConvertTo-Json $sess -Compress -Depth 10

Write-Ok "Tunnel active: $InstanceId`:$RemotePort --> localhost:$LocalPort"

# Launch ssm-port-forward.ps1 in SSH Bridge mode
& "$ScriptDir/ssm-port-forward.ps1" $sessJson $resolvedRegion 'StartSession' '' `
    (ConvertTo-Json @{Target=$InstanceId} -Compress) "https://ssm.$resolvedRegion.amazonaws.com" `
    -SshBridgeMode -SshUser $SshUser -SshKeyPath $SshKeyPath `
    -SshBindAddress '0.0.0.0' -SshBindPort $RemotePort -SshLocalPort $LocalPort

Write-Ok "Tunnel closed."
