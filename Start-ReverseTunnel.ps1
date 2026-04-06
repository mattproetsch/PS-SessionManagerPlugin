#Requires -Version 5.1
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

# ── Helpers ──────────────────────────────────────────────────────────────────

function Invoke-Aws {
    param([string[]]$Args)
    $cmd = @('aws') + $Args
    if ($Profile) { $cmd += '--profile'; $cmd += $Profile }
    if ($Region)  { $cmd += '--region';  $cmd += $Region }
    $result = & $cmd[0] $cmd[1..($cmd.Length-1)] 2>&1
    if ($LASTEXITCODE -ne 0) {
        $err = ($result | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join "`n"
        throw "aws $($Args[0..1] -join ' ') failed: $err"
    }
    ($result | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
}

function Invoke-AwsNoFail {
    param([string[]]$Args)
    $cmd = @('aws') + $Args
    if ($Profile) { $cmd += '--profile'; $cmd += $Profile }
    if ($Region)  { $cmd += '--region';  $cmd += $Region }
    $result = & $cmd[0] $cmd[1..($cmd.Length-1)] 2>$null
    $result -join "`n"
}

function Write-Step([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }

# ── 1. Ensure SSM Session Document ──────────────────────────────────────────

Write-Step "Checking SSM document '$DocumentName'..."

$docExists = $false
try {
    $docInfo = Invoke-AwsNoFail @('ssm', 'describe-document',
        '--name', $DocumentName, '--query', 'Document.Status', '--output', 'text')
    if ($docInfo -and $docInfo.Trim() -eq 'Active') { $docExists = $true }
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
    $tmpDoc = [System.IO.Path]::GetTempFileName()
    Set-Content -Path $tmpDoc -Value $docContent -Encoding UTF8
    try {
        Invoke-Aws @('ssm', 'create-document',
            '--name', $DocumentName,
            '--document-type', 'Session',
            '--document-format', 'JSON',
            '--content', "file://$tmpDoc",
            '--query', 'DocumentDescription.Status', '--output', 'text')
        Write-Ok "Document created."
    } finally {
        Remove-Item $tmpDoc -Force -ErrorAction SilentlyContinue
    }
}

# ── 2. Ensure SSH Key Pair ──────────────────────────────────────────────────

if (-not $SshKeyPath) {
    $sshDir = Join-Path $env:USERPROFILE '.ssh'
    if (-not (Test-Path $sshDir)) {
        $sshDir = Join-Path $HOME '.ssh'
    }
    # Prefer ed25519, fall back to rsa
    $candidates = @(
        (Join-Path $sshDir 'id_ed25519'),
        (Join-Path $sshDir 'id_rsa')
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $SshKeyPath = $c; break }
    }
}

if (-not $SshKeyPath -or -not (Test-Path $SshKeyPath)) {
    $sshDir = Join-Path $HOME '.ssh'
    if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir -Force | Out-Null }
    $SshKeyPath = Join-Path $sshDir 'id_ed25519'
    Write-Step "Generating SSH key pair at $SshKeyPath..."
    & ssh-keygen -t ed25519 -f $SshKeyPath -N '' -q
    if ($LASTEXITCODE -ne 0) { throw "ssh-keygen failed" }
    Write-Ok "Key pair generated."
} else {
    Write-Ok "Using SSH key: $SshKeyPath"
}

$pubKeyPath = "$SshKeyPath.pub"
if (-not (Test-Path $pubKeyPath)) { throw "Public key not found: $pubKeyPath" }
$pubKey = (Get-Content $pubKeyPath -Raw).Trim()

# ── 3. Deploy SSH Key & Configure sshd via Run Command ─────────────────────

Write-Step "Deploying SSH key to $InstanceId via SSM Run Command..."

# Build commands as an array of individual lines (avoids heredoc escaping issues).
# This script is idempotent: only adds the key if not present,
# only modifies sshd_config if GatewayPorts not already set.
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
$cmdJson = ConvertTo-Json $cmds -Compress

$cmdId = Invoke-Aws @('ssm', 'send-command',
    '--instance-ids', $InstanceId,
    '--document-name', 'AWS-RunShellScript',
    '--parameters', "{`"commands`":$cmdJson}",
    '--query', 'Command.CommandId', '--output', 'text')
$cmdId = $cmdId.Trim()

Write-Step "Waiting for Run Command $cmdId..."
$maxWait = 60
for ($i = 0; $i -lt $maxWait; $i++) {
    Start-Sleep -Seconds 2
    $status = (Invoke-AwsNoFail @('ssm', 'get-command-invocation',
        '--command-id', $cmdId, '--instance-id', $InstanceId,
        '--query', 'Status', '--output', 'text')).Trim()
    if ($status -eq 'Success') {
        $output = Invoke-Aws @('ssm', 'get-command-invocation',
            '--command-id', $cmdId, '--instance-id', $InstanceId,
            '--query', 'StandardOutputContent', '--output', 'text')
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
        $errOut = Invoke-AwsNoFail @('ssm', 'get-command-invocation',
            '--command-id', $cmdId, '--instance-id', $InstanceId,
            '--query', 'StandardErrorContent', '--output', 'text')
        throw "Run Command failed ($status): $errOut"
    }
}
if ($i -ge $maxWait) { throw "Run Command timed out after $($maxWait*2) seconds." }

# ── 4. Start Reverse Tunnel ─────────────────────────────────────────────────

Write-Host ""
Write-Step "Starting reverse tunnel: $InstanceId`:$RemotePort --> localhost:$LocalPort"
Write-Host "    Press Ctrl+C to stop."
Write-Host ""

# Build the SSH ProxyCommand. AWS CLI start-session invokes session-manager-plugin
# (our .cmd wrapper) which runs ssm-port-forward.ps1 in stdio mode.
$proxyArgs = @(
    'ssm', 'start-session',
    '--target', $InstanceId,
    '--document-name', $DocumentName,
    '--parameters', "{`"portNumber`":[`"22`"]}"
)
if ($Profile) { $proxyArgs += '--profile'; $proxyArgs += $Profile }
if ($Region)  { $proxyArgs += '--region';  $proxyArgs += $Region }
$proxyCmd = "aws $($proxyArgs -join ' ')"

$sshArgs = @(
    '-i', $SshKeyPath,
    '-o', 'StrictHostKeyChecking=no',
    '-o', 'UserKnownHostsFile=/dev/null',
    '-o', "ProxyCommand=$proxyCmd",
    '-o', 'ServerAliveInterval=60',
    '-R', "0.0.0.0:${RemotePort}:localhost:${LocalPort}",
    '-N',
    "$SshUser@$InstanceId"
)

Write-Ok "Tunnel active: $InstanceId`:$RemotePort --> localhost:$LocalPort"
& ssh @sshArgs
$sshExit = $LASTEXITCODE

if ($sshExit -ne 0) {
    Write-Warn "SSH exited with code $sshExit"
} else {
    Write-Ok "Tunnel closed."
}
