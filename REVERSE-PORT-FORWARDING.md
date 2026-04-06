# Reverse Port Forwarding through AWS SSM

Forward traffic arriving at a port on your EC2 instance back to your local dev
machine. No public IP, no security group changes, no direct SSH access required.
The only path to the instance is SSM.

## Quick Start

```powershell
.\Start-ReverseTunnel.ps1 -InstanceId i-0123456789abcdef0 -RemotePort 8080 -LocalPort 3000
```

This single command:
1. Creates the SSM session document (if it doesn't exist)
2. Finds or generates an SSH key pair
3. Deploys the public key to the instance via SSM Run Command
4. Configures `GatewayPorts` in sshd so the remote port is externally reachable
5. Opens an SSH reverse tunnel through SSM

Traffic destined for `EC2:8080` is forwarded to `localhost:3000` on your machine.

## How It Works

```
External traffic
       |
       v
  EC2:8080 (sshd -R listener)
       |
       v
  sshd reverse tunnel
       |
       v
  SSM data channel (WebSocket)
       |
       v
  ssm-port-forward.ps1 (stdin/stdout mode)
       |
       v
  localhost:3000 (your dev service)
```

SSM doesn't natively support reverse port forwarding. This setup uses SSH `-R`
tunneled through SSM's data channel. The PowerShell plugin
(`ssm-port-forward.ps1`) acts as the transport layer, piping SSH traffic through
SSM via stdin/stdout.

## Prerequisites

- **Windows 10 1809+** with PowerShell 5.1 and native `ssh.exe`
- **AWS CLI v2** configured with a profile that has `ssm:StartSession` and
  `ssm:SendCommand` permissions
- **EC2 instance** with SSM Agent running and an IAM instance profile with
  `AmazonSSMManagedInstanceCore`

## Installation

Place all files in a single directory (e.g., `C:\tools\ssm-plugin\`):

```
ssm-port-forward.ps1          # The SSM plugin
session-manager-plugin.cmd     # AWS CLI wrapper
Start-ReverseTunnel.ps1        # Orchestrator
```

Add that directory to your `PATH` so `aws ssm start-session` can find
`session-manager-plugin.cmd`.

## Parameters

```
-InstanceId     (required)  EC2 instance ID
-RemotePort     (default 8080)  Port to bind on the EC2 instance
-LocalPort      (default 3000)  Port on your local machine to forward to
-SshUser        (default ec2-user)  SSH user on the instance
-SshKeyPath     (optional)  Path to SSH private key; auto-detected or generated
-Profile        (optional)  AWS CLI profile name
-Region         (optional)  AWS region
-DocumentName   (default SSM-StartSSHSession)  SSM session document name
```

## Examples

```powershell
# Basic: EC2:8080 -> local:3000
.\Start-ReverseTunnel.ps1 -InstanceId i-abc123 -RemotePort 8080 -LocalPort 3000

# With explicit profile and region
.\Start-ReverseTunnel.ps1 -InstanceId i-abc123 -RemotePort 8080 -LocalPort 3000 `
  -Profile prod-account -Region us-west-2

# Ubuntu instance
.\Start-ReverseTunnel.ps1 -InstanceId i-abc123 -SshUser ubuntu

# Custom SSH key
.\Start-ReverseTunnel.ps1 -InstanceId i-abc123 -SshKeyPath C:\Users\me\.ssh\work_key
```

## Standard (Forward) Port Forwarding

To access a service running on the EC2 instance from your local machine
(the opposite direction), use standard port forwarding without SSH:

```powershell
aws ssm start-session --target i-abc123 `
  --document-name AWS-StartPortForwardingSession `
  --parameters '{"portNumber":["8080"],"localPortNumber":["3000"]}'
```

Then connect to `localhost:3000` to reach `EC2:8080`.

## Troubleshooting

**"ssh-keygen is not recognized"**: Ensure `C:\Windows\System32\OpenSSH` is in
your `PATH`.

**SSH hangs**: The instance may not have sshd. Amazon Linux 2/2023 and Ubuntu
include it. The orchestrator's Run Command will fail with a clear error if the
SSH user doesn't exist.

**"Connection refused" from other machines to EC2:8080**: The orchestrator
configures `GatewayPorts clientspecified` and binds to `0.0.0.0`. If the
security group blocks inbound traffic on 8080, you need to add an inbound rule.
For localhost-only access on the EC2, this is not needed.

**Session drops after idle**: Add `-o ServerAliveInterval=60` to the SSH
command (the orchestrator does this automatically).

**"session-manager-plugin" not found**: Ensure `session-manager-plugin.cmd` is
on your `PATH`. The AWS CLI looks for it when running `aws ssm start-session`.
