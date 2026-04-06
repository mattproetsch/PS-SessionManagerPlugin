# Session Manager Plugin (PowerShell)

A native PowerShell reimplementation of the AWS Session Manager Plugin.
Supports standard port forwarding and **reverse port forwarding** through SSM,
with no direct network access to the instance required.

## Reverse Port Forwarding

Bind a port on a remote EC2 instance to a port on your local machine so that
traffic destined for the instance is forwarded back to your dev machine.

```powershell
.\Start-ReverseTunnel.ps1 -InstanceId i-0123456789abcdef0 -RemotePort 8080 -LocalPort 3000
```

This single command handles everything:

1. Creates the SSM session document (idempotent)
2. Finds or generates a local SSH key pair
3. Deploys the public key to the instance via SSM Run Command
4. Configures sshd `GatewayPorts` so the remote port is externally reachable
5. Opens the reverse tunnel through SSM

No public IP, no security group changes, no pre-existing SSH access needed.
The only requirement is SSM Agent on the instance with an IAM role that has
`AmazonSSMManagedInstanceCore`.

### Parameters

| Parameter       | Default              | Description                                |
|-----------------|----------------------|--------------------------------------------|
| `-InstanceId`   | *(required)*         | EC2 instance ID                            |
| `-RemotePort`   | `8080`               | Port to listen on the EC2 instance         |
| `-LocalPort`    | `3000`               | Local port to forward traffic to           |
| `-SshUser`      | `ec2-user`           | SSH user on the instance                   |
| `-SshKeyPath`   | *(auto-detected)*    | Path to SSH private key                    |
| `-Profile`      | *(default)*          | AWS CLI profile                            |
| `-Region`       | *(default)*          | AWS region                                 |

### Examples

```powershell
# EC2:8080 -> local:3000
.\Start-ReverseTunnel.ps1 -InstanceId i-abc123 -RemotePort 8080 -LocalPort 3000

# With explicit AWS profile
.\Start-ReverseTunnel.ps1 -InstanceId i-abc123 -RemotePort 8080 -LocalPort 3000 -Profile myprofile

# Ubuntu instance
.\Start-ReverseTunnel.ps1 -InstanceId i-abc123 -SshUser ubuntu
```

## Standard Port Forwarding

Access a service running on the instance from your local machine (the opposite
direction). No SSH required:

```powershell
aws ssm start-session --target i-abc123 `
  --document-name AWS-StartPortForwardingSession `
  --parameters '{"portNumber":["8080"],"localPortNumber":["3000"]}'
```

Connect to `localhost:3000` to reach the service on `EC2:8080`.

## Installation

Place these files in a directory on your `PATH`:

| File                         | Purpose                                         |
|------------------------------|--------------------------------------------------|
| `ssm-port-forward.ps1`      | SSM plugin (protocol, WebSocket, smux, TCP)      |
| `session-manager-plugin.cmd` | Wrapper invoked by AWS CLI                       |
| `Start-ReverseTunnel.ps1`   | Reverse tunnel orchestrator                      |

### Requirements

- Windows 10 1809+ with PowerShell 5.1 and native `ssh.exe`
- AWS CLI v2
- EC2 instance with SSM Agent and `AmazonSSMManagedInstanceCore` IAM policy

## How It Works

The plugin reimplements the SSM data channel protocol in PowerShell:

- **Binary message format** (120-byte Big-Endian header, SHA-256 digest)
- **Reliable delivery** (sequence numbers, ACKs, adaptive RTT retransmission)
- **Handshake** (agent version detection, session type negotiation)
- **smux multiplexing** (8-byte Little-Endian frame protocol for concurrent connections)
- **Two I/O modes**: TCP listener (standard port forwarding) and stdin/stdout pipe (SSH ProxyCommand)

For reverse port forwarding, the plugin runs in stdin/stdout mode as an SSH
`ProxyCommand`. SSH handles the reverse tunnel (`-R`) at the protocol level
while the plugin provides the SSM transport.

```
Traffic to EC2:8080
  -> sshd reverse tunnel
  -> SSM data channel (WebSocket)
  -> ssm-port-forward.ps1
  -> localhost:3000 on your machine
```

## Troubleshooting

**`session-manager-plugin` not found**: Ensure `session-manager-plugin.cmd` is
on your `PATH`. The AWS CLI invokes it by name when running `start-session`.

**SSH hangs**: Verify sshd is running on the instance. Amazon Linux 2/2023 and
Ubuntu include it by default.

**Remote port not reachable from other machines**: The orchestrator configures
`GatewayPorts clientspecified` automatically, but the instance's security group
must allow inbound traffic on the remote port if you need access from outside
the instance.

**Session drops**: SSM sessions time out after the configured idle timeout
(default 20 minutes). The orchestrator sets `ServerAliveInterval=60` to prevent
this.
