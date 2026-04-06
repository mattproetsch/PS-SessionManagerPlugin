#Requires -Version 5.1
<#
.SYNOPSIS
    PowerShell implementation of AWS Session Manager Plugin for port forwarding.
.DESCRIPTION
    Implements the SSM data channel protocol over WebSocket, including handshake,
    reliable delivery, smux multiplexing, and TCP port forwarding.
    Compatible with PowerShell 5.1 (.NET Framework 4.5.2+) and PowerShell 7+.
.EXAMPLE
    .\ssm-port-forward.ps1 '<StartSessionResponse JSON>' 'us-east-1' 'StartSession' 'default' '{"Target":"i-xxx"}' 'https://ssm.us-east-1.amazonaws.com'
#>
param(
    [Parameter(Position=0)][string]$SessionResponse,
    [Parameter(Position=1)][string]$Region,
    [Parameter(Position=2)][string]$Operation = 'StartSession',
    [Parameter(Position=3)][string]$Profile,
    [Parameter(Position=4)][string]$Parameters,
    [Parameter(Position=5)][string]$Endpoint,
    # SSH Bridge Mode parameters
    [switch]$SshBridgeMode,
    [string]$SshUser,
    [string]$SshKeyPath,
    [string]$SshBindAddress = '0.0.0.0',
    [int]$SshBindPort,
    [int]$SshLocalPort
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Constants ────────────────────────────────────────────────────────────────

$script:CLIENT_VERSION          = '1.3.0.0'
$script:MSG_SCHEMA_VERSION      = '1.0'
$script:PAYLOAD_MAX             = 1024
$script:RESEND_SLEEP_MS         = 100
$script:RESEND_MAX              = 3000
$script:DEFAULT_TIMEOUT_MS      = 200
$script:MAX_TIMEOUT_MS          = 1000
$script:RTT_K                   = 1.0 / 8.0
$script:RTTV_K                  = 1.0 / 4.0
$script:CLOCK_GRAN_MS           = 10

$script:INPUT_STREAM  = 'input_stream_data'
$script:OUTPUT_STREAM = 'output_stream_data'
$script:ACK_TYPE      = 'acknowledge'
$script:CHAN_CLOSED    = 'channel_closed'

$script:PT_OUTPUT             = [uint32]1
$script:PT_HANDSHAKE_REQ      = [uint32]5
$script:PT_HANDSHAKE_RESP     = [uint32]6
$script:PT_HANDSHAKE_COMPLETE = [uint32]7
$script:PT_ENC_CHALLENGE_REQ  = [uint32]8
$script:PT_ENC_CHALLENGE_RESP = [uint32]9
$script:PT_FLAG               = [uint32]10

$script:FLAG_DISCONNECT   = [uint32]1
$script:FLAG_TERMINATE    = [uint32]2
$script:FLAG_CONNECT_ERR  = [uint32]3

$script:TCP_MUX_AFTER     = [version]'3.0.196.0'
$script:SMUX_KA_OFF_AFTER = [version]'3.1.1511.0'

$script:SMUX_VER    = [byte]1
$script:SMUX_SYN    = [byte]0
$script:SMUX_FIN    = [byte]1
$script:SMUX_PSH    = [byte]2
$script:SMUX_NOP    = [byte]3
$script:SMUX_HDR    = 8
$script:SMUX_MAX_DATA = $script:PAYLOAD_MAX - $script:SMUX_HDR   # 1016

# ClientMessage header layout (Big-Endian)
$script:CM_HL        = 0    # uint32  4B
$script:CM_MT        = 4    # string 32B
$script:CM_MT_LEN    = 32
$script:CM_SV        = 36   # uint32  4B
$script:CM_CD        = 40   # uint64  8B
$script:CM_SEQ       = 48   # int64   8B
$script:CM_FL        = 56   # uint64  8B
$script:CM_MID       = 64   # uuid   16B
$script:CM_DIG       = 80   # sha256 32B
$script:CM_PT        = 112  # uint32  4B
$script:CM_PL        = 116  # uint32  4B
$script:CM_PAY       = 120  # payload variable
$script:CM_HL_VAL    = [uint32]116  # HeaderLength value written on wire

# ── Big-Endian Helpers ───────────────────────────────────────────────────────

function Write-BE32([byte[]]$b,[int]$o,[uint32]$v) {
    $t=[System.BitConverter]::GetBytes($v)
    if([System.BitConverter]::IsLittleEndian){[Array]::Reverse($t)}
    [System.Buffer]::BlockCopy($t,0,$b,$o,4)
}
function Write-BE64([byte[]]$b,[int]$o,[uint64]$v) {
    $t=[System.BitConverter]::GetBytes($v)
    if([System.BitConverter]::IsLittleEndian){[Array]::Reverse($t)}
    [System.Buffer]::BlockCopy($t,0,$b,$o,8)
}
function Write-BEi64([byte[]]$b,[int]$o,[int64]$v) {
    $t=[System.BitConverter]::GetBytes($v)
    if([System.BitConverter]::IsLittleEndian){[Array]::Reverse($t)}
    [System.Buffer]::BlockCopy($t,0,$b,$o,8)
}
function Read-BE32([byte[]]$b,[int]$o) {
    $t=[byte[]]::new(4);[System.Buffer]::BlockCopy($b,$o,$t,0,4)
    if([System.BitConverter]::IsLittleEndian){[Array]::Reverse($t)}
    [System.BitConverter]::ToUInt32($t,0)
}
function Read-BE64([byte[]]$b,[int]$o) {
    $t=[byte[]]::new(8);[System.Buffer]::BlockCopy($b,$o,$t,0,8)
    if([System.BitConverter]::IsLittleEndian){[Array]::Reverse($t)}
    [System.BitConverter]::ToUInt64($t,0)
}
function Read-BEi64([byte[]]$b,[int]$o) {
    $t=[byte[]]::new(8);[System.Buffer]::BlockCopy($b,$o,$t,0,8)
    if([System.BitConverter]::IsLittleEndian){[Array]::Reverse($t)}
    [System.BitConverter]::ToInt64($t,0)
}
function Write-PadStr([byte[]]$b,[int]$o,[int]$len,[string]$s) {
    for($i=0;$i -lt $len;$i++){$b[$o+$i]=0x20}
    $sb=[System.Text.Encoding]::UTF8.GetBytes($s)
    [System.Buffer]::BlockCopy($sb,0,$b,$o,[Math]::Min($sb.Length,$len))
}
function Read-TrimStr([byte[]]$b,[int]$o,[int]$len) {
    $t=[byte[]]::new($len);[System.Buffer]::BlockCopy($b,$o,$t,0,$len)
    [System.Text.Encoding]::UTF8.GetString($t).Replace("`0",'').Trim()
}

# ── UUID Helpers ─────────────────────────────────────────────────────────────
# .NET Guid.ToByteArray() uses mixed-endian. Convert to/from RFC 4122 (BE).
# Go wire format swaps LSB/MSB halves of the 16-byte UUID.

function GuidToRfc([guid]$g) {
    $b=$g.ToByteArray(); $r=[byte[]]::new(16)
    $r[0]=$b[3];$r[1]=$b[2];$r[2]=$b[1];$r[3]=$b[0]
    $r[4]=$b[5];$r[5]=$b[4];$r[6]=$b[7];$r[7]=$b[6]
    [System.Buffer]::BlockCopy($b,8,$r,8,8); ,$r
}
function RfcToGuid([byte[]]$r) {
    $b=[byte[]]::new(16)
    $b[0]=$r[3];$b[1]=$r[2];$b[2]=$r[1];$b[3]=$r[0]
    $b[4]=$r[5];$b[5]=$r[4];$b[6]=$r[7];$b[7]=$r[6]
    [System.Buffer]::BlockCopy($r,8,$b,8,8); [guid]::new($b)
}
function Write-Uuid([byte[]]$buf,[int]$o,[guid]$id) {
    $rfc = GuidToRfc $id
    # Go puts LSB (rfc[8:15]) at offset, MSB (rfc[0:7]) at offset+8
    [System.Buffer]::BlockCopy($rfc,8,$buf,$o,8)
    [System.Buffer]::BlockCopy($rfc,0,$buf,($o+8),8)
}
function Read-Uuid([byte[]]$buf,[int]$o) {
    $rfc=[byte[]]::new(16)
    [System.Buffer]::BlockCopy($buf,($o+8),$rfc,0,8)
    [System.Buffer]::BlockCopy($buf,$o,$rfc,8,8)
    RfcToGuid $rfc
}

# ── ClientMessage Serialization ──────────────────────────────────────────────

function Get-EpochMs {
    [uint64][Math]::Floor(([DateTime]::UtcNow - [DateTime]::new(1970,1,1,0,0,0,[DateTimeKind]::Utc)).TotalMilliseconds)
}

function New-Msg {
    param([string]$MsgType,[int64]$Seq,[uint64]$Flags,[guid]$Id,[uint32]$PayType,[byte[]]$Pay)
    $pLen = if($Pay){$Pay.Length}else{0}
    $buf = [byte[]]::new($CM_PAY + $pLen)
    Write-BE32  $buf $CM_HL  $CM_HL_VAL
    Write-PadStr $buf $CM_MT $CM_MT_LEN $MsgType
    Write-BE32  $buf $CM_SV  1
    Write-BE64  $buf $CM_CD  (Get-EpochMs)
    Write-BEi64 $buf $CM_SEQ $Seq
    Write-BE64  $buf $CM_FL  $Flags
    Write-Uuid  $buf $CM_MID $Id
    if($pLen -gt 0){
        $sha=[System.Security.Cryptography.SHA256]::Create()
        $h=$sha.ComputeHash($Pay); $sha.Dispose()
        [System.Buffer]::BlockCopy($h,0,$buf,$CM_DIG,32)
        [System.Buffer]::BlockCopy($Pay,0,$buf,$CM_PAY,$pLen)
    }
    Write-BE32 $buf $CM_PT $PayType
    Write-BE32 $buf $CM_PL ([uint32]$pLen)
    ,$buf
}

function Parse-Msg([byte[]]$raw) {
    if($raw.Length -lt $CM_PAY){throw "Message too short: $($raw.Length)"}
    $hl  = Read-BE32  $raw $CM_HL
    $pLen= Read-BE32  $raw $CM_PL
    $pay = $null
    if($pLen -gt 0 -and ($hl+4+$pLen) -le $raw.Length){
        $pay=[byte[]]::new($pLen)
        [System.Buffer]::BlockCopy($raw,($hl+4),$pay,0,$pLen)
    }
    [PSCustomObject]@{
        MessageType = Read-TrimStr $raw $CM_MT $CM_MT_LEN
        Seq         = Read-BEi64   $raw $CM_SEQ
        Flags       = Read-BE64    $raw $CM_FL
        MessageId   = Read-Uuid    $raw $CM_MID
        PayloadType = Read-BE32    $raw $CM_PT
        PayloadLen  = $pLen
        Payload     = $pay
    }
}

function New-Ack([string]$mt,[guid]$mid,[int64]$seq) {
    $j = @{
        AcknowledgedMessageType           = $mt
        AcknowledgedMessageId             = $mid.ToString()
        AcknowledgedMessageSequenceNumber = $seq
        IsSequentialMessage               = $true
    } | ConvertTo-Json -Compress
    $p = [System.Text.Encoding]::UTF8.GetBytes($j)
    New-Msg -MsgType $ACK_TYPE -Seq 0 -Flags ([uint64]3) -Id ([guid]::NewGuid()) -PayType ([uint32]0) -Pay $p
}

# ── WebSocket ────────────────────────────────────────────────────────────────

function Send-WS([byte[]]$data,[System.Net.WebSockets.WebSocketMessageType]$mt) {
    $seg = New-Object System.ArraySegment[byte] -ArgumentList (,$data)
    $null = $script:ws.SendAsync($seg, $mt, $true, [System.Threading.CancellationToken]::None
    ).GetAwaiter().GetResult()
}
function Send-WSBin([byte[]]$data)  { Send-WS $data ([System.Net.WebSockets.WebSocketMessageType]::Binary) }
function Send-WSText([string]$text) { Send-WS ([System.Text.Encoding]::UTF8.GetBytes($text)) ([System.Net.WebSockets.WebSocketMessageType]::Text) }

# ── Data Channel Ops ─────────────────────────────────────────────────────────

function Send-Data([uint32]$pt,[byte[]]$payload) {
    $seq = $script:txSeq
    $raw = New-Msg -MsgType $INPUT_STREAM -Seq $seq -Flags ([uint64]0) `
                   -Id ([guid]::NewGuid()) -PayType $pt -Pay $payload
    Send-WSBin $raw
    $script:outBuf[$seq] = @{ Raw=$raw; Sent=[DateTime]::UtcNow; Retries=0 }
    $script:txSeq++
}

function Send-Ack($msg) {
    $raw = New-Ack $msg.MessageType $msg.MessageId $msg.Seq
    Send-WSBin $raw
}

function Send-SessionFlag([uint32]$flag) {
    $fb = [byte[]]::new(4)
    Write-BE32 $fb 0 $flag
    Send-Data $PT_FLAG $fb
}

# ── Smux Helpers ─────────────────────────────────────────────────────────────

function New-SmuxFrame([byte]$cmd,[uint32]$sid,[byte[]]$data) {
    $dLen = if($data){$data.Length}else{0}
    $f = [byte[]]::new($SMUX_HDR + $dLen)
    $f[0] = $SMUX_VER; $f[1] = $cmd
    # Length & StreamID are Little-Endian (smux protocol)
    $lb = [System.BitConverter]::GetBytes([uint16]$dLen)
    [System.Buffer]::BlockCopy($lb,0,$f,2,2)
    $sb = [System.BitConverter]::GetBytes($sid)
    [System.Buffer]::BlockCopy($sb,0,$f,4,4)
    if($dLen -gt 0){ [System.Buffer]::BlockCopy($data,0,$f,$SMUX_HDR,$dLen) }
    ,$f
}

function Open-SmuxStream {
    $script:smuxNextId += 2
    $sid = $script:smuxNextId
    $syn = New-SmuxFrame $SMUX_SYN $sid $null
    Send-Data $PT_OUTPUT $syn
    $script:conns[$sid] = @{
        Client  = $null    # set after association with TCP
        Stream  = $null
        Pending = [System.Collections.Generic.List[byte[]]]::new()
    }
    $sid
}

function Close-SmuxStream([uint32]$sid) {
    $fin = New-SmuxFrame $SMUX_FIN $sid $null
    Send-Data $PT_OUTPUT $fin
    if($script:conns.ContainsKey($sid)){
        try{ $script:conns[$sid].Client.Close() }catch{}
        $script:conns.Remove($sid)
    }
}

function Write-SmuxData([uint32]$sid,[byte[]]$data) {
    $off = 0
    while($off -lt $data.Length){
        $n = [Math]::Min($SMUX_MAX_DATA, $data.Length - $off)
        $chunk = [byte[]]::new($n)
        [System.Buffer]::BlockCopy($data,$off,$chunk,0,$n)
        $psh = New-SmuxFrame $SMUX_PSH $sid $chunk
        Send-Data $PT_OUTPUT $psh
        $off += $n
    }
}

function Parse-SmuxFrames {
    # Parse complete smux frames from $script:smuxBuf and dispatch
    while($script:smuxBuf.Count -ge $SMUX_HDR){
        $hdr = [byte[]]::new($SMUX_HDR)
        $script:smuxBuf.CopyTo(0,$hdr,0,$SMUX_HDR)
        $dLen = [int][System.BitConverter]::ToUInt16($hdr,2)
        $sid  = [System.BitConverter]::ToUInt32($hdr,4)
        $total = $SMUX_HDR + $dLen
        if($script:smuxBuf.Count -lt $total){ break }  # incomplete

        $fdata = $null
        if($dLen -gt 0){
            $fdata = [byte[]]::new($dLen)
            $script:smuxBuf.CopyTo($SMUX_HDR,$fdata,0,$dLen)
        }
        $script:smuxBuf.RemoveRange(0,$total)

        switch($hdr[1]){
            $SMUX_PSH {
                if($fdata -and $script:streamMode -eq 'ssh-bridge' -and $sid -eq $script:sshSmuxId){
                    # Route to SSH client channel
                    $null = $script:ssmToSsh.Writer.TryWrite([byte[]]$fdata)
                } elseif($fdata -and $script:conns.ContainsKey($sid)){
                    $script:conns[$sid].Pending.Add($fdata)
                }
            }
            $SMUX_FIN {
                if($script:conns.ContainsKey($sid)){
                    $c = $script:conns[$sid]
                    # Flush any pending data before closing
                    if($c.Stream -and $c.Pending.Count -gt 0){
                        try {
                            foreach($chunk in $c.Pending){ $c.Stream.Write($chunk, 0, $chunk.Length) }
                            $c.Stream.Flush()
                        } catch {}
                        $c.Pending.Clear()
                    }
                    try{ $c.Client.Close() }catch{}
                    $script:conns.Remove($sid)
                    [Console]::Error.WriteLine("Remote closed stream $sid.")
                }
            }
            $SMUX_SYN {
                # Server-initiated stream: create entry for reverse forwarding
                if(-not $script:conns.ContainsKey($sid)){
                    $script:conns[$sid] = @{
                        Client=$null; Stream=$null
                        Pending=[System.Collections.Generic.List[byte[]]]::new()
                    }
                    # Attempt to connect to the local forwarding target
                    try {
                        $tc = New-Object System.Net.Sockets.TcpClient
                        $tc.Connect('127.0.0.1', [int]$script:localPort)
                        $ns = $tc.GetStream()
                        $script:conns[$sid].Client = $tc
                        $script:conns[$sid].Stream = $ns
                        [Console]::Error.WriteLine("Reverse stream $sid connected to local port $($script:localPort).")
                    } catch {
                        [Console]::Error.WriteLine("Failed to connect stream $sid to local port: $_")
                        $cf = New-SmuxFrame $SMUX_FIN $sid $null
                        Send-Data $PT_OUTPUT $cf
                        $script:conns.Remove($sid)
                    }
                }
            }
            $SMUX_NOP { <# keepalive, ignore #> }
        }
    }
}

# ── Message Processing ───────────────────────────────────────────────────────

function Process-HandshakeReq($msg) {
    $json = [System.Text.Encoding]::UTF8.GetString($msg.Payload)
    $req  = ConvertFrom-Json $json
    $script:agentVer = $req.AgentVersion
    [Console]::Error.WriteLine("Agent version: $($script:agentVer)")

    $processed = @()
    $errors    = @()
    foreach($action in @($req.RequestedClientActions)){
        switch($action.ActionType){
            'SessionType' {
                $p = $action.ActionParameters
                # ActionParameters may be a string (json.RawMessage) that needs re-parsing
                if($p -is [string]){ $p = ConvertFrom-Json $p }
                $script:sessionType = $p.SessionType
                $script:portParams  = $p.Properties
                $processed += @{ ActionType='SessionType'; ActionStatus=1; ActionResult=$null; Error='' }
            }
            'KMSEncryption' {
                $processed += @{ ActionType='KMSEncryption'; ActionStatus=3; ActionResult=$null
                                 Error='KMS encryption not supported by this client' }
                $errors    += 'KMS encryption not supported by this client'
            }
            default {
                $processed += @{ ActionType=$action.ActionType; ActionStatus=3; ActionResult=$null
                                 Error="Unsupported action: $($action.ActionType)" }
                $errors    += "Unsupported action: $($action.ActionType)"
            }
        }
    }
    $resp = [ordered]@{
        ClientVersion          = $CLIENT_VERSION
        ProcessedClientActions = @($processed)
        Errors                 = @($errors)
    }
    $rj = ConvertTo-Json $resp -Depth 10 -Compress
    Send-Data $PT_HANDSHAKE_RESP ([System.Text.Encoding]::UTF8.GetBytes($rj))
}

function Process-HandshakeComplete($msg) {
    $json = [System.Text.Encoding]::UTF8.GetString($msg.Payload)
    $hc   = ConvertFrom-Json $json
    if($hc.CustomerMessage){ [Console]::Error.WriteLine($hc.CustomerMessage) }
    $script:hsComplete = $true
    [Console]::Error.WriteLine('Handshake complete.')
}

function Process-DataPayload($msg) {
    switch($msg.PayloadType){
        $PT_OUTPUT {
            if($script:streamMode -eq 'ssh-bridge' -and $script:useMux){
                # SSH Bridge with smux: data goes through smux parsing
                $script:smuxBuf.AddRange([byte[]]$msg.Payload)
                Parse-SmuxFrames
            } elseif($script:streamMode -eq 'ssh-bridge'){
                # SSH Bridge without smux: feed data directly
                $null = $script:ssmToSsh.Writer.TryWrite([byte[]]$msg.Payload)
            } elseif($script:streamMode -eq 'stdio'){
                # StandardStreamForwarding: write to stdout
                if($script:stdoutStream){
                    $script:stdoutStream.Write($msg.Payload, 0, $msg.PayloadLen)
                    $script:stdoutStream.Flush()
                }
            } elseif($script:useMux){
                $script:smuxBuf.AddRange([byte[]]$msg.Payload)
                Parse-SmuxFrames
            } else {
                # BasicPortForwarding: write directly to TCP
                if($script:basicStream -and $script:basicStream.CanWrite){
                    $script:basicStream.Write($msg.Payload, 0, $msg.PayloadLen)
                    $script:basicStream.Flush()
                }
            }
        }
        $PT_FLAG {
            if($msg.PayloadLen -ge 4){
                $fv = Read-BE32 $msg.Payload 0
                switch($fv){
                    $FLAG_CONNECT_ERR  { [Console]::Error.WriteLine("`nConnection to destination port failed.") }
                    $FLAG_TERMINATE    { [Console]::Error.WriteLine("`nSession terminated by remote."); $script:running=$false }
                    $FLAG_DISCONNECT   {
                        [Console]::Error.WriteLine('Remote disconnect signal received.')
                        if(-not $script:useMux -and $script:basicClient){
                            try{ $script:basicClient.Close() }catch{}
                            $script:basicClient = $null
                            $script:basicStream = $null
                        }
                    }
                }
            }
        }
    }
}

function Process-OutputMsg($msg,[byte[]]$raw) {
    if($msg.Seq -eq $script:rxSeq){
        # In-order message
        Send-Ack $msg
        switch($msg.PayloadType){
            $PT_HANDSHAKE_REQ      { Process-HandshakeReq $msg }
            $PT_HANDSHAKE_COMPLETE { Process-HandshakeComplete $msg }
            $PT_ENC_CHALLENGE_REQ  { Write-Warning 'Encryption challenge received but not supported.' }
            default                { Process-DataPayload $msg }
        }
        $script:rxSeq++
        # Drain incoming buffer
        while($script:inBuf.ContainsKey($script:rxSeq)){
            $braw = $script:inBuf[$script:rxSeq]
            $script:inBuf.Remove($script:rxSeq)
            $bmsg = Parse-Msg $braw
            Process-DataPayload $bmsg
            $script:rxSeq++
        }
    } elseif($msg.Seq -gt $script:rxSeq) {
        # Out of order: buffer and ack
        if($script:inBuf.Count -lt 10000){
            Send-Ack $msg
            $script:inBuf[$msg.Seq] = $raw
        }
    }
    # Seq < expected = duplicate, ignore
}

function Process-AckMsg($msg) {
    $j   = [System.Text.Encoding]::UTF8.GetString($msg.Payload)
    $ack = ConvertFrom-Json $j
    $seq = [long]$ack.AcknowledgedMessageSequenceNumber
    if($script:outBuf.ContainsKey($seq)){
        $entry = $script:outBuf[$seq]
        $ms = ([DateTime]::UtcNow - $entry.Sent).TotalMilliseconds
        if($script:rttVar -eq 0.0){
            $script:rtt    = $ms
            $script:rttVar = $ms / 2.0
        } else {
            $script:rttVar = (1.0-$RTTV_K)*$script:rttVar + $RTTV_K*[Math]::Abs($script:rtt-$ms)
            $script:rtt    = (1.0-$RTT_K) *$script:rtt    + $RTT_K*$ms
        }
        $script:retransmitMs = [Math]::Min($MAX_TIMEOUT_MS,
                                [Math]::Max($script:rtt + 4.0*$script:rttVar, $CLOCK_GRAN_MS))
        $script:outBuf.Remove($seq)
    }
}

function Route-WSMessage([byte[]]$data,[System.Net.WebSockets.WebSocketMessageType]$mt) {
    if($mt -eq [System.Net.WebSockets.WebSocketMessageType]::Text){
        Write-Verbose "WS text: $([System.Text.Encoding]::UTF8.GetString($data))"
        return
    }
    $msg = Parse-Msg $data
    switch($msg.MessageType){
        $OUTPUT_STREAM { Process-OutputMsg $msg $data }
        $ACK_TYPE      { Process-AckMsg $msg }
        $CHAN_CLOSED    {
            if($msg.Payload){
                $j = ConvertFrom-Json ([System.Text.Encoding]::UTF8.GetString($msg.Payload))
                [Console]::Error.WriteLine("Channel closed: $($j.Output)")
            }
            $script:running = $false
        }
    }
}

function Check-Retransmit {
    if($script:outBuf.Count -eq 0){ return }
    $oldest = [long]($script:outBuf.Keys | Measure-Object -Minimum).Minimum
    $e = $script:outBuf[$oldest]
    $el = ([DateTime]::UtcNow - $e.Sent).TotalMilliseconds
    if($el -gt $script:retransmitMs){
        if($e.Retries -ge $RESEND_MAX){
            [Console]::Error.WriteLine('Retransmission timeout. Connection lost.')
            $script:running = $false; return
        }
        Send-WSBin $e.Raw
        $e.Sent = [DateTime]::UtcNow
        $e.Retries++
    }
}

# ── Main ─────────────────────────────────────────────────────────────────────

# Handle no-args / --version
if(-not $SessionResponse){
    Write-Output "`nThe Session Manager plugin was installed successfully. Use the AWS CLI to start a session.`n"
    return
}
if($SessionResponse -eq '--version'){
    Write-Output $CLIENT_VERSION; return
}

# Parse session response (may be env-var reference)
if($SessionResponse -like 'AWS_SSM_START_SESSION_RESPONSE*'){
    $envN = $SessionResponse
    $SessionResponse = [Environment]::GetEnvironmentVariable($envN)
    [Environment]::SetEnvironmentVariable($envN, $null)
}
$sess = ConvertFrom-Json $SessionResponse
$sessionId = $sess.SessionId
$streamUrl = $sess.StreamUrl
$tokenVal  = $sess.TokenValue

$target = ''
if($Parameters){
    $pp = ConvertFrom-Json $Parameters
    if($pp.Target){ $target = $pp.Target }
}
$clientId = [guid]::NewGuid().ToString()

[Console]::Error.WriteLine("Starting session $sessionId to $target")

# ── State ────────────────────────────────────────────────────────────────────

$script:ws           = $null
$script:running      = $true
$script:hsComplete   = $false
$script:txSeq        = [long]0
$script:rxSeq        = [long]0
$script:outBuf       = @{}          # seqNum -> @{Raw;Sent;Retries}
$script:inBuf        = @{}          # seqNum -> byte[]
$script:rtt          = 100.0
$script:rttVar       = 0.0
$script:retransmitMs = $DEFAULT_TIMEOUT_MS
$script:agentVer     = ''
$script:sessionType  = ''
$script:portParams   = $null
$script:useMux       = $false
$script:smuxNextId   = [uint32]1
$script:smuxBuf      = [System.Collections.Generic.List[byte]]::new()
$script:conns        = @{}          # streamId -> @{Client;Stream;Pending}
$script:localPort    = 0
$script:listener     = $null
# BasicPortForwarding state
$script:basicClient  = $null
$script:basicStream  = $null
# StandardStreamForwarding (stdin/stdout) state
$script:streamMode   = ''          # 'tcp', 'stdio', or 'ssh-bridge'
$script:stdinStream  = $null
$script:stdoutStream = $null
$script:stdinTask    = $null
$script:stdinBuf     = $null
# SSH Bridge mode state
$script:ssmToSsh     = $null       # Channel<byte[]> SSM -> SSH
$script:sshToSsm     = $null       # Channel<byte[]> SSH -> SSM
$script:sshThread    = $null       # Background thread running SSH client
$script:sshCts       = $null       # CancellationTokenSource for SSH

# ── Connect WebSocket ────────────────────────────────────────────────────────

$script:ws = New-Object System.Net.WebSockets.ClientWebSocket
$script:ws.Options.KeepAliveInterval = [TimeSpan]::FromMinutes(5)


[Console]::Error.WriteLine('Connecting to SSM WebSocket...')
try {
    $null = $script:ws.ConnectAsync([Uri]$streamUrl, [System.Threading.CancellationToken]::None
    ).GetAwaiter().GetResult()
} catch {
    [Console]::Error.WriteLine("WebSocket connection failed: $_")
    return
}
[Console]::Error.WriteLine('Connected.')

# ── Send OpenDataChannelInput ────────────────────────────────────────────────

$odci = [ordered]@{
    MessageSchemaVersion = $MSG_SCHEMA_VERSION
    RequestId            = [guid]::NewGuid().ToString()
    TokenValue           = $tokenVal
    ClientId             = $clientId
    ClientVersion        = $CLIENT_VERSION
} | ConvertTo-Json -Compress

Send-WSText $odci
[Console]::Error.WriteLine('Sent OpenDataChannelInput. Waiting for handshake...')

# ── Event Loop ───────────────────────────────────────────────────────────────

$recvBuf  = [byte[]]::new(65536)
$recvSeg  = New-Object System.ArraySegment[byte] -ArgumentList (,$recvBuf)
$recvTask = $null
$msgBuild = [System.IO.MemoryStream]::new()
$lastRetransmitCheck = [DateTime]::UtcNow
$smuxKaTimer = [DateTime]::UtcNow

try {
while($script:running -and $script:ws.State -eq [System.Net.WebSockets.WebSocketState]::Open){

    $didWork = $false

    # ── 1. WebSocket receive ─────────────────────────────────────────────
    if($recvTask -eq $null){
        $recvTask = $script:ws.ReceiveAsync($recvSeg, [System.Threading.CancellationToken]::None)
    }
    if($recvTask.IsCompleted){
        $didWork = $true
        try {
            $result = $recvTask.GetAwaiter().GetResult()
            $recvTask = $null
            if($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close){
                [Console]::Error.WriteLine('WebSocket closed by server.')
                $script:running = $false; continue
            }
            $msgBuild.Write($recvBuf, 0, $result.Count)
            if($result.EndOfMessage){
                $complete = $msgBuild.ToArray()
                $msgBuild.SetLength(0)
                Route-WSMessage $complete $result.MessageType
            }
        } catch {
            [Console]::Error.WriteLine("WebSocket receive error: $_")
            $script:running = $false; continue
        }
    }

    # ── 2. Post-handshake setup ──────────────────────────────────────────
    if($script:hsComplete -and $script:streamMode -eq ''){
        $portType = ''
        if($script:portParams){
            $pp = $script:portParams
            if($pp.PSObject.Properties['type']){ $portType = $pp.type }
        }

        if($SshBridgeMode){
            # ── SSH Bridge mode: run SSH client in-process ──
            $script:streamMode = 'ssh-bridge'

            # Enable smux if the agent supports it (required for Port sessions)
            try {
                $av = [version]$script:agentVer
                $script:useMux = $av -gt $TCP_MUX_AFTER
            } catch { $script:useMux = $false }

            # Open a smux stream to port 22
            if($script:useMux){
                $script:sshSmuxId = Open-SmuxStream
                [Console]::Error.WriteLine("Opened smux stream $($script:sshSmuxId) for SSH bridge.")
            }

            $script:ssmToSsh = [System.Threading.Channels.Channel]::CreateUnbounded[byte[]]()
            $script:sshToSsm = [System.Threading.Channels.Channel]::CreateUnbounded[byte[]]()
            $script:sshCts   = [System.Threading.CancellationTokenSource]::new()

            $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
            . "$ScriptDir/SshClient.ps1"

            $rsa = Import-SshPrivateKey $SshKeyPath

            # Use a PowerShell runspace for the SSH thread (raw .NET threads lack a PS runspace)
            $sshScriptContent = Get-Content "$ScriptDir/SshClient.ps1" -Raw
            $paramLine = 'param($FromSsm, $ToSsm, $Username, $PrivateKey, $BindAddress, [int]$BindPort, [int]$LocalPort, $Cancel)'
            $callLine = 'Start-SshReverseTunnel -FromSsm $FromSsm -ToSsm $ToSsm -Username $Username -PrivateKey $PrivateKey -BindAddress $BindAddress -BindPort $BindPort -LocalPort $LocalPort -Cancel $Cancel'
            $wrapperScript = $paramLine + "`n" + $sshScriptContent + "`n" + $callLine
            $sshPs = [powershell]::Create()
            $null = $sshPs.AddScript($wrapperScript)
            $null = $sshPs.AddParameter('FromSsm', $script:ssmToSsh.Reader)
            $null = $sshPs.AddParameter('ToSsm', $script:sshToSsm.Writer)
            $null = $sshPs.AddParameter('Username', $SshUser)
            $null = $sshPs.AddParameter('PrivateKey', $rsa)
            $null = $sshPs.AddParameter('BindAddress', $SshBindAddress)
            $null = $sshPs.AddParameter('BindPort', $SshBindPort)
            $null = $sshPs.AddParameter('LocalPort', $SshLocalPort)
            $null = $sshPs.AddParameter('Cancel', $script:sshCts.Token)
            $script:sshHandle = $sshPs.BeginInvoke()
            $script:sshPs = $sshPs
            [Console]::Error.WriteLine("SSH bridge mode active for sessionId $sessionId.")
        } elseif($portType -eq 'LocalPortForwarding') {
            # ── TCP port forwarding (mux or basic) ──
            $script:streamMode = 'tcp'
            $lpStr = ''
            if($script:portParams.PSObject.Properties['localPortNumber']){ $lpStr = $script:portParams.localPortNumber }
            if(-not $lpStr){ $lpStr = '0' }
            $script:localPort = [int]$lpStr

            try {
                $av = [version]$script:agentVer
                $script:useMux = $av -gt $TCP_MUX_AFTER
            } catch { $script:useMux = $false }

            if($script:useMux){
                [Console]::Error.WriteLine("Using multiplexed port forwarding (agent $($script:agentVer)).")
            } else {
                [Console]::Error.WriteLine('Using basic port forwarding.')
            }

            $script:listener = New-Object System.Net.Sockets.TcpListener(
                [System.Net.IPAddress]::Loopback, $script:localPort)
            $script:listener.Start()
            $actual = $script:listener.LocalEndpoint.Port
            $script:localPort = $actual
            [Console]::Error.WriteLine("Port $actual opened for sessionId $sessionId.")
            [Console]::Error.WriteLine('Waiting for connections...')
        } else {
            # ── Stdin/stdout stream forwarding (for SSH ProxyCommand) ──
            $script:streamMode = 'stdio'
            $script:stdinStream  = [Console]::OpenStandardInput()
            $script:stdoutStream = [Console]::OpenStandardOutput()
            $script:stdinBuf     = [byte[]]::new($PAYLOAD_MAX)
            $script:stdinTask    = $script:stdinStream.ReadAsync($script:stdinBuf, 0, $PAYLOAD_MAX)
            [Console]::Error.WriteLine("Stream forwarding active for sessionId $sessionId.")
        }
    }

    # ── 3. Stdin read (stdio mode) ──────────────────────────────────────
    if($script:streamMode -eq 'stdio' -and $script:stdinTask -ne $null -and $script:stdinTask.IsCompleted){
        $didWork = $true
        try {
            $n = $script:stdinTask.GetAwaiter().GetResult()
            if($n -gt 0){
                $chunk = [byte[]]::new($n)
                [System.Buffer]::BlockCopy($script:stdinBuf,0,$chunk,0,$n)
                Send-Data $PT_OUTPUT $chunk
                $script:stdinTask = $script:stdinStream.ReadAsync($script:stdinBuf, 0, $PAYLOAD_MAX)
            } else {
                # stdin closed (SSH disconnected)
                [Console]::Error.WriteLine('Stdin closed.')
                $script:running = $false; continue
            }
        } catch {
            [Console]::Error.WriteLine("Stdin read error: $_")
            $script:running = $false; continue
        }
    }

    # ── 3b. SSH Bridge: drain sshToSsm channel ────────────────────────
    if($script:streamMode -eq 'ssh-bridge' -and $script:sshToSsm){
        $sshChunk = $null
        while($script:sshToSsm.Reader.TryRead([ref]$sshChunk)){
            $didWork = $true
            if($script:useMux -and $script:sshSmuxId){
                Write-SmuxData $script:sshSmuxId $sshChunk
            } else {
                Send-Data $PT_OUTPUT $sshChunk
            }
        }
        # Check if SSH runspace has completed
        if($script:sshHandle -and $script:sshHandle.IsCompleted){
            [Console]::Error.WriteLine('SSH client exited.')
            try {
                $script:sshPs.EndInvoke($script:sshHandle)
            } catch {
                [Console]::Error.WriteLine("SSH error: $_")
            }
            if($script:sshPs.Streams.Error.Count -gt 0){
                foreach($e in $script:sshPs.Streams.Error){
                    [Console]::Error.WriteLine("SSH: $($e.ToString())")
                    if($e.InvocationInfo){
                        [Console]::Error.WriteLine("  at line $($e.InvocationInfo.ScriptLineNumber)")
                    }
                    if($e.ScriptStackTrace){
                        [Console]::Error.WriteLine("  $($e.ScriptStackTrace)")
                    }
                }
            }
            $script:running = $false; continue
        }
    }

    # ── 4. Accept new TCP connections (tcp mode) ─────────────────────────
    if($script:streamMode -eq 'tcp' -and $script:listener -and $script:listener.Pending()){
        $didWork = $true
        $tc = $script:listener.AcceptTcpClient()
        $ns = $tc.GetStream()
        $ep = $tc.Client.RemoteEndPoint
        [Console]::Error.WriteLine("Connection accepted from $ep.")

        if($script:useMux){
            $sid = Open-SmuxStream
            $script:conns[$sid].Client = $tc
            $script:conns[$sid].Stream = $ns
        } else {
            if($script:basicClient){ try{$script:basicClient.Close()}catch{} }
            $script:basicClient = $tc
            $script:basicStream = $ns
        }
    }

    # ── 5. Read from TCP connections → send to data channel (tcp mode) ──
    if($script:streamMode -eq 'tcp'){
        if($script:useMux){
            foreach($sid in @($script:conns.Keys)){
                $c = $script:conns[$sid]
                if($c.Stream -eq $null){ continue }
                try {
                    if($c.Client.Connected -and $c.Stream.DataAvailable){
                        $didWork = $true
                        $tbuf = [byte[]]::new($SMUX_MAX_DATA)
                        $n = $c.Stream.Read($tbuf, 0, $SMUX_MAX_DATA)
                        if($n -gt 0){
                            $chunk = [byte[]]::new($n)
                            [System.Buffer]::BlockCopy($tbuf,0,$chunk,0,$n)
                            Write-SmuxData $sid $chunk
                        } else {
                            Close-SmuxStream $sid
                            [Console]::Error.WriteLine("Client disconnected from stream $sid.")
                        }
                    }
                } catch {
                    Close-SmuxStream $sid
                    [Console]::Error.WriteLine("Stream $sid error: $_")
                }
            }
        } else {
            if($script:basicStream -and $script:basicClient.Connected){
                try {
                    if($script:basicStream.DataAvailable){
                        $didWork = $true
                        $tbuf = [byte[]]::new($PAYLOAD_MAX)
                        $n = $script:basicStream.Read($tbuf, 0, $PAYLOAD_MAX)
                        if($n -gt 0){
                            $chunk = [byte[]]::new($n)
                            [System.Buffer]::BlockCopy($tbuf,0,$chunk,0,$n)
                            Send-Data $PT_OUTPUT $chunk
                        } else {
                            Send-SessionFlag $FLAG_DISCONNECT
                            try{$script:basicClient.Close()}catch{}
                            $script:basicClient=$null; $script:basicStream=$null
                            [Console]::Error.WriteLine('Client disconnected. Waiting for new connection...')
                        }
                    }
                } catch {
                    Send-SessionFlag $FLAG_DISCONNECT
                    try{$script:basicClient.Close()}catch{}
                    $script:basicClient=$null; $script:basicStream=$null
                    [Console]::Error.WriteLine("TCP read error: $_. Waiting for new connection...")
                }
            }
        }
    }

    # ── 6. Write pending smux data to TCP (tcp mode) ─────────────────────
    if($script:streamMode -eq 'tcp' -and $script:useMux){
        foreach($sid in @($script:conns.Keys)){
            $c = $script:conns[$sid]
            if($c.Stream -eq $null -or $c.Pending.Count -eq 0){ continue }
            $didWork = $true
            try {
                foreach($chunk in $c.Pending){
                    $c.Stream.Write($chunk, 0, $chunk.Length)
                }
                $c.Stream.Flush()
            } catch {
                Close-SmuxStream $sid
                [Console]::Error.WriteLine("Write error on stream ${sid}: $_")
            }
            $c.Pending.Clear()
        }
    }

    # ── 7. Retransmission check ──────────────────────────────────────────
    $now = [DateTime]::UtcNow
    if(($now - $lastRetransmitCheck).TotalMilliseconds -ge $RESEND_SLEEP_MS){
        Check-Retransmit
        $lastRetransmitCheck = $now
    }

    # ── 8. Smux NOP keepalive (if needed) ────────────────────────────────
    if($script:useMux -and $script:hsComplete){
        $kaDisabled = $false
        try { $kaDisabled = [version]$script:agentVer -gt $SMUX_KA_OFF_AFTER } catch {}
        if(-not $kaDisabled -and ($now - $smuxKaTimer).TotalSeconds -ge 10){
            $nop = New-SmuxFrame $SMUX_NOP ([uint32]0) $null
            Send-Data $PT_OUTPUT $nop
            $smuxKaTimer = $now
        }
    }

    # ── 9. Sleep if idle ───────────────────────────────────────────────
    if(-not $didWork){
        [System.Threading.Thread]::Sleep(1)
    }
}
} finally {
    # ── Cleanup ──────────────────────────────────────────────────────────
    [Console]::Error.WriteLine("`nCleaning up...")
    if($script:ws -and $script:ws.State -eq [System.Net.WebSockets.WebSocketState]::Open){
        try { Send-SessionFlag $FLAG_TERMINATE } catch {}
        try {
            $null = $script:ws.CloseAsync(
                [System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure,
                'done',
                [System.Threading.CancellationToken]::None
            ).GetAwaiter().GetResult()
        } catch {}
    }
    foreach($sid in @($script:conns.Keys)){
        try { $script:conns[$sid].Client.Close() } catch {}
    }
    if($script:basicClient){ try{$script:basicClient.Close()}catch{} }
    if($script:listener){ try{$script:listener.Stop()}catch{} }
    if($script:stdinStream){ try{$script:stdinStream.Dispose()}catch{} }
    if($script:stdoutStream){ try{$script:stdoutStream.Dispose()}catch{} }
    # SSH bridge cleanup
    if($script:sshCts){ try{$script:sshCts.Cancel()}catch{} }
    if($script:ssmToSsh){ try{$null = $script:ssmToSsh.Writer.TryComplete($null)}catch{} }
    if($script:sshHandle -and -not $script:sshHandle.IsCompleted){
        try{ $script:sshHandle.AsyncWaitHandle.WaitOne(5000) | Out-Null }catch{}
    }
    if($script:sshPs){ try{$script:sshPs.Dispose()}catch{} }
    if($script:sshCts){ try{$script:sshCts.Dispose()}catch{} }
    if($script:ws){ $script:ws.Dispose() }
    $msgBuild.Dispose()
    [Console]::Error.WriteLine('Session ended.')
}
