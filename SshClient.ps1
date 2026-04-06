#Requires -Version 5.1
<#
.SYNOPSIS
    Minimal SSH client for reverse port forwarding. Pure PowerShell/.NET implementation.
    Supports only the protocol subset needed for SSH -R tunnels.
    Compatible with PowerShell 5.1 / .NET Framework 4.7.2+.
#>

Add-Type -AssemblyName System.Numerics

# ── SSH Constants ───────────────────────────────────────────────────────────

$script:SSH_MSG_DISCONNECT           = [byte]1
$script:SSH_MSG_IGNORE               = [byte]2
$script:SSH_MSG_UNIMPLEMENTED        = [byte]3
$script:SSH_MSG_DEBUG                = [byte]4
$script:SSH_MSG_SERVICE_REQUEST      = [byte]5
$script:SSH_MSG_SERVICE_ACCEPT       = [byte]6
$script:SSH_MSG_KEXINIT              = [byte]20
$script:SSH_MSG_NEWKEYS              = [byte]21
$script:SSH_MSG_KEXDH_INIT           = [byte]30
$script:SSH_MSG_KEXDH_REPLY          = [byte]31
$script:SSH_MSG_USERAUTH_REQUEST     = [byte]50
$script:SSH_MSG_USERAUTH_FAILURE     = [byte]51
$script:SSH_MSG_USERAUTH_SUCCESS     = [byte]52
$script:SSH_MSG_USERAUTH_PK_OK       = [byte]60
$script:SSH_MSG_GLOBAL_REQUEST       = [byte]80
$script:SSH_MSG_REQUEST_SUCCESS      = [byte]81
$script:SSH_MSG_REQUEST_FAILURE      = [byte]82
$script:SSH_MSG_CHANNEL_OPEN         = [byte]90
$script:SSH_MSG_CHANNEL_OPEN_CONFIRM = [byte]91
$script:SSH_MSG_CHANNEL_OPEN_FAILURE = [byte]92
$script:SSH_MSG_CHANNEL_WINDOW_ADJUST = [byte]93
$script:SSH_MSG_CHANNEL_DATA         = [byte]94
$script:SSH_MSG_CHANNEL_EOF          = [byte]96
$script:SSH_MSG_CHANNEL_CLOSE        = [byte]97

$script:SSH_CLIENT_VERSION = 'SSH-2.0-PS-SessionManager_1.0'

# DH Group 14 prime (RFC 3526 Section 3 - 2048-bit MODP)
$script:DH_P = [System.Numerics.BigInteger]::Parse(
    '00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',
    [System.Globalization.NumberStyles]::HexNumber)
$script:DH_G = [System.Numerics.BigInteger]2

# ── SSH Wire Format Helpers ─────────────────────────────────────────────────

function _WriteU32([System.IO.MemoryStream]$s, [uint32]$v) {
    $b = [System.BitConverter]::GetBytes($v)
    if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
    $s.Write($b, 0, 4)
}

function _ReadU32([byte[]]$buf, [ref][int]$pos) {
    $t = [byte[]]::new(4)
    [System.Buffer]::BlockCopy($buf, $pos.Value, $t, 0, 4)
    if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($t) }
    $pos.Value += 4
    [System.BitConverter]::ToUInt32($t, 0)
}

function _WriteString([System.IO.MemoryStream]$s, [byte[]]$data) {
    _WriteU32 $s ([uint32]$data.Length)
    if ($data.Length -gt 0) { $s.Write($data, 0, $data.Length) }
}

function _WriteStringUtf8([System.IO.MemoryStream]$s, [string]$str) {
    _WriteString $s ([System.Text.Encoding]::UTF8.GetBytes($str))
}

function _ReadString([byte[]]$buf, [ref][int]$pos) {
    $len = [int](_ReadU32 $buf $pos)
    if ($len -eq 0) { return ,[byte[]]::new(0) }
    $data = [byte[]]::new($len)
    [System.Buffer]::BlockCopy($buf, $pos.Value, $data, 0, $len)
    $pos.Value += $len
    ,$data
}

function _ReadStringUtf8([byte[]]$buf, [ref][int]$pos) {
    [System.Text.Encoding]::UTF8.GetString((_ReadString $buf $pos))
}

function _WriteBool([System.IO.MemoryStream]$s, [bool]$v) {
    $s.WriteByte($(if ($v) { 1 } else { 0 }))
}

function _BigIntToBeBytes([System.Numerics.BigInteger]$v) {
    # .NET Framework ToByteArray() returns little-endian with sign byte.
    # Reverse to get big-endian (sign byte moves to index 0), which is SSH mpint.
    if ($v.IsZero) { return ,[byte[]]::new(0) }
    $le = $v.ToByteArray()   # LE, minimal two's complement
    [Array]::Reverse($le)    # now big-endian
    ,$le
}

function _WriteMPInt([System.IO.MemoryStream]$s, [System.Numerics.BigInteger]$v) {
    if ($v.IsZero) { _WriteU32 $s 0; return }
    $be = _BigIntToBeBytes $v
    _WriteU32 $s ([uint32]$be.Length)
    $s.Write($be, 0, $be.Length)
}

function _ReadMPInt([byte[]]$buf, [ref][int]$pos) {
    $data = _ReadString $buf $pos
    if ($data.Length -eq 0) { return [System.Numerics.BigInteger]::Zero }
    # SSH mpint is big-endian. Reverse to LE, append 0x00 to ensure positive.
    $le = [byte[]]::new($data.Length + 1)
    for ($i = 0; $i -lt $data.Length; $i++) { $le[$data.Length - 1 - $i] = $data[$i] }
    [System.Numerics.BigInteger]::new($le)
}

function _WriteNameList([System.IO.MemoryStream]$s, [string[]]$names) {
    _WriteStringUtf8 $s ($names -join ',')
}

function _GetRandomBytes([int]$count) {
    $buf = [byte[]]::new($count)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($buf); $rng.Dispose()
    ,$buf
}

# ── AES-128-CTR Cipher ─────────────────────────────────────────────────────

function New-AesCtrCipher([byte[]]$key, [byte[]]$iv) {
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $aes.KeySize = $key.Length * 8
    $aes.Key = $key
    $encryptor = $aes.CreateEncryptor()
    $counter = [byte[]]::new(16)
    [System.Buffer]::BlockCopy($iv, 0, $counter, 0, 16)
    @{ Encryptor = $encryptor; Counter = $counter; Aes = $aes }
}

function Invoke-AesCtr([hashtable]$cipher, [byte[]]$data) {
    $result = [byte[]]::new($data.Length)
    $keystream = [byte[]]::new(16)
    $off = 0
    while ($off -lt $data.Length) {
        $null = $cipher.Encryptor.TransformBlock($cipher.Counter, 0, 16, $keystream, 0)
        $n = [Math]::Min(16, $data.Length - $off)
        for ($i = 0; $i -lt $n; $i++) {
            $result[$off + $i] = $data[$off + $i] -bxor $keystream[$i]
        }
        for ($j = 15; $j -ge 0; $j--) {
            $v = [int]$cipher.Counter[$j] + 1
            $cipher.Counter[$j] = [byte]($v -band 0xFF)
            if ($v -lt 256) { break }
        }
        $off += $n
    }
    ,$result
}

# ── SSH Packet Layer ────────────────────────────────────────────────────────
# Transport: BlockingCollection<byte[]> for FromSsm / ToSsm

function _SshSend([hashtable]$st, [byte[]]$payload) {
    $blockSize = if ($st.EncOut) { 16 } else { 8 }
    $raw = $payload.Length + 5
    $pad = $blockSize - ($raw % $blockSize)
    if ($pad -lt 4) { $pad += $blockSize }
    $packetLen = [uint32]($payload.Length + $pad + 1)

    $ms = [System.IO.MemoryStream]::new()
    _WriteU32 $ms $packetLen
    $ms.WriteByte([byte]$pad)
    $ms.Write($payload, 0, $payload.Length)
    $padding = _GetRandomBytes $pad
    $ms.Write($padding, 0, $pad)
    $packet = $ms.ToArray(); $ms.Dispose()

    if ($st.MacOut) {
        $macMs = [System.IO.MemoryStream]::new()
        $seqB = [System.BitConverter]::GetBytes([uint32]$st.TxSeq)
        if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($seqB) }
        $macMs.Write($seqB, 0, 4)
        $macMs.Write($packet, 0, $packet.Length)
        $mac = $st.MacOut.ComputeHash($macMs.ToArray()); $macMs.Dispose()
    }

    if ($st.EncOut) { $packet = Invoke-AesCtr $st.EncOut $packet }

    $st.ToSsm.Add($packet)
    if ($st.MacOut) { $st.ToSsm.Add($mac) }
    $st.TxSeq++
}

function _SshRecv([hashtable]$st) {
    $blockSize = if ($st.EncIn) { 16 } else { 8 }
    $macLen = if ($st.MacIn) { 32 } else { 0 }

    $firstBlock = _ReadTransport $st $blockSize
    if ($st.EncIn) { $firstBlock = Invoke-AesCtr $st.EncIn $firstBlock }

    $lenB = [byte[]]::new(4)
    [System.Buffer]::BlockCopy($firstBlock, 0, $lenB, 0, 4)
    if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($lenB) }
    $packetLen = [System.BitConverter]::ToUInt32($lenB, 0)

    $remaining = $packetLen + 4 - $blockSize
    $restEnc = if ($remaining -gt 0) { _ReadTransport $st $remaining } else { [byte[]]::new(0) }
    if ($st.EncIn -and $remaining -gt 0) { $restEnc = Invoke-AesCtr $st.EncIn $restEnc }

    $full = [byte[]]::new($packetLen + 4)
    [System.Buffer]::BlockCopy($firstBlock, 0, $full, 0, $blockSize)
    if ($remaining -gt 0) { [System.Buffer]::BlockCopy($restEnc, 0, $full, $blockSize, $remaining) }

    if ($macLen -gt 0) {
        $recvMac = _ReadTransport $st $macLen
        $macMs = [System.IO.MemoryStream]::new()
        $seqB = [System.BitConverter]::GetBytes([uint32]$st.RxSeq)
        if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($seqB) }
        $macMs.Write($seqB, 0, 4)
        $macMs.Write($full, 0, $full.Length)
        $expected = $st.MacIn.ComputeHash($macMs.ToArray()); $macMs.Dispose()
        for ($i = 0; $i -lt $macLen; $i++) {
            if ($recvMac[$i] -ne $expected[$i]) { throw 'SSH MAC verification failed' }
        }
    }

    $st.RxSeq++
    $padLen = $full[4]
    $payloadLen = $packetLen - $padLen - 1
    $payload = [byte[]]::new($payloadLen)
    [System.Buffer]::BlockCopy($full, 5, $payload, 0, $payloadLen)
    ,$payload
}

function _ReadTransport([hashtable]$st, [int]$count) {
    while ($st.ReadBuf.Count -lt $count) {
        # BlockingCollection.Take() blocks until an item is available.
        # Throws InvalidOperationException when CompleteAdding has been called and collection is empty.
        try {
            $chunk = $st.FromSsm.Take()
        } catch [System.InvalidOperationException] {
            throw 'Transport channel closed'
        }
        if ($null -eq $chunk) { throw 'Transport channel closed (null)' }
        $st.ReadBuf.AddRange([byte[]]$chunk)
        # Drain any additional items already queued
        $more = $null
        while ($st.FromSsm.TryTake([ref]$more, 0)) {
            $st.ReadBuf.AddRange([byte[]]$more)
        }
    }
    $result = [byte[]]::new($count)
    $st.ReadBuf.CopyTo(0, $result, 0, $count)
    $st.ReadBuf.RemoveRange(0, $count)
    ,$result
}

function _ReadLine([hashtable]$st) {
    $line = [System.Collections.Generic.List[byte]]::new()
    while ($true) {
        while ($st.ReadBuf.Count -eq 0) {
            try {
                $chunk = $st.FromSsm.Take()
            } catch [System.InvalidOperationException] {
                throw 'Transport channel closed in _ReadLine'
            }
            $st.ReadBuf.AddRange([byte[]]$chunk)
            $more = $null
            while ($st.FromSsm.TryTake([ref]$more, 0)) {
                $st.ReadBuf.AddRange([byte[]]$more)
            }
        }
        $b = $st.ReadBuf[0]; $st.ReadBuf.RemoveAt(0)
        if ($b -eq 0x0A) { break }
        $line.Add($b)
    }
    $arr = $line.ToArray()
    if ($arr.Length -gt 0 -and $arr[$arr.Length - 1] -eq 0x0D) {
        $arr = $arr[0..($arr.Length - 2)]
    }
    [System.Text.Encoding]::UTF8.GetString($arr)
}

# ── SSH Key I/O ─────────────────────────────────────────────────────────────

function _SshPubKeyBlob([System.Security.Cryptography.RSA]$rsa) {
    $p = $rsa.ExportParameters($false)
    $ms = [System.IO.MemoryStream]::new()
    _WriteStringUtf8 $ms 'ssh-rsa'
    _WriteString $ms $p.Exponent
    $n = $p.Modulus
    if ($n[0] -band 0x80) { $n = [byte[]]@(0) + $n }
    _WriteString $ms $n
    $blob = $ms.ToArray(); $ms.Dispose()
    ,$blob
}

function Export-SshPublicKey([System.Security.Cryptography.RSA]$rsa, [string]$comment = '') {
    $blob = _SshPubKeyBlob $rsa
    $b64 = [System.Convert]::ToBase64String($blob)
    $line = "ssh-rsa $b64"
    if ($comment) { $line += " $comment" }
    $line
}

function Export-SshPrivateKey([System.Security.Cryptography.RSA]$rsa, [string]$comment = '') {
    $p = $rsa.ExportParameters($true)
    $pubBlob = _SshPubKeyBlob $rsa

    $priv = [System.IO.MemoryStream]::new()
    $checkInt = [uint32](Get-Random -Maximum ([int]::MaxValue))
    _WriteU32 $priv $checkInt
    _WriteU32 $priv $checkInt
    _WriteStringUtf8 $priv 'ssh-rsa'
    $n = $p.Modulus; if ($n[0] -band 0x80) { $n = [byte[]]@(0) + $n }
    _WriteString $priv $n
    _WriteString $priv $p.Exponent
    $d = $p.D; if ($d[0] -band 0x80) { $d = [byte[]]@(0) + $d }
    _WriteString $priv $d
    $iqmp = $p.InverseQ; if ($iqmp[0] -band 0x80) { $iqmp = [byte[]]@(0) + $iqmp }
    _WriteString $priv $iqmp
    $pp = $p.P; if ($pp[0] -band 0x80) { $pp = [byte[]]@(0) + $pp }
    _WriteString $priv $pp
    $qq = $p.Q; if ($qq[0] -band 0x80) { $qq = [byte[]]@(0) + $qq }
    _WriteString $priv $qq
    _WriteStringUtf8 $priv $comment
    $padN = 8 - ([int]$priv.Length % 8)
    if ($padN -eq 8) { $padN = 0 }
    for ($i = 1; $i -le $padN; $i++) { $priv.WriteByte([byte]$i) }
    $privBytes = $priv.ToArray(); $priv.Dispose()

    $outer = [System.IO.MemoryStream]::new()
    $magic = [System.Text.Encoding]::UTF8.GetBytes("openssh-key-v1`0")
    $outer.Write($magic, 0, $magic.Length)
    _WriteStringUtf8 $outer 'none'
    _WriteStringUtf8 $outer 'none'
    $emptyBytes = [byte[]]::new(0)
    _WriteString $outer $emptyBytes
    _WriteU32 $outer 1
    _WriteString $outer $pubBlob
    _WriteString $outer $privBytes
    $outerBytes = $outer.ToArray(); $outer.Dispose()

    $b64 = [System.Convert]::ToBase64String($outerBytes)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('-----BEGIN OPENSSH PRIVATE KEY-----')
    for ($i = 0; $i -lt $b64.Length; $i += 70) {
        $lines.Add($b64.Substring($i, [Math]::Min(70, $b64.Length - $i)))
    }
    $lines.Add('-----END OPENSSH PRIVATE KEY-----')
    $lines.Add('')
    $lines -join "`n"
}

function New-SshRsaKeyPair {
    param([int]$KeyBits = 4096, [string]$Comment = '')
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider($KeyBits)
    @{
        Rsa           = $rsa
        PublicKeyLine = Export-SshPublicKey $rsa $Comment
        PrivateKeyPem = Export-SshPrivateKey $rsa $Comment
    }
}

function Import-SshPrivateKey([string]$path) {
    $content = Get-Content $path -Raw
    if ($content -match 'BEGIN OPENSSH PRIVATE KEY') {
        $b64 = ($content -replace '-----[^-]+-----', '' -replace '\s', '')
        $data = [System.Convert]::FromBase64String($b64)
        $magic = [System.Text.Encoding]::UTF8.GetString($data[0..14])
        if ($magic -ne "openssh-key-v1`0") { throw "Invalid OpenSSH key magic" }
        $pos = [ref]15
        $cipher = _ReadStringUtf8 $data $pos
        if ($cipher -ne 'none') { throw "Encrypted SSH keys not supported (cipher: $cipher)" }
        $null = _ReadStringUtf8 $data $pos
        $null = _ReadString $data $pos
        $null = _ReadU32 $data $pos
        $null = _ReadString $data $pos
        $privSection = _ReadString $data $pos
        $pp = [ref]0
        $check1 = _ReadU32 $privSection $pp
        $check2 = _ReadU32 $privSection $pp
        if ($check1 -ne $check2) { throw 'SSH key checkint mismatch' }
        $keyType = _ReadStringUtf8 $privSection $pp
        if ($keyType -ne 'ssh-rsa') { throw "Unsupported key type: $keyType" }
        $n_bytes = _ReadString $privSection $pp
        $e_bytes = _ReadString $privSection $pp
        $d_bytes = _ReadString $privSection $pp
        $iqmp_bytes = _ReadString $privSection $pp
        $p_bytes = _ReadString $privSection $pp
        $q_bytes = _ReadString $privSection $pp
        $strip = { param([byte[]]$b) if ($b.Length -gt 1 -and $b[0] -eq 0) { $b[1..($b.Length-1)] } else { $b } }
        $params = New-Object System.Security.Cryptography.RSAParameters
        $params.Modulus  = & $strip $n_bytes
        $params.Exponent = & $strip $e_bytes
        $params.D        = & $strip $d_bytes
        $params.InverseQ = & $strip $iqmp_bytes
        $params.P        = & $strip $p_bytes
        $params.Q        = & $strip $q_bytes
        # Compute DP and DQ from D, P, Q using BigInteger
        $toBI = {
            param([byte[]]$b)
            $le = [byte[]]::new($b.Length + 1)
            for ($i = 0; $i -lt $b.Length; $i++) { $le[$b.Length - 1 - $i] = $b[$i] }
            [System.Numerics.BigInteger]::new($le)
        }
        $dBig = & $toBI $params.D
        $pBig = & $toBI $params.P
        $qBig = & $toBI $params.Q
        $dpBig = $dBig % ($pBig - [System.Numerics.BigInteger]::One)
        $dqBig = $dBig % ($qBig - [System.Numerics.BigInteger]::One)
        $dpLE = $dpBig.ToByteArray(); [Array]::Reverse($dpLE)
        $dqLE = $dqBig.ToByteArray(); [Array]::Reverse($dqLE)
        # Strip leading zero if present and ensure length matches P/Q
        if ($dpLE[0] -eq 0 -and $dpLE.Length -gt $params.P.Length) { $dpLE = $dpLE[1..($dpLE.Length-1)] }
        if ($dqLE[0] -eq 0 -and $dqLE.Length -gt $params.Q.Length) { $dqLE = $dqLE[1..($dqLE.Length-1)] }
        while ($dpLE.Length -lt $params.P.Length) { $dpLE = [byte[]]@(0) + $dpLE }
        while ($dqLE.Length -lt $params.Q.Length) { $dqLE = [byte[]]@(0) + $dqLE }
        $params.DP = $dpLE
        $params.DQ = $dqLE
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.ImportParameters($params)
        return $rsa
    }
    throw "Unsupported key format. Only OpenSSH private key format (ssh-rsa) is supported."
}

# ── Key Exchange ────────────────────────────────────────────────────────────

function _Sha256Bytes([byte[]]$data) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ,$sha.ComputeHash($data) } finally { $sha.Dispose() }
}

function _DeriveKey([byte[]]$K_mpint, [byte[]]$H, [byte]$letter, [byte[]]$sessionId, [int]$needed) {
    $ms = [System.IO.MemoryStream]::new()
    $ms.Write($K_mpint, 0, $K_mpint.Length)
    $ms.Write($H, 0, $H.Length)
    $ms.WriteByte($letter)
    $ms.Write($sessionId, 0, $sessionId.Length)
    $key = _Sha256Bytes $ms.ToArray(); $ms.Dispose()
    if ($key.Length -ge $needed) {
        $result = [byte[]]::new($needed)
        [System.Buffer]::BlockCopy($key, 0, $result, 0, $needed)
        return ,$result
    }
    $accum = [System.Collections.Generic.List[byte]]::new($key)
    while ($accum.Count -lt $needed) {
        $ms2 = [System.IO.MemoryStream]::new()
        $ms2.Write($K_mpint, 0, $K_mpint.Length)
        $ms2.Write($H, 0, $H.Length)
        $ms2.Write($accum.ToArray(), 0, $accum.Count)
        $ext = _Sha256Bytes $ms2.ToArray(); $ms2.Dispose()
        $accum.AddRange($ext)
    }
    $result = [byte[]]::new($needed)
    $accum.CopyTo(0, $result, 0, $needed)
    ,$result
}

function _DoKeyExchange([hashtable]$st) {
    $clientKexInit = [System.IO.MemoryStream]::new()
    $clientKexInit.WriteByte($SSH_MSG_KEXINIT)
    $cookie = _GetRandomBytes 16
    $clientKexInit.Write($cookie, 0, 16)
    _WriteNameList $clientKexInit @('diffie-hellman-group14-sha256')
    _WriteNameList $clientKexInit @('ssh-ed25519','ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521','rsa-sha2-256','rsa-sha2-512','ssh-rsa')
    _WriteNameList $clientKexInit @('aes128-ctr')
    _WriteNameList $clientKexInit @('aes128-ctr')
    _WriteNameList $clientKexInit @('hmac-sha2-256')
    _WriteNameList $clientKexInit @('hmac-sha2-256')
    _WriteNameList $clientKexInit @('none')
    _WriteNameList $clientKexInit @('none')
    _WriteNameList $clientKexInit @()
    _WriteNameList $clientKexInit @()
    _WriteBool $clientKexInit $false
    _WriteU32 $clientKexInit 0
    $I_C = $clientKexInit.ToArray(); $clientKexInit.Dispose()
    _SshSend $st $I_C

    $I_S = _SshRecv $st
    if ($I_S[0] -ne $SSH_MSG_KEXINIT) { throw "Expected KEXINIT, got $($I_S[0])" }

    $xBytes = _GetRandomBytes 32
    $xBytes[0] = $xBytes[0] -band 0x7F
    $xLE = [byte[]]::new($xBytes.Length + 1)
    for ($i = 0; $i -lt $xBytes.Length; $i++) { $xLE[$xBytes.Length - 1 - $i] = $xBytes[$i] }
    $x = [System.Numerics.BigInteger]::new($xLE)
    $e = [System.Numerics.BigInteger]::ModPow($DH_G, $x, $DH_P)

    $dhInit = [System.IO.MemoryStream]::new()
    $dhInit.WriteByte($SSH_MSG_KEXDH_INIT)
    _WriteMPInt $dhInit $e
    _SshSend $st $dhInit.ToArray(); $dhInit.Dispose()

    $reply = _SshRecv $st
    if ($reply[0] -ne $SSH_MSG_KEXDH_REPLY) { throw "Expected KEXDH_REPLY, got $($reply[0])" }
    $rpos = [ref]1
    $K_S = _ReadString $reply $rpos
    $f = _ReadMPInt $reply $rpos
    $null = _ReadString $reply $rpos  # signature (not verified)

    $K = [System.Numerics.BigInteger]::ModPow($f, $x, $DH_P)

    $hms = [System.IO.MemoryStream]::new()
    _WriteStringUtf8 $hms $st.ClientVersion
    _WriteStringUtf8 $hms $st.ServerVersion
    _WriteString $hms $I_C
    _WriteString $hms $I_S
    _WriteString $hms $K_S
    _WriteMPInt $hms $e
    _WriteMPInt $hms $f
    _WriteMPInt $hms $K
    $H = _Sha256Bytes $hms.ToArray(); $hms.Dispose()

    if (-not $st.SessionId) { $st.SessionId = $H }

    $kms = [System.IO.MemoryStream]::new()
    _WriteMPInt $kms $K
    $K_mpint = $kms.ToArray(); $kms.Dispose()

    _SshSend $st ([byte[]]@($SSH_MSG_NEWKEYS))

    $nk = _SshRecv $st
    if ($nk[0] -ne $SSH_MSG_NEWKEYS) { throw "Expected NEWKEYS, got $($nk[0])" }

    $ivCS  = _DeriveKey $K_mpint $H ([byte][char]'A') $st.SessionId 16
    $ivSC  = _DeriveKey $K_mpint $H ([byte][char]'B') $st.SessionId 16
    $keyCS = _DeriveKey $K_mpint $H ([byte][char]'C') $st.SessionId 16
    $keySC = _DeriveKey $K_mpint $H ([byte][char]'D') $st.SessionId 16
    $macCS = _DeriveKey $K_mpint $H ([byte][char]'E') $st.SessionId 32
    $macSC = _DeriveKey $K_mpint $H ([byte][char]'F') $st.SessionId 32

    $st.EncOut = New-AesCtrCipher $keyCS $ivCS
    $st.EncIn  = New-AesCtrCipher $keySC $ivSC
    $st.MacOut = [System.Security.Cryptography.HMACSHA256]::new($macCS)
    $st.MacIn  = [System.Security.Cryptography.HMACSHA256]::new($macSC)

    [Console]::Error.WriteLine('SSH key exchange complete.')
}

# ── Authentication ──────────────────────────────────────────────────────────

function _DoAuth([hashtable]$st, [string]$username, [System.Security.Cryptography.RSA]$rsa) {
    $sreq = [System.IO.MemoryStream]::new()
    $sreq.WriteByte($SSH_MSG_SERVICE_REQUEST)
    _WriteStringUtf8 $sreq 'ssh-userauth'
    _SshSend $st $sreq.ToArray(); $sreq.Dispose()

    $resp = _SshRecv $st
    if ($resp[0] -ne $SSH_MSG_SERVICE_ACCEPT) { throw "Expected SERVICE_ACCEPT, got $($resp[0])" }

    $pubBlob = _SshPubKeyBlob $rsa
    $algoName = 'rsa-sha2-256'

    $probe = [System.IO.MemoryStream]::new()
    $probe.WriteByte($SSH_MSG_USERAUTH_REQUEST)
    _WriteStringUtf8 $probe $username
    _WriteStringUtf8 $probe 'ssh-connection'
    _WriteStringUtf8 $probe 'publickey'
    _WriteBool $probe $false
    _WriteStringUtf8 $probe $algoName
    _WriteString $probe $pubBlob
    _SshSend $st $probe.ToArray(); $probe.Dispose()

    $resp = _SshRecv $st
    if ($resp[0] -eq $SSH_MSG_USERAUTH_FAILURE) { throw "SSH publickey auth not accepted for user '$username'" }
    if ($resp[0] -ne $SSH_MSG_USERAUTH_PK_OK) { throw "Expected USERAUTH_PK_OK, got $($resp[0])" }

    $sigData = [System.IO.MemoryStream]::new()
    _WriteString $sigData $st.SessionId
    $sigData.WriteByte($SSH_MSG_USERAUTH_REQUEST)
    _WriteStringUtf8 $sigData $username
    _WriteStringUtf8 $sigData 'ssh-connection'
    _WriteStringUtf8 $sigData 'publickey'
    _WriteBool $sigData $true
    _WriteStringUtf8 $sigData $algoName
    _WriteString $sigData $pubBlob
    $dataToSign = $sigData.ToArray(); $sigData.Dispose()

    $rawSig = $rsa.SignData($dataToSign, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

    $sigBlob = [System.IO.MemoryStream]::new()
    _WriteStringUtf8 $sigBlob $algoName
    _WriteString $sigBlob $rawSig
    $sigBlobBytes = $sigBlob.ToArray(); $sigBlob.Dispose()

    $auth = [System.IO.MemoryStream]::new()
    $auth.WriteByte($SSH_MSG_USERAUTH_REQUEST)
    _WriteStringUtf8 $auth $username
    _WriteStringUtf8 $auth 'ssh-connection'
    _WriteStringUtf8 $auth 'publickey'
    _WriteBool $auth $true
    _WriteStringUtf8 $auth $algoName
    _WriteString $auth $pubBlob
    _WriteString $auth $sigBlobBytes
    _SshSend $st $auth.ToArray(); $auth.Dispose()

    $resp = _SshRecv $st
    if ($resp[0] -eq $SSH_MSG_USERAUTH_FAILURE) { throw 'SSH authentication failed' }
    if ($resp[0] -ne $SSH_MSG_USERAUTH_SUCCESS) { throw "Expected USERAUTH_SUCCESS, got $($resp[0])" }
    [Console]::Error.WriteLine('SSH authentication successful.')
}

# ── Channel Management ──────────────────────────────────────────────────────

function _RequestForward([hashtable]$st, [string]$bindAddr, [int]$bindPort) {
    $req = [System.IO.MemoryStream]::new()
    $req.WriteByte($SSH_MSG_GLOBAL_REQUEST)
    _WriteStringUtf8 $req 'tcpip-forward'
    _WriteBool $req $true
    _WriteStringUtf8 $req $bindAddr
    _WriteU32 $req ([uint32]$bindPort)
    _SshSend $st $req.ToArray(); $req.Dispose()

    while ($true) {
        $resp = _SshRecv $st
        if ($resp[0] -eq $SSH_MSG_REQUEST_SUCCESS) {
            $rp = [ref]1
            $boundPort = if ($resp.Length -ge 5) { _ReadU32 $resp $rp } else { $bindPort }
            [Console]::Error.WriteLine("SSH reverse forwarding active: $bindAddr`:$boundPort")
            return $boundPort
        } elseif ($resp[0] -eq $SSH_MSG_REQUEST_FAILURE) {
            throw "Server rejected tcpip-forward request for $bindAddr`:$bindPort"
        } else {
            _DispatchPacket $st $resp
        }
    }
}

function _DispatchPacket([hashtable]$st, [byte[]]$payload) {
    switch ($payload[0]) {
        $SSH_MSG_CHANNEL_OPEN {
            $p = [ref]1
            $chanType = _ReadStringUtf8 $payload $p
            $senderChan = _ReadU32 $payload $p
            $initWindow = _ReadU32 $payload $p
            $maxPacket = _ReadU32 $payload $p
            if ($chanType -eq 'forwarded-tcpip') {
                $null = _ReadStringUtf8 $payload $p  # connAddr
                $null = _ReadU32 $payload $p          # connPort
                $origAddr = _ReadStringUtf8 $payload $p
                $origPort = _ReadU32 $payload $p
                $localChan = $st.NextChanId++
                try {
                    $tc = New-Object System.Net.Sockets.TcpClient
                    $tc.Connect('127.0.0.1', $st.LocalPort)
                    $ns = $tc.GetStream()
                    $st.Channels[$localChan] = @{
                        RemoteChan = $senderChan; RemoteWin = $initWindow
                        RemoteMax = $maxPacket; LocalWin = [uint32]2097152
                        Client = $tc; Stream = $ns; EofSent = $false; CloseSent = $false
                    }
                    $confirm = [System.IO.MemoryStream]::new()
                    $confirm.WriteByte($SSH_MSG_CHANNEL_OPEN_CONFIRM)
                    _WriteU32 $confirm $senderChan
                    _WriteU32 $confirm $localChan
                    _WriteU32 $confirm 2097152
                    _WriteU32 $confirm 32768
                    _SshSend $st $confirm.ToArray(); $confirm.Dispose()
                    [Console]::Error.WriteLine("Reverse channel $localChan opened ($origAddr`:$origPort -> localhost:$($st.LocalPort))")
                } catch {
                    [Console]::Error.WriteLine("Failed to connect to localhost:$($st.LocalPort): $_")
                    $fail = [System.IO.MemoryStream]::new()
                    $fail.WriteByte($SSH_MSG_CHANNEL_OPEN_FAILURE)
                    _WriteU32 $fail $senderChan
                    _WriteU32 $fail 2
                    _WriteStringUtf8 $fail 'Connection refused'
                    _WriteStringUtf8 $fail ''
                    _SshSend $st $fail.ToArray(); $fail.Dispose()
                }
            }
        }
        $SSH_MSG_CHANNEL_DATA {
            $p = [ref]1
            $recipientChan = _ReadU32 $payload $p
            $data = _ReadString $payload $p
            if ($st.Channels.ContainsKey($recipientChan)) {
                $ch = $st.Channels[$recipientChan]
                try {
                    $ch.Stream.Write($data, 0, $data.Length)
                    $ch.Stream.Flush()
                } catch { _CloseChannel $st $recipientChan }
                $ch.LocalWin -= $data.Length
                if ($ch.LocalWin -lt 1048576) {
                    $adj = [System.IO.MemoryStream]::new()
                    $adj.WriteByte($SSH_MSG_CHANNEL_WINDOW_ADJUST)
                    _WriteU32 $adj $ch.RemoteChan
                    _WriteU32 $adj 2097152
                    _SshSend $st $adj.ToArray(); $adj.Dispose()
                    $ch.LocalWin += 2097152
                }
            }
        }
        $SSH_MSG_CHANNEL_WINDOW_ADJUST {
            $p = [ref]1; $recipientChan = _ReadU32 $payload $p; $bytes = _ReadU32 $payload $p
            if ($st.Channels.ContainsKey($recipientChan)) { $st.Channels[$recipientChan].RemoteWin += $bytes }
        }
        $SSH_MSG_CHANNEL_EOF { }
        $SSH_MSG_CHANNEL_CLOSE {
            $p = [ref]1; $recipientChan = _ReadU32 $payload $p
            if ($st.Channels.ContainsKey($recipientChan)) {
                $ch = $st.Channels[$recipientChan]
                if (-not $ch.CloseSent) {
                    $cls = [System.IO.MemoryStream]::new()
                    $cls.WriteByte($SSH_MSG_CHANNEL_CLOSE)
                    _WriteU32 $cls $ch.RemoteChan
                    _SshSend $st $cls.ToArray(); $cls.Dispose()
                }
                try { $ch.Client.Close() } catch {}
                $st.Channels.Remove($recipientChan)
                [Console]::Error.WriteLine("Channel $recipientChan closed.")
            }
        }
        $SSH_MSG_GLOBAL_REQUEST {
            $p = [ref]1; $null = _ReadStringUtf8 $payload $p
            $wantReply = $payload[$p.Value] -ne 0
            if ($wantReply) { _SshSend $st ([byte[]]@($SSH_MSG_REQUEST_FAILURE)) }
        }
        $SSH_MSG_DISCONNECT {
            $p = [ref]1; $null = _ReadU32 $payload $p
            $desc = _ReadStringUtf8 $payload $p
            [Console]::Error.WriteLine("SSH disconnect: $desc"); $st.Running = $false
        }
        $SSH_MSG_IGNORE { }
        $SSH_MSG_DEBUG { }
    }
}

function _CloseChannel([hashtable]$st, [uint32]$chanId) {
    if (-not $st.Channels.ContainsKey($chanId)) { return }
    $ch = $st.Channels[$chanId]
    if (-not $ch.EofSent) {
        $eof = [System.IO.MemoryStream]::new()
        $eof.WriteByte($SSH_MSG_CHANNEL_EOF)
        _WriteU32 $eof $ch.RemoteChan
        _SshSend $st $eof.ToArray(); $eof.Dispose()
        $ch.EofSent = $true
    }
    if (-not $ch.CloseSent) {
        $cls = [System.IO.MemoryStream]::new()
        $cls.WriteByte($SSH_MSG_CHANNEL_CLOSE)
        _WriteU32 $cls $ch.RemoteChan
        _SshSend $st $cls.ToArray(); $cls.Dispose()
        $ch.CloseSent = $true
    }
    try { $ch.Client.Close() } catch {}
}

function _SendChannelData([hashtable]$st, [uint32]$chanId, [byte[]]$data) {
    $ch = $st.Channels[$chanId]
    $off = 0
    while ($off -lt $data.Length) {
        while ($ch.RemoteWin -le 0) { $pkt = _SshRecv $st; _DispatchPacket $st $pkt }
        $n = [Math]::Min([int]$ch.RemoteWin, [Math]::Min([int]$ch.RemoteMax, $data.Length - $off))
        $chunk = [byte[]]::new($n)
        [System.Buffer]::BlockCopy($data, $off, $chunk, 0, $n)
        $msg = [System.IO.MemoryStream]::new()
        $msg.WriteByte($SSH_MSG_CHANNEL_DATA)
        _WriteU32 $msg $ch.RemoteChan
        _WriteString $msg $chunk
        _SshSend $st $msg.ToArray(); $msg.Dispose()
        $ch.RemoteWin -= $n
        $off += $n
    }
}

# ── Main SSH Entry Point ───────────────────────────────────────────────────
# Uses BlockingCollection<byte[]> for FromSsm / ToSsm (PS 5.1 compatible).

function Start-SshReverseTunnel {
    param(
        [System.Collections.Concurrent.BlockingCollection[byte[]]]$FromSsm,
        [System.Collections.Concurrent.BlockingCollection[byte[]]]$ToSsm,
        [string]$Username,
        [System.Security.Cryptography.RSA]$PrivateKey,
        [string]$BindAddress,
        [int]$BindPort,
        [int]$LocalPort
    )

    $st = @{
        FromSsm       = $FromSsm
        ToSsm         = $ToSsm
        ReadBuf       = [System.Collections.Generic.List[byte]]::new()
        TxSeq         = [uint32]0
        RxSeq         = [uint32]0
        EncOut        = $null
        EncIn         = $null
        MacOut        = $null
        MacIn         = $null
        SessionId     = $null
        ClientVersion = $SSH_CLIENT_VERSION
        ServerVersion = $null
        Channels      = @{}
        NextChanId    = [uint32]0
        LocalPort     = $LocalPort
        Running       = $true
    }

    try {
        $verBytes = [System.Text.Encoding]::UTF8.GetBytes("$SSH_CLIENT_VERSION`r`n")
        $st.ToSsm.Add($verBytes)
        $st.ServerVersion = _ReadLine $st
        [Console]::Error.WriteLine("SSH server: $($st.ServerVersion)")

        _DoKeyExchange $st
        _DoAuth $st $Username $PrivateKey
        $boundPort = _RequestForward $st $BindAddress $BindPort
        [Console]::Error.WriteLine("Reverse tunnel active: remote $BindAddress`:$boundPort -> localhost:$LocalPort")

        $lastKeepalive = [DateTime]::UtcNow
        while ($st.Running) {
            $didWork = $false

            # Drain incoming data from SSM
            $chunk = $null
            while ($st.FromSsm.TryTake([ref]$chunk, 0)) {
                $st.ReadBuf.AddRange([byte[]]$chunk)
                $didWork = $true
            }

            # Parse SSH packets if enough data
            while ($st.ReadBuf.Count -ge 5 -and $st.Running) {
                try {
                    $pkt = _SshRecv $st
                    _DispatchPacket $st $pkt
                    $didWork = $true
                } catch [System.InvalidOperationException] { break }
            }

            # Read from TCP connections -> send channel data
            foreach ($chanId in @($st.Channels.Keys)) {
                $ch = $st.Channels[$chanId]
                if ($ch.Stream -and $ch.Client.Connected) {
                    try {
                        if ($ch.Stream.DataAvailable) {
                            $didWork = $true
                            $tbuf = [byte[]]::new(32768)
                            $n = $ch.Stream.Read($tbuf, 0, $tbuf.Length)
                            if ($n -gt 0) {
                                $c2 = [byte[]]::new($n)
                                [System.Buffer]::BlockCopy($tbuf, 0, $c2, 0, $n)
                                _SendChannelData $st $chanId $c2
                            } else { _CloseChannel $st $chanId }
                        }
                    } catch { _CloseChannel $st $chanId }
                }
            }

            if (([DateTime]::UtcNow - $lastKeepalive).TotalSeconds -ge 60) {
                _SshSend $st ([byte[]]@($SSH_MSG_IGNORE, 0, 0, 0, 0))
                $lastKeepalive = [DateTime]::UtcNow
            }

            if (-not $didWork) { [System.Threading.Thread]::Sleep(1) }
        }
    } catch [System.InvalidOperationException] {
        # BlockingCollection completed — normal shutdown
    } catch {
        [Console]::Error.WriteLine("SSH error: $_")
        [Console]::Error.WriteLine("SSH stack: $($_.ScriptStackTrace)")
    } finally {
        foreach ($chanId in @($st.Channels.Keys)) { try { _CloseChannel $st $chanId } catch {} }
        try {
            $disc = [System.IO.MemoryStream]::new()
            $disc.WriteByte($SSH_MSG_DISCONNECT)
            _WriteU32 $disc 11
            _WriteStringUtf8 $disc 'Tunnel closed'
            _WriteStringUtf8 $disc ''
            _SshSend $st $disc.ToArray(); $disc.Dispose()
        } catch {}
        if ($st.EncOut) { try { $st.EncOut.Aes.Dispose(); $st.EncOut.Encryptor.Dispose() } catch {} }
        if ($st.EncIn)  { try { $st.EncIn.Aes.Dispose(); $st.EncIn.Encryptor.Dispose() } catch {} }
        if ($st.MacOut) { try { $st.MacOut.Dispose() } catch {} }
        if ($st.MacIn)  { try { $st.MacIn.Dispose() } catch {} }
        try { $ToSsm.CompleteAdding() } catch {}
        [Console]::Error.WriteLine('SSH session ended.')
    }
}
