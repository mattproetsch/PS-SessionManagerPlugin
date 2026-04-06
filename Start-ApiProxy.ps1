#Requires -Version 5.1
<#
.SYNOPSIS
    OpenAI API-compatible HTTP reverse proxy. Injects an Authorization header
    and forwards requests to an upstream provider. Streams SSE responses.

.DESCRIPTION
    Listens on a local port, accepts HTTP requests, replaces the Authorization
    header with the configured Bearer token, and forwards to the upstream URL.
    Responses (including streaming text/event-stream) are forwarded back to the
    caller in real time.

    Can be run standalone or auto-launched by Start-ReverseTunnel.ps1.

.EXAMPLE
    .\Start-ApiProxy.ps1 -ListenPort 3000 -UpstreamUrl https://api.openai.com -ApiKey sk-...

.EXAMPLE
    .\Start-ApiProxy.ps1 -ListenPort 3000 -UpstreamUrl https://my-provider.example.com/v1 -ApiKey my-token
#>
param(
    [int]$ListenPort = 3000,
    [Parameter(Mandatory)][string]$UpstreamUrl,
    [Parameter(Mandatory)][string]$ApiKey,
    [string]$ListenPrefix = 'http://127.0.0.1'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Trim trailing slash from upstream so we can append $request.RawUrl cleanly
$UpstreamUrl = $UpstreamUrl.TrimEnd('/')

# ── Listener ────────────────────────────────────────────────────────────────

$listener = New-Object System.Net.HttpListener
$prefix = "$ListenPrefix`:$ListenPort/"
$listener.Prefixes.Add($prefix)

try {
    $listener.Start()
} catch {
    throw "Failed to start HTTP listener on $prefix — $_"
}

[Console]::Error.WriteLine("[proxy] Listening on $prefix")
[Console]::Error.WriteLine("[proxy] Upstream: $UpstreamUrl")
[Console]::Error.WriteLine("[proxy] Press Ctrl+C to stop.")

# Headers that must not be copied between HttpWebRequest restricted headers
$script:RestrictedHeaders = @(
    'Accept','Connection','Content-Length','Content-Type','Date','Expect',
    'Host','If-Modified-Since','Range','Referer','Transfer-Encoding','User-Agent'
)

# ── Request loop ────────────────────────────────────────────────────────────

try {
    while ($listener.IsListening) {
        # Blocks until a request arrives
        $ctx      = $listener.GetContext()
        $request  = $ctx.Request
        $response = $ctx.Response

        $method = $request.HttpMethod
        $path   = $request.RawUrl          # includes query string
        $upUri  = "$UpstreamUrl$path"

        [Console]::Error.WriteLine("[proxy] $method $path -> $upUri")

        try {
            # ── Build upstream request ──────────────────────────────────
            $upReq = [System.Net.HttpWebRequest]::Create($upUri)
            $upReq.Method = $method

            # Copy safe headers from client
            foreach ($hdr in $request.Headers.AllKeys) {
                $val = $request.Headers[$hdr]
                if ($hdr -eq 'Authorization') { continue }   # we override this
                if ($hdr -eq 'Host')          { continue }   # set by .NET
                if ($hdr -eq 'Content-Type')  { $upReq.ContentType = $val; continue }
                if ($hdr -eq 'Accept')        { $upReq.Accept = $val; continue }
                if ($hdr -eq 'User-Agent')    { $upReq.UserAgent = $val; continue }
                if ($hdr -eq 'Content-Length') { continue }  # set automatically
                if ($hdr -eq 'Transfer-Encoding') { continue }
                if ($hdr -eq 'Connection')    { continue }
                if ($hdr -eq 'Expect')        { continue }
                try { $upReq.Headers.Add($hdr, $val) } catch {}
            }

            # Inject authorization
            $upReq.Headers.Set('Authorization', "Bearer $ApiKey")

            # Copy request body (for POST/PUT/PATCH)
            if ($method -in @('POST','PUT','PATCH') -and $request.HasEntityBody) {
                $upReq.ContentType = if ($request.ContentType) { $request.ContentType } else { 'application/json' }
                $bodyMs = New-Object System.IO.MemoryStream
                $request.InputStream.CopyTo($bodyMs)
                $bodyBytes = $bodyMs.ToArray(); $bodyMs.Dispose()
                $upReq.ContentLength = $bodyBytes.Length
                $upStream = $upReq.GetRequestStream()
                $upStream.Write($bodyBytes, 0, $bodyBytes.Length)
                $upStream.Close()
            }

            # ── Send & stream response ──────────────────────────────────
            $upResp = $null
            try {
                $upResp = $upReq.GetResponse()
            } catch [System.Net.WebException] {
                # 4xx/5xx — forward the error response body + status
                $upResp = $_.Exception.Response
                if (-not $upResp) { throw }
            }

            $response.StatusCode = [int]$upResp.StatusCode

            # Copy response headers
            foreach ($hdr in $upResp.Headers.AllKeys) {
                if ($hdr -eq 'Transfer-Encoding') { continue }  # let HttpListener handle chunking
                if ($hdr -eq 'Content-Length')     { continue }  # recalculated
                if ($hdr -eq 'Connection')         { continue }
                try { $response.Headers.Set($hdr, $upResp.Headers[$hdr]) } catch {}
            }

            # Stream body to client
            $srcStream = $upResp.GetResponseStream()
            $dstStream = $response.OutputStream
            $buf = [byte[]]::new(8192)
            while (($n = $srcStream.Read($buf, 0, $buf.Length)) -gt 0) {
                $dstStream.Write($buf, 0, $n)
                $dstStream.Flush()
            }
            $srcStream.Close()
            $upResp.Close()

        } catch {
            [Console]::Error.WriteLine("[proxy] Error: $_")
            try {
                $response.StatusCode = 502
                $errBytes = [System.Text.Encoding]::UTF8.GetBytes(
                    "{`"error`":{`"message`":`"Proxy error: $($_.ToString() -replace '"','\"')`",`"type`":`"proxy_error`"}}")
                $response.ContentType = 'application/json'
                $response.OutputStream.Write($errBytes, 0, $errBytes.Length)
            } catch {}
        } finally {
            try { $response.Close() } catch {}
        }
    }
} finally {
    $listener.Stop()
    $listener.Close()
    [Console]::Error.WriteLine('[proxy] Stopped.')
}
