@echo off
setlocal EnableDelayedExpansion
:: SSM SSH ProxyCommand wrapper for Windows
:: Usage: ssm-proxy.cmd <instance-id> <port>
set INSTANCE=%1
set PORT=%2
if "%PORT%"=="" set PORT=22

:: session-manager-plugin.cmd must be on PATH (it captures the session JSON)
for /f "usebackq delims=" %%i in (`aws ssm start-session --target %INSTANCE% --document-name Custom-StartSSHSession --parameters portNumber^=["%PORT%"] 2^>nul`) do set CAPTURED=1

:: Read the captured session response
if exist "%TEMP%\ssm-session-response.json" (
    set /p RESPONSE=<"%TEMP%\ssm-session-response.json"
) else (
    echo ERROR: No session response captured. Ensure session-manager-plugin.cmd is on PATH. >&2
    exit /b 1
)

:: Launch PowerShell plugin in stdio mode
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0ssm-port-forward.ps1" "!RESPONSE!" "%AWS_DEFAULT_REGION%" "StartSession" "%AWS_PROFILE%" "{\"Target\":\"%INSTANCE%\"}" ""
