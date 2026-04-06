@echo off
setlocal EnableDelayedExpansion
:: AWS CLI invokes this as: session-manager-plugin <response-json> <region> <operation> <profile> <params> <endpoint>
:: When used as SSH ProxyCommand, we capture the response for ssm-proxy.cmd to read.

:: Save response JSON for the proxy wrapper
echo %1 > "%TEMP%\ssm-session-response.json"

:: Launch the PowerShell plugin
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0ssm-port-forward.ps1" %*
