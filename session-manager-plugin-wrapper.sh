#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
pwsh "$DIR/ssm-port-forward.ps1" "$@"
