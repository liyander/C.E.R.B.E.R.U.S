# Production runner for the CERBERUS startup task. No auto-reload.
param([string]$BindHost = "127.0.0.1", [int]$Port = 8787)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "Run .\run.ps1 once to install dependencies before enabling the startup task."
}
& $python -m uvicorn app.main:app --app-dir (Join-Path $root "backend") --host $BindHost --port $Port
