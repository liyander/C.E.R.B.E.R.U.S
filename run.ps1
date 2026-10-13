# Starts CERBERUS. First run creates a virtual environment and installs dependencies.
#   .\run.ps1                       -> http://127.0.0.1:8787 (this PC only)
#   .\run.ps1 -BindHost 0.0.0.0     -> reachable from the LAN (needed for Grafana webhooks from another host)
param(
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 8787
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$venvPython = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "Creating virtual environment..."
    python -m venv (Join-Path $root ".venv")
    & $venvPython -m pip install --quiet --upgrade pip
}
# Quick when nothing is missing; picks up libraries added by later versions.
& $venvPython -m pip install --quiet --disable-pip-version-check -r (Join-Path $root "backend\requirements.txt")

if ($BindHost -ne "127.0.0.1") {
    Write-Warning "Listening on $BindHost over plain HTTP. Keep this on a trusted network or put a TLS reverse proxy in front."
}
Write-Host "CERBERUS is starting on http://${BindHost}:$Port"
# --reload restarts the server by itself whenever the backend code changes, so updates never need a manual restart.
& $venvPython -m uvicorn app.main:app --app-dir (Join-Path $root "backend") --host $BindHost --port $Port `
    --reload --reload-dir (Join-Path $root "backend")
