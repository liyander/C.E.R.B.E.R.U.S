# Register or remove a background startup task for the current Windows user.
param([ValidateSet("Install", "Remove")][string]$Action = "Install", [int]$Port = 8787)
$ErrorActionPreference = "Stop"
$name = "CERBERUS"
if ($Action -eq "Remove") {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false
    Write-Host "CERBERUS startup task removed."
    exit
}
$runner = Join-Path $PSScriptRoot "run-service.ps1"
$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "Run .\run.ps1 once to install dependencies first."
}
$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$runner`" -Port $Port" -WorkingDirectory $PSScriptRoot
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
Register-ScheduledTask -TaskName $name -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "CERBERUS will start in the background when $env:USERNAME signs in."
