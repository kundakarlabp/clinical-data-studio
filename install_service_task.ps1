$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$taskName = "ClinicalDataStudio"
$python = (Get-Command python).Source
$script = Join-Path $PSScriptRoot "server.py"
$action = New-ScheduledTaskAction -Execute $python -Argument "`"$script`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "Starts Clinical Data Studio at user logon." -Force
Write-Host "Installed scheduled task: $taskName"
Write-Host "Start now with: Start-ScheduledTask -TaskName $taskName"
