$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$dataPath = Join-Path $PSScriptRoot "data"
New-Item -ItemType Directory -Force -Path $dataPath | Out-Null

Write-Host "Enabling Windows EFS encryption for: $dataPath"
Write-Host "This protects files at rest for the current Windows account. Keep Windows account recovery keys safe."
cipher.exe /e /s:$dataPath

Write-Host ""
Write-Host "Protection status:"
cipher.exe /c $dataPath
