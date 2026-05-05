$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$port = if ($env:CDS_PORT) { $env:CDS_PORT } else { "8765" }
Write-Host "Starting Clinical Data Studio on http://127.0.0.1:$port"
Write-Host "Phone/tablet URLs on this Wi-Fi:"
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown" } |
  ForEach-Object { Write-Host "  http://$($_.IPAddress):$port" }
python .\server.py
