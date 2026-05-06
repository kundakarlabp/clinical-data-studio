$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$port = if ($env:CDS_PORT) { $env:CDS_PORT } else { "8765" }

Write-Host "Clinical Data Studio remote access helper"
Write-Host "Easiest free path: run .\start_easy_remote.ps1 and share the HTTPS link it prints."
Write-Host "More private path: private VPN access to this study computer."
Write-Host ""
Write-Host "1. Start the app first:"
Write-Host "   .\start.ps1"
Write-Host ""
Write-Host "2. Same Wi-Fi URLs:"
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown" } |
  ForEach-Object { Write-Host "   http://$($_.IPAddress):$port" }

Write-Host ""
Write-Host "3. Private VPN overlay:"
if (Get-Command tailscale -ErrorAction SilentlyContinue) {
  try {
    $tailscaleIp = (tailscale ip -4 2>$null | Select-Object -First 1)
    if ($tailscaleIp) {
      Write-Host "   Tailscale detected. Approved tailnet devices can try:"
      Write-Host "   http://$tailscaleIp`:$port"
      Write-Host "   Keep Clinical Data Studio accounts separate for each user."
    }
    else {
      Write-Host "   Tailscale detected, but no IPv4 address was returned. Sign in to Tailscale first."
    }
  }
  catch {
    Write-Host "   Tailscale detected, but status could not be read. Sign in to Tailscale first."
  }
}
else {
  Write-Host "   Tailscale is not installed. Install and sign in on the study computer and approved devices."
  Write-Host "   After setup, rerun this helper to print the private VPN URL."
}

Write-Host ""
Write-Host "4. HTTPS tunnel option:"
if (Get-Command cloudflared -ErrorAction SilentlyContinue) {
  Write-Host "   cloudflared detected. Only run this with study approval and access controls:"
  Write-Host "   cloudflared tunnel --url http://127.0.0.1:$port"
}
else {
  Write-Host "   cloudflared is not installed. Use it only if your study approves public tunnel access."
  Write-Host "   Demo command after installation: cloudflared tunnel --url http://127.0.0.1:$port"
}

Write-Host ""
Write-Host "5. True free cloud VM:"
Write-Host "   See docs\FREE_REMOTE_ACCESS.md for Oracle Always Free VM steps."
Write-Host ""
Write-Host "Do not store the live database or PHI in GitHub or unsupervised Google Drive sync."
