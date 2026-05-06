param(
  [int]$Port = $(if ($env:CDS_PORT) { [int]$env:CDS_PORT } else { 8765 }),
  [switch]$CheckOnly,
  [switch]$NoDownload
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$toolDir = Join-Path $PSScriptRoot "tools"
$localCloudflared = Join-Path $toolDir "cloudflared.exe"
$cloudflaredDownload = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"

function Get-CommandPath {
  param([string]$Name)
  $command = Get-Command $Name -ErrorAction SilentlyContinue
  if ($command) {
    return $command.Source
  }
  return $null
}

function Get-CloudflaredPath {
  $installed = Get-CommandPath "cloudflared"
  if ($installed) {
    return $installed
  }

  if (Test-Path -LiteralPath $localCloudflared) {
    return $localCloudflared
  }

  if ($NoDownload) {
    return $null
  }

  New-Item -ItemType Directory -Force -Path $toolDir | Out-Null
  Write-Host "Downloading cloudflared. This is the free tunnel tool used to create the remote link."
  Invoke-WebRequest -Uri $cloudflaredDownload -OutFile $localCloudflared
  return $localCloudflared
}

function Test-AppHealth {
  param([int]$AppPort)
  try {
    $response = curl.exe -s "http://127.0.0.1:$AppPort/api/health"
    return ($response -like '*"ok":true*')
  }
  catch {
    return $false
  }
}

function Wait-AppHealth {
  param([int]$AppPort)
  for ($i = 0; $i -lt 30; $i++) {
    if (Test-AppHealth -AppPort $AppPort) {
      return $true
    }
    Start-Sleep -Seconds 1
  }
  return $false
}

Write-Host "Clinical Data Studio easy remote link"
Write-Host ""
Write-Host "Best simple free setup:"
Write-Host "1. Keep this computer switched on."
Write-Host "2. Use strong app passwords and separate user accounts."
Write-Host "3. Share only the HTTPS trycloudflare.com link printed below."
Write-Host "4. Keep this PowerShell window open while users enter data."
Write-Host "5. For identifiable patient data, prefer Tailscale or Cloudflare Access controls."
Write-Host ""

$python = Get-CommandPath "python"
$cloudflared = Get-CloudflaredPath

if ($CheckOnly) {
  Write-Host "Check only:"
  Write-Host "  Python:      $(if ($python) { $python } else { 'not found' })"
  Write-Host "  cloudflared: $(if ($cloudflared) { $cloudflared } else { 'not found' })"
  Write-Host "  Port:        $Port"
  exit 0
}

if (-not $python) {
  throw "Python was not found in PATH. Install Python or run from the same environment used for this app."
}

if (-not $cloudflared) {
  throw "cloudflared was not found. Run without -NoDownload so this script can download it."
}

$startedServer = $false
$serverProcess = $null

if (Test-AppHealth -AppPort $Port) {
  Write-Host "Clinical Data Studio is already running at http://127.0.0.1:$Port"
}
else {
  Write-Host "Starting Clinical Data Studio locally on http://127.0.0.1:$Port"
  $env:CDS_PORT = [string]$Port
  $serverProcess = Start-Process -FilePath $python -ArgumentList ".\server.py" -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru
  $startedServer = $true

  if (-not (Wait-AppHealth -AppPort $Port)) {
    if ($serverProcess -and -not $serverProcess.HasExited) {
      Stop-Process -Id $serverProcess.Id -Force
    }
    throw "Clinical Data Studio did not become healthy on port $Port."
  }
}

Write-Host ""
Write-Host "Remote link is starting now."
Write-Host "When cloudflared prints an https://*.trycloudflare.com URL, share that URL with approved users."
Write-Host "Press Ctrl+C to stop remote access."
Write-Host ""

try {
  & $cloudflared tunnel --url "http://127.0.0.1:$Port"
}
finally {
  if ($startedServer -and $serverProcess -and -not $serverProcess.HasExited) {
    Stop-Process -Id $serverProcess.Id -Force
  }
}
