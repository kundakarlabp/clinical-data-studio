$ErrorActionPreference = "Stop"

$defaultBaseUrl = "http://127.0.0.1:8765"
$baseUrl = if ($env:CDS_BASE_URL) { $env:CDS_BASE_URL } else { $defaultBaseUrl }
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$serverProcess = $null
$oldCdsEnv = $env:CDS_ENV
$oldCdsHost = $env:CDS_HOST
$oldCdsPort = $env:CDS_PORT

function Test-AppReady {
  param([string]$Url)

  try {
    $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 2
    return ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500)
  }
  catch {
    return $false
  }
}

if (-not $env:CDS_BASE_URL -and -not (Test-AppReady $baseUrl)) {
  $python = (Get-Command python -ErrorAction Stop).Source
  $env:CDS_ENV = "development"
  $env:CDS_HOST = "127.0.0.1"
  $env:CDS_PORT = "8765"
  $startArgs = @{
    FilePath = $python
    ArgumentList = "server.py"
    WorkingDirectory = $repoRoot
    PassThru = $true
  }
  if ($IsWindows) {
    $startArgs.WindowStyle = "Hidden"
  }
  $serverProcess = Start-Process @startArgs

  $ready = $false
  for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    if ($serverProcess.HasExited) {
      throw "Clinical Data Studio server exited before browser smoke could run."
    }
    if (Test-AppReady $baseUrl) {
      $ready = $true
      break
    }
  }
  if (-not $ready) {
    throw "Clinical Data Studio server did not become ready at $baseUrl."
  }
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) "cds-playwright-smoke"
New-Item -ItemType Directory -Force -Path $work | Out-Null

$script = @'
const { chromium, devices } = require("playwright");

const baseURL = process.env.CDS_BASE_URL || "http://127.0.0.1:8765";
const viewports = [
  { name: "desktop", options: { viewport: { width: 1366, height: 768 } } },
  { name: "mobile", options: { ...devices["Pixel 7"] } },
];

(async () => {
  for (const target of viewports) {
    const browser = await chromium.launch();
    const context = await browser.newContext(target.options);
    const page = await context.newPage();
    await page.goto(baseURL, { waitUntil: "networkidle" });
    const title = await page.title();
    if (!title || !title.includes("Clinical Data Studio")) {
      throw new Error(`${target.name} did not render the app shell`);
    }
    const hasViewport = await page.locator("meta[name='viewport']").count();
    if (!hasViewport) {
      throw new Error(`${target.name} missing viewport metadata`);
    }
    await browser.close();
  }
  console.log("Browser smoke passed for desktop and mobile viewports.");
})();
'@

$scriptPath = Join-Path $work "browser_smoke.cjs"
Set-Content -LiteralPath $scriptPath -Value $script -Encoding UTF8
Push-Location $work
try {
  if (-not (Test-Path ".\package.json")) {
    npm init -y | Out-Null
  }
  npm install playwright --no-save | Out-Null
  npx playwright install chromium | Out-Null
  $env:CDS_BASE_URL = $baseUrl
  node $scriptPath
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }
}
finally {
  Pop-Location
  if ($serverProcess -and -not $serverProcess.HasExited) {
    Stop-Process -Id $serverProcess.Id -Force
  }
  $env:CDS_ENV = $oldCdsEnv
  $env:CDS_HOST = $oldCdsHost
  $env:CDS_PORT = $oldCdsPort
}
