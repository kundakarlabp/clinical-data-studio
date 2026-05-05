$ErrorActionPreference = "Stop"

$baseUrl = if ($env:CDS_BASE_URL) { $env:CDS_BASE_URL } else { "http://127.0.0.1:8765" }
$work = Join-Path $env:TEMP "cds-playwright-smoke"
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
}
