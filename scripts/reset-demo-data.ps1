param([string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")))
$ErrorActionPreference = "Stop"
Push-Location (Join-Path $ProjectRoot "backend")
try {
    npm.cmd run demo:reset
    if ($LASTEXITCODE -ne 0) { throw "Demo reset failed" }
} finally { Pop-Location }
Write-Host "DEMO DATA RESET: PASS" -ForegroundColor Green
