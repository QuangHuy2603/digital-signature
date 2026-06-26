param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")),
    [switch]$SkipHardware
)

$ErrorActionPreference = "Stop"
$backend = Join-Path $ProjectRoot "backend"
Write-Host "=== DIGITAL SIGNATURE CAPSTONE SYSTEM VERIFICATION ===" -ForegroundColor Cyan

& (Join-Path $PSScriptRoot "check-environment.ps1") -ProjectRoot $ProjectRoot
if ($LASTEXITCODE -ne 0) { throw "Environment check failed" }

Push-Location $ProjectRoot
try {
    node ".\scripts\prepare-local-paths.js"
    if ($LASTEXITCODE -ne 0) { throw "Path preparation failed" }
    Push-Location $backend
    try {
        npm.cmd run test:run
        if ($LASTEXITCODE -ne 0) { throw "Automated test suite failed" }
        npm.cmd run attack:all
        if ($LASTEXITCODE -ne 0) { throw "Attack scenarios failed" }
        npm.cmd run e2e:local
        if ($LASTEXITCODE -ne 0) { throw "Local end-to-end checks failed" }
        if (-not $SkipHardware) {
            npm.cmd run e2e:hardware
            if ($LASTEXITCODE -ne 0) { throw "PKCS#11/SoftHSM end-to-end checks failed" }
        }
    } finally { Pop-Location }
} finally { Pop-Location }

Write-Host "SYSTEM VERIFICATION: PASS" -ForegroundColor Green
