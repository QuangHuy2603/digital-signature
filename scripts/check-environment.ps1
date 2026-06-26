param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot ".."))
)

$ErrorActionPreference = "Stop"
$missing = @()

function Test-Tool([string]$Name, [string[]]$Arguments = @("--version"), [switch]$Optional) {
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $command) {
        if ($Optional) {
            Write-Host "[WARN] $Name was not found (optional for software-only flows)." -ForegroundColor Yellow
            return $false
        }
        Write-Host "[FAIL] $Name was not found." -ForegroundColor Red
        $script:missing += $Name
        return $false
    }
    Write-Host "[PASS] $Name -> $($command.Source)" -ForegroundColor Green
    try { & $command.Source @Arguments 2>$null | Select-Object -First 1 | ForEach-Object { Write-Host "       $_" } } catch {}
    return $true
}

Write-Host "=== DIGITAL SIGNATURE CAPSTONE ENVIRONMENT CHECK ===" -ForegroundColor Cyan
Test-Tool "node" @("--version") | Out-Null
Test-Tool "npm.cmd" @("--version") | Out-Null
Test-Tool "openssl" @("version") | Out-Null
Test-Tool "python" @("--version") | Out-Null
Test-Tool "softhsm2-util" @("--version") -Optional | Out-Null
Test-Tool "pkcs11-tool" @("--version") -Optional | Out-Null

$requiredPaths = @(
    "backend/package.json",
    "backend/.env.example",
    "pki/config/root-ca.cnf",
    "infrastructure/softhsm/softhsm2.conf.example"
)
foreach ($relative in $requiredPaths) {
    $full = Join-Path $ProjectRoot $relative
    if (Test-Path $full) { Write-Host "[PASS] $relative" -ForegroundColor Green }
    else { Write-Host "[FAIL] Missing $relative" -ForegroundColor Red; $missing += $relative }
}

if ($missing.Count -gt 0) {
    Write-Host "ENVIRONMENT CHECK: FAIL" -ForegroundColor Red
    exit 1
}
Write-Host "ENVIRONMENT CHECK: PASS" -ForegroundColor Green

$global:LASTEXITCODE = 0
