param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$PkiRoot = Split-Path -Parent $PSScriptRoot
$RootDir = Join-Path $PkiRoot "root-ca"
$ConfigDir = Join-Path $PkiRoot "config"
$RootKey = Join-Path $RootDir "root-ca.key"
$RootCert = Join-Path $RootDir "root-ca.crt"

if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    throw "Khong tim thay openssl trong PATH. Kiem tra bang: openssl version"
}

if ((Test-Path $RootKey) -and (Test-Path $RootCert) -and -not $Force) {
    Write-Host "NT219 Test Root CA da ton tai. Khong thay doi." -ForegroundColor Green
    Write-Host "Dung -Force chi khi muon tao CA moi. CA moi se lam chung thu cu mat tin cay." -ForegroundColor Yellow
    exit 0
}

if ($Force) {
    Write-Host "CANH BAO: Dang tao lai Root CA. Chung thu va ho so PKI cu se khong con tin cay." -ForegroundColor Yellow
}

New-Item -ItemType Directory -Path $RootDir -Force | Out-Null
Remove-Item (Join-Path $RootDir "root-ca.key") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $RootDir "root-ca.crt") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $RootDir "root-ca.srl") -Force -ErrorAction SilentlyContinue

& openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out $RootKey
if ($LASTEXITCODE -ne 0) { throw "Khong tao duoc Root CA private key" }

& openssl req -x509 -new -sha256 -days 3650 -key $RootKey -out $RootCert -config (Join-Path $ConfigDir "root-ca.cnf") -extensions v3_ca
if ($LASTEXITCODE -ne 0) { throw "Khong tao duoc Root CA certificate" }

Write-Host "NT219 Test Root CA initialization: PASS" -ForegroundColor Green
& openssl x509 -in $RootCert -noout -subject -issuer -dates -fingerprint -sha256
