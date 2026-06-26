param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")),
    [switch]$SkipDependencies,
    [switch]$SkipHardwareTokens,
    [switch]$ForcePki
)

$ErrorActionPreference = "Stop"
$backend = Join-Path $ProjectRoot "backend"
$envFile = Join-Path $backend ".env"
$envExample = Join-Path $backend ".env.example"

function New-RandomHex([int]$Bytes = 32) {
    $buffer = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($buffer)
    } finally {
        $rng.Dispose()
    }
    return -join ($buffer | ForEach-Object { $_.ToString("x2") })
}

function Set-EnvValue([string]$Name, [string]$Value) {
    $content = Get-Content $envFile -Raw
    $line = "$Name=$Value"
    $escaped = [regex]::Escape($Name)
    if ($content -match "(?m)^$escaped=.*$") {
        $content = [regex]::Replace($content, "(?m)^$escaped=.*$", $line)
    } else {
        $content = $content.TrimEnd() + "`r`n$line`r`n"
    }
    [System.IO.File]::WriteAllText($envFile, $content, [System.Text.UTF8Encoding]::new($false))
}

Write-Host "=== DIGITAL SIGNATURE CAPSTONE DEMO SETUP ===" -ForegroundColor Cyan
& (Join-Path $PSScriptRoot "check-environment.ps1") -ProjectRoot $ProjectRoot
if ($LASTEXITCODE -ne 0) { throw "Environment check failed" }

if (-not (Test-Path $envFile)) {
    Copy-Item $envExample $envFile
    Set-EnvValue "JWT_SECRET" (New-RandomHex 32)
    Set-EnvValue "TSP_SHARED_SECRET" (New-RandomHex 32)
    Set-EnvValue "CLIENT_AGENT_SHARED_SECRET" (New-RandomHex 32)
    Set-EnvValue "REMOTE_OTP_SECRET" (New-RandomHex 32)
    Write-Host "[PASS] Created backend/.env with random development secrets" -ForegroundColor Green
}

Push-Location $ProjectRoot
try {
    node ".\scripts\prepare-local-paths.js"
    if ($LASTEXITCODE -ne 0) { throw "Local path preparation failed" }

    if (-not $SkipDependencies) {
        npm.cmd --prefix ".\backend" ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
    }

    Push-Location $backend
    try {
        npm.cmd run storage:init
        if ($LASTEXITCODE -ne 0) { throw "JSON storage initialization failed" }
    } finally { Pop-Location }

    $rootKey = Join-Path $ProjectRoot "pki\root-ca\root-ca.key"
    $rootCert = Join-Path $ProjectRoot "pki\root-ca\root-ca.crt"
    if ($ForcePki -or -not ((Test-Path $rootKey) -and (Test-Path $rootCert))) {
        $args = @()
        if ($ForcePki) { $args += "-Force" }
        & (Join-Path $ProjectRoot "pki\scripts\initialize-root-ca.ps1") @args
        if ($LASTEXITCODE -ne 0) { throw "Root CA initialization failed" }
    }

    Push-Location $backend
    try {
        $trustArgs = @("run", "pki:init-trust-services")
        if ($ForcePki) { $trustArgs += @("--", "--force") }
        & npm.cmd @trustArgs
        if ($LASTEXITCODE -ne 0) { throw "Trust-service initialization failed" }

        npm.cmd run officer:ensure-demo
        if ($LASTEXITCODE -ne 0) { throw "Demo officer initialization failed" }
        npm.cmd run citizen:ensure-demo
        if ($LASTEXITCODE -ne 0) { throw "Demo citizen initialization failed" }
        npm.cmd run admin:ensure-demo
        if ($LASTEXITCODE -ne 0) { throw "Demo admin initialization failed" }

        node --input-type=module -e "import('./src/services/certificate.repository.js').then(m=>process.exit(m.findCertificatesByOfficerId('OFFICER-001').some(c=>c.status==='active' && String(c.key_provider||c.provider||'software').toLowerCase()!=='softhsm')?0:1))"
        if ($LASTEXITCODE -ne 0) {
            npm.cmd run pki:issue-officer -- --officer-id OFFICER-001
            if ($LASTEXITCODE -ne 0) { throw "Demo officer software certificate issuance failed" }
        }

        npm.cmd run citizen:issue-software
        if ($LASTEXITCODE -ne 0) { throw "Demo citizen software certificate issuance failed" }
        npm.cmd run pki:generate-crl
        if ($LASTEXITCODE -ne 0) { throw "CRL generation failed" }
    } finally { Pop-Location }

    $archiveDirectory = Join-Path $ProjectRoot "pki\archive"
    $archiveKey = Join-Path $archiveDirectory "archive-seal.key"
    $archiveCert = Join-Path $archiveDirectory "archive-seal.crt"
    if ($ForcePki -or -not ((Test-Path $archiveKey) -and (Test-Path $archiveCert))) {
        New-Item -ItemType Directory -Force -Path $archiveDirectory | Out-Null
        $archiveCsr = Join-Path $archiveDirectory "archive-seal.csr"
        $rootSerial = Join-Path $ProjectRoot "pki\root-ca\root-ca.srl"
        & openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out $archiveKey
        if ($LASTEXITCODE -ne 0) { throw "Archive seal key generation failed" }
        & openssl req -new -sha256 -key $archiveKey -out $archiveCsr -subj "/C=VN/O=HCMUTE/OU=Digital Signature Capstone/CN=Archive Seal"
        if ($LASTEXITCODE -ne 0) { throw "Archive seal CSR generation failed" }
        $serialArgs = if (Test-Path $rootSerial) { @("-CAserial", $rootSerial) } else { @("-CAcreateserial") }
        & openssl x509 -req -in $archiveCsr -CA $rootCert -CAkey $rootKey @serialArgs -out $archiveCert -days 825 -sha256 -extfile (Join-Path $ProjectRoot "pki\config\archive-seal-ext.cnf")
        if ($LASTEXITCODE -ne 0) { throw "Archive seal certificate issuance failed" }
        $chain = (Get-Content $archiveCert -Raw).Trim() + "`n" + (Get-Content $rootCert -Raw).Trim() + "`n"
        [System.IO.File]::WriteAllText((Join-Path $archiveDirectory "archive-chain.pem"), $chain, [System.Text.Encoding]::ASCII)
    }

    if (-not $SkipHardwareTokens) {
        $softHsm = Get-Command "softhsm2-util" -ErrorAction SilentlyContinue
        $pkcs11 = Get-Command "pkcs11-tool" -ErrorAction SilentlyContinue
        if ($softHsm -and $pkcs11) {
            & (Join-Path $PSScriptRoot "provision-officer-softhsm.ps1") -ProjectRoot $ProjectRoot -SkipE2E
            if ($LASTEXITCODE -ne 0) { throw "Officer SoftHSM provisioning failed" }
            & (Join-Path $PSScriptRoot "provision-citizen-pkcs11.ps1") -ProjectRoot $ProjectRoot
            if ($LASTEXITCODE -ne 0) { throw "Citizen PKCS#11 provisioning failed" }
        } else {
            Write-Host "[WARN] SoftHSM/OpenSC not found; hardware-token provisioning was skipped." -ForegroundColor Yellow
        }
    }

    Write-Host "`nDEMO SETUP: PASS" -ForegroundColor Green
    Write-Host "Run: npm.cmd start" -ForegroundColor Cyan
} finally {
    Pop-Location
}
