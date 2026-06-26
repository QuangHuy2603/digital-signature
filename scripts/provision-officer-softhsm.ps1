param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")),
    [string]$OfficerId = "OFFICER-001",
    [string]$SoftHsmUtil = "softhsm2-util",
    [string]$Pkcs11Tool = "pkcs11-tool",
    [string]$ModulePath = "",
    [ValidateSet("provider", "engine")]
    [string]$OpenSslMode = "provider",
    [string]$ProviderName = "",
    [string]$ProviderDirectory = "",
    [string]$EngineId = "pkcs11",
    [string]$TokenLabel = "NT219-TSP",
    [string]$SoPin = "12345678",
    [string]$UserPin = "123456",
    [switch]$SkipE2E
)

$ErrorActionPreference = "Stop"
$backend = Join-Path $ProjectRoot "backend"
$envFile = Join-Path $backend ".env"
$configTemplate = Join-Path $ProjectRoot "infrastructure\softhsm\softhsm2.conf.example"
$config = Join-Path $ProjectRoot "infrastructure\softhsm\softhsm2.conf"
$tokens = Join-Path $ProjectRoot "infrastructure\softhsm\tokens"

function Resolve-Executable([string]$Name) {
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    if (Test-Path $Name) { return (Resolve-Path $Name).Path }
    return $null
}

function Set-EnvValue([string]$Name, [string]$Value) {
    if (-not (Test-Path $envFile)) {
        Copy-Item (Join-Path $backend ".env.example") $envFile
    }
    $content = Get-Content $envFile -Raw
    $escaped = [regex]::Escape($Name)
    $line = "$Name=$Value"
    if ($content -match "(?m)^$escaped=.*$") {
        $content = [regex]::Replace($content, "(?m)^$escaped=.*$", $line)
    } else {
        $content = $content.TrimEnd() + "`r`n$line`r`n"
    }
    [System.IO.File]::WriteAllText($envFile, $content, [System.Text.UTF8Encoding]::new($false))
}

function Find-FirstExisting([string[]]$Candidates) {
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path $candidate)) { return (Resolve-Path $candidate).Path }
    }
    return $null
}

$softHsmExe = Resolve-Executable $SoftHsmUtil
if (-not $softHsmExe) {
    throw "Không tìm thấy softhsm2-util. Hãy cài SoftHSM2 và thêm thư mục bin vào PATH."
}
$pkcs11Exe = Resolve-Executable $Pkcs11Tool
if (-not $pkcs11Exe) {
    $pkcs11Exe = Find-FirstExisting @(
        "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe",
        "C:\Program Files (x86)\OpenSC Project\OpenSC\tools\pkcs11-tool.exe"
    )
}
if (-not $pkcs11Exe) {
    throw "Không tìm thấy pkcs11-tool. Hãy cài OpenSC và thêm thư mục tools vào PATH."
}
$opensslExe = Resolve-Executable "openssl"
if (-not $opensslExe) { throw "Không tìm thấy openssl trong PATH." }
$nodeExe = Resolve-Executable "node"
if (-not $nodeExe) { throw "Không tìm thấy Node.js trong PATH." }

if (-not $ModulePath) {
    $ModulePath = Find-FirstExisting @(
        "C:\SoftHSM2\lib\softhsm2-x64.dll",
        "C:\SoftHSM2\lib\softhsm2.dll",
        "C:\Program Files\SoftHSM2\lib\softhsm2-x64.dll",
        "C:\Program Files\SoftHSM2\lib\softhsm2.dll",
        "C:\Program Files\SoftHSM2\lib\softhsm\libsofthsm2.dll",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so"
    )
}
if (-not $ModulePath -or -not (Test-Path $ModulePath)) {
    throw "Không tìm thấy thư viện PKCS#11 của SoftHSM. Chạy lại với -ModulePath '<đường-dẫn-softhsm2-x64.dll>'."
}

New-Item -ItemType Directory -Force -Path $tokens | Out-Null
$templateText = Get-Content $configTemplate -Raw
$tokenPath = ($tokens -replace '\\','/')
$configText = $templateText.Replace("./infrastructure/softhsm/tokens", $tokenPath)
[System.IO.File]::WriteAllText($config, $configText, [System.Text.UTF8Encoding]::new($false))

$env:SOFTHSM2_CONF = $config
$env:PKCS11_MODULE_PATH = $ModulePath
$env:PKCS11_PROVIDER_MODULE = $ModulePath
$env:PKCS11_PIN = $UserPin
$env:PKCS11_PROVIDER_PIN = $UserPin

if ($OpenSslMode -eq "provider") {
    $providerCandidates = if ($ProviderName) { @($ProviderName) } else { @("pkcs11prov", "pkcs11") }
    $selectedProvider = $null
    foreach ($candidate in $providerCandidates) {
        $providerArgs = @("list", "-providers", "-verbose")
        if ($ProviderDirectory) { $providerArgs += @("-provider-path", $ProviderDirectory) }
        $providerArgs += @("-provider", $candidate)
        & $opensslExe @providerArgs *> $null
        if ($LASTEXITCODE -eq 0) {
            $selectedProvider = $candidate
            break
        }
    }
    if (-not $selectedProvider) {
        throw @"
OpenSSL chưa tải được PKCS#11 provider.
Cần cài một provider tương thích OpenSSL 3+, ví dụ libp11 pkcs11prov hoặc openssl-projects pkcs11-provider.
Sau đó chạy lại với:
  -ProviderName pkcs11prov
  -ProviderDirectory '<thư-mục-chứa-provider-DLL>'
Hoặc dùng legacy engine nếu máy đã có engine_pkcs11:
  -OpenSslMode engine -EngineId pkcs11
"@
    }
    $ProviderName = $selectedProvider
} else {
    & $opensslExe engine -t $EngineId *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL engine '$EngineId' chưa sẵn sàng. Cài libp11/engine_pkcs11 hoặc chuyển sang provider mode."
    }
}

Set-EnvValue "SIGNING_PROVIDER_FAIL_CLOSED" "true"
Set-EnvValue "SOFTHSM2_UTIL_BIN" ($softHsmExe -replace '\\','/')
Set-EnvValue "PKCS11_TOOL_BIN" ($pkcs11Exe -replace '\\','/')
Set-EnvValue "SOFTHSM_TOKEN_LABEL" $TokenLabel
Set-EnvValue "SOFTHSM_SO_PIN" $SoPin
Set-EnvValue "SOFTHSM_USER_PIN" $UserPin
Set-EnvValue "SOFTHSM_OPENSSL_MODE" $OpenSslMode
Set-EnvValue "SOFTHSM_OPENSSL_PROVIDER_NAME" $ProviderName
Set-EnvValue "SOFTHSM_PKCS11_PROVIDER_PATH" ($ProviderDirectory -replace '\\','/')
Set-EnvValue "SOFTHSM_ENGINE_ID" $EngineId
Set-EnvValue "SOFTHSM_PKCS11_MODULE_PATH" ($ModulePath -replace '\\','/')
Set-EnvValue "SOFTHSM2_CONF" ($config -replace '\\','/')
Set-EnvValue "SOFTHSM_PIN_MODE" "environment"
Set-EnvValue "SOFTHSM_RUNTIME_PROBE" "true"
Set-EnvValue "SOFTHSM_PKCS11_URI_TEMPLATE" "pkcs11:token={token};object={label};id={id};type=private"

Write-Host "[1/3] Cấu hình SoftHSM đã được ghi vào backend/.env" -ForegroundColor Cyan
Push-Location $backend
try {
    if (-not (Test-Path (Join-Path $backend "node_modules"))) {
        npm.cmd ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
    }
    Write-Host "[2/3] Tạo khóa ECDSA P-256 bên trong SoftHSM và cấp chứng thư remote" -ForegroundColor Cyan
    npm.cmd run softhsm:provision -- --officer-id $OfficerId
    if ($LASTEXITCODE -ne 0) { throw "SoftHSM provisioning failed" }

    if (-not $SkipE2E) {
        Write-Host "[3/3] Chạy kiểm thử Portal API -> TSP -> SoftHSM -> PAdES-B-T" -ForegroundColor Cyan
        npm.cmd run softhsm:e2e -- --officer-id $OfficerId
        if ($LASTEXITCODE -ne 0) { throw "SoftHSM end-to-end test failed" }
    } else {
        Write-Host "[3/3] Bỏ qua E2E theo tùy chọn -SkipE2E" -ForegroundColor Yellow
    }
} finally {
    Pop-Location
}

Write-Host "`nOFFICER SOFTHSM PROVISIONING: PASS" -ForegroundColor Green
Write-Host "Remote signing dùng SoftHSM; local Client Agent vẫn giữ chứng thư phần mềm riêng." -ForegroundColor Green
