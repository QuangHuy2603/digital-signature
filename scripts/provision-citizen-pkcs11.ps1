param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")),
    [string]$UserId = "2",
    [string]$SoftHsmUtil = "softhsm2-util",
    [string]$Pkcs11Tool = "pkcs11-tool",
    [string]$ModulePath = "",
    [string]$ProviderName = "pkcs11prov",
    [string]$ProviderDirectory = "",
    [string]$TokenLabel = "NT219-CITIZEN",
    [string]$SoPin = "87654321",
    [string]$UserPin = "654321",
    [switch]$Force
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
function Find-FirstExisting([string[]]$Candidates) {
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path $candidate)) { return (Resolve-Path $candidate).Path }
    }
    return $null
}
function Set-EnvValue([string]$Name, [string]$Value) {
    if (-not (Test-Path $envFile)) { Copy-Item (Join-Path $backend ".env.example") $envFile }
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

$softHsmExe = Resolve-Executable $SoftHsmUtil
if (-not $softHsmExe) { throw "softhsm2-util was not found. Install SoftHSM2 or pass -SoftHsmUtil." }
$pkcs11Exe = Resolve-Executable $Pkcs11Tool
if (-not $pkcs11Exe) {
    $pkcs11Exe = Find-FirstExisting @(
        "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe",
        "C:\Program Files (x86)\OpenSC Project\OpenSC\tools\pkcs11-tool.exe"
    )
}
if (-not $pkcs11Exe) { throw "pkcs11-tool was not found. Install OpenSC or pass -Pkcs11Tool." }
$opensslExe = Resolve-Executable "openssl"
if (-not $opensslExe) { throw "openssl was not found in PATH." }
if (-not (Resolve-Executable "node")) { throw "Node.js was not found in PATH." }

if (-not $ModulePath) {
    $ModulePath = Find-FirstExisting @(
        "C:\SoftHSM2\lib\softhsm2-x64.dll",
        "C:\SoftHSM2\lib\softhsm2.dll",
        "C:\Program Files\SoftHSM2\lib\softhsm2-x64.dll",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so"
    )
}
if (-not $ModulePath -or -not (Test-Path $ModulePath)) {
    throw "SoftHSM PKCS#11 module was not found. Pass -ModulePath '<softhsm2-x64.dll>'."
}
if (-not $ProviderDirectory) {
    $opensslDirectory = Split-Path -Parent $opensslExe
    $ProviderDirectory = Find-FirstExisting @(
        $env:OPENSSL_MODULES,
        (Join-Path $opensslDirectory "..\lib\ossl-modules"),
        "C:\msys64\ucrt64\lib\ossl-modules",
        "C:\Program Files\OpenSSL-Win64\lib\ossl-modules"
    )
}
if (-not $ProviderDirectory) { throw "OpenSSL PKCS#11 provider directory was not found. Pass -ProviderDirectory." }

$providerArgs = @("list", "-providers", "-verbose", "-provider-path", $ProviderDirectory, "-provider", $ProviderName)
& $opensslExe @providerArgs *> $null
if ($LASTEXITCODE -ne 0) { throw "OpenSSL cannot load provider '$ProviderName' from '$ProviderDirectory'." }

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

Set-EnvValue "SOFTHSM2_CONF" ($config -replace '\\','/')
Set-EnvValue "PKCS11_TOOL_BIN" ($pkcs11Exe -replace '\\','/')
Set-EnvValue "CLIENT_AGENT_SOFTHSM2_UTIL_BIN" ($softHsmExe -replace '\\','/')
Set-EnvValue "CLIENT_AGENT_PKCS11_TOOL_BIN" ($pkcs11Exe -replace '\\','/')
Set-EnvValue "CLIENT_AGENT_OPENSSL_BIN" ($opensslExe -replace '\\','/')
Set-EnvValue "CLIENT_AGENT_PKCS11_TOKEN_LABEL" $TokenLabel
Set-EnvValue "CLIENT_AGENT_PKCS11_SO_PIN" $SoPin
Set-EnvValue "CLIENT_AGENT_PKCS11_USER_PIN" $UserPin
Set-EnvValue "CLIENT_AGENT_PKCS11_PROVIDER_NAME" $ProviderName
Set-EnvValue "CLIENT_AGENT_PKCS11_PROVIDER_PATH" ($ProviderDirectory -replace '\\','/')
Set-EnvValue "CLIENT_AGENT_PKCS11_MODULE_PATH" ($ModulePath -replace '\\','/')
Set-EnvValue "CLIENT_AGENT_SOFTHSM2_CONF" ($config -replace '\\','/')

Write-Host "[1/4] Install dependencies and ensure demo citizen" -ForegroundColor Cyan
Push-Location $backend
try {
    if (-not (Test-Path "node_modules")) {
        npm.cmd ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
    }
    npm.cmd run citizen:ensure-demo
    if ($LASTEXITCODE -ne 0) { throw "Demo citizen setup failed" }
    npm.cmd run citizen:issue-software
    if ($LASTEXITCODE -ne 0) { throw "Citizen software certificate setup failed" }

    Write-Host "[2/4] Provision citizen non-exportable ECDSA key in PKCS#11 token" -ForegroundColor Cyan
    $provisionArgs = @("run", "citizen:provision-pkcs11", "--", "--user-id", $UserId)
    if ($Force) { $provisionArgs += "--force" }
    & npm.cmd @provisionArgs
    if ($LASTEXITCODE -ne 0) { throw "Citizen PKCS#11 provisioning failed" }

    Write-Host "[3/4] Run citizen PKCS#11 end-to-end test" -ForegroundColor Cyan
    npm.cmd run citizen:e2e:pkcs11
    if ($LASTEXITCODE -ne 0) { throw "Citizen PKCS#11 E2E failed" }

    Write-Host "[4/4] Run PKCS#11 binding attack test" -ForegroundColor Cyan
    npm.cmd run attack:citizen-pkcs11-binding
    if ($LASTEXITCODE -ne 0) { throw "Citizen PKCS#11 binding attack test failed" }
} finally {
    Pop-Location
}
Write-Host "`nCITIZEN PKCS#11 PROVISIONING: PASS" -ForegroundColor Green
