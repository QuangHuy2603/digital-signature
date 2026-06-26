param(
    [string]$OfficerId = "OFFICER-001"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$BackendDir = Join-Path $ProjectRoot "backend"

Push-Location $BackendDir
try {
    & node ".\scripts\show-officer-certificate.js" --officer-id $OfficerId
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to show officer certificate"
    }
} finally {
    Pop-Location
}
