# Clones dflippojr/fhir-crd-router at the pinned commit into .deps\ and installs
# it into the local Maven repository so the workbench build can resolve it.
$ErrorActionPreference = 'Stop'

$repoUrl = if ($env:CRD_ROUTER_REPO_URL) { $env:CRD_ROUTER_REPO_URL } else { 'https://github.com/dflippojr/fhir-crd-router.git' }
$commit = '7f5fd56'

$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $root '.deps\fhir-crd-router'

function Invoke-Checked {
    param([string]$Exe, [string[]]$Arguments)
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE" }
}

if (-not (Test-Path (Join-Path $dest '.git'))) {
    New-Item -ItemType Directory -Force (Join-Path $root '.deps') | Out-Null
    Invoke-Checked git @('clone', '--quiet', $repoUrl, $dest)
}

Invoke-Checked git @('-C', $dest, 'fetch', '--quiet', 'origin')
Invoke-Checked git @('-C', $dest, 'checkout', '--quiet', '--detach', $commit)

Push-Location $dest
try {
    Invoke-Checked (Join-Path $dest 'mvnw.cmd') @('-q', 'install', '-DskipTests')
} finally {
    Pop-Location
}
Write-Host "Installed fhir-crd-router at $(git -C $dest rev-parse --short HEAD)"
