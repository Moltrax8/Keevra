<#
.SYNOPSIS
  Build and publish a Keevra release from this machine, without GitHub Actions.

.DESCRIPTION
  GitHub Actions minutes are not available, so this script reproduces what
  `.github/workflows/release.yml` does, on the maintainer's Windows machine:

    1. checks every version file and the CHANGELOG against -Version
    2. runs the same gates (npm ci/audit/test, cargo test/check --locked)
    3. builds the NSIS installer and the app executable
    4. collects installer + exe + SHA256SUMS.txt + CycloneDX SBOMs
    5. composes release notes from CHANGELOG.md
    6. tags, creates the GitHub release and uploads the assets
    7. signs updates.unsigned.json with the OFFLINE key (update-tool),
       uploads updates.json + updates.json.minisig
    8. re-downloads the published manifest through the app's own live test
       (`updates::tests::live_manifest_fetch_and_installer_download`)

  The private key is read only by tools/update-tool. This script never prints
  or copies its contents.

.PARAMETER Version
  Version to release, e.g. 0.2.5. Must already be in every version file and
  have a `## [0.2.5]` CHANGELOG section.

.PARAMETER SigningKey
  Path to the offline ed25519 key. Required when publishing.

.PARAMETER Publish
  Create the tag/release and upload assets. Without it, only local artefacts
  are produced under release-artifacts\.

.PARAMETER SkipTests
  Skip the test gates. Only use when the same commit was already verified.

.PARAMETER SkipBuild
  Reuse the existing src-tauri\target\release build.

.EXAMPLE
  powershell -File tools\release-local.ps1 -Version 0.2.5
  powershell -File tools\release-local.ps1 -Version 0.2.5 -SkipTests -SkipBuild `
    -Publish -SigningKey "$env:USERPROFILE\.keevra\updates-signing.key"
#>
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$SigningKey = "",
    [switch]$Publish,
    [switch]$SkipTests,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$utf8 = New-Object System.Text.UTF8Encoding($false)
$tag = "v$Version"
$artifacts = Join-Path $repo "release-artifacts"

function Step($name) {
    Write-Host ""
    Write-Host "=== $name ===" -ForegroundColor Cyan
}

function Invoke-Native {
    param([scriptblock]$Command, [string]$What)
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" }
}

function Write-Utf8 {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, $utf8)
}

# ---------------------------------------------------------------- version gate
Step "Version files"
$pkg = (Get-Content package.json -Raw | ConvertFrom-Json).version
$lock = [regex]::Match((Get-Content package-lock.json -Raw), '(?m)^\s{2}"version": "([^"]+)"').Groups[1].Value
$cargo = [regex]::Match((Get-Content src-tauri/Cargo.toml -Raw), '(?m)^version = "([^"]+)"').Groups[1].Value
$conf = (Get-Content src-tauri/tauri.conf.json -Raw | ConvertFrom-Json).version
$cargoLock = [regex]::Match(
    (Get-Content src-tauri/Cargo.lock -Raw),
    '(?m)^name = "keevra"\r?\nversion = "([^"]+)"').Groups[1].Value

foreach ($pair in @(
        @("package.json", $pkg),
        @("package-lock.json", $lock),
        @("src-tauri/Cargo.toml", $cargo),
        @("src-tauri/Cargo.lock", $cargoLock),
        @("src-tauri/tauri.conf.json", $conf))) {
    if ($pair[1] -ne $Version) {
        throw "$($pair[0]) says $($pair[1]), expected $Version"
    }
}
if ((Get-Content CHANGELOG.md -Raw) -notmatch "(?m)^## \[$([regex]::Escape($Version))\]") {
    throw "CHANGELOG.md has no '## [$Version]' section"
}
Write-Host "all version files and CHANGELOG say $Version"

# ---------------------------------------------------------------------- gates
if (-not $SkipTests) {
    Step "Gates (same commands as CI)"
    Invoke-Native { npm ci } "npm ci"
    Invoke-Native { npm audit --audit-level=high } "npm audit"
    Invoke-Native { npm test } "npm test"
    Invoke-Native { cargo test --manifest-path src-tauri/Cargo.toml --locked } "cargo test"
    Invoke-Native { cargo check --manifest-path src-tauri/Cargo.toml --locked } "cargo check"
}
else {
    Write-Host "tests skipped (-SkipTests); the commit must already be verified" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------- build
if (-not $SkipBuild) {
    Step "Build NSIS installer"
    Invoke-Native { npx tauri build --bundles nsis } "tauri build"
}
else {
    Write-Host "build skipped (-SkipBuild); reusing src-tauri\target\release" -ForegroundColor Yellow
}

# ------------------------------------------------------------------ artefacts
Step "Collect artifacts"
$installer = Get-ChildItem "src-tauri\target\release\bundle\nsis\*_${Version}_x64-setup.exe" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $installer) {
    $installer = Get-ChildItem "src-tauri\target\release\bundle\nsis\*-setup.exe" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}
if (-not $installer) { throw "NSIS installer not found; run without -SkipBuild" }
$exe = Get-Item "src-tauri\target\release\keevra.exe" -ErrorAction SilentlyContinue
if (-not $exe) { throw "keevra.exe not found; run without -SkipBuild" }

if (Test-Path $artifacts) { Remove-Item $artifacts -Recurse -Force }
New-Item -ItemType Directory -Force $artifacts | Out-Null
Copy-Item $installer.FullName $artifacts
Copy-Item $exe.FullName $artifacts

$installerHash = (Get-FileHash -Algorithm SHA256 $installer.FullName).Hash.ToLower()
$exeHash = (Get-FileHash -Algorithm SHA256 $exe.FullName).Hash.ToLower()
$sums = @(
    ("{0}  {1}" -f $installerHash, $installer.Name),
    ("{0}  {1}" -f $exeHash, "keevra.exe")
)
Write-Utf8 (Join-Path $artifacts "SHA256SUMS.txt") (($sums -join "`r`n") + "`r`n")

# Unsigned manifest input. Signed out-of-band with the offline key; never
# published as updates.json.
$manifest = [ordered]@{
    version = $Version
    assets  = @([ordered]@{ sha256 = $installerHash; name = $installer.Name })
} | ConvertTo-Json -Depth 5
Write-Utf8 (Join-Path $artifacts "updates.unsigned.json") ($manifest + "`r`n")

Step "SBOMs (CycloneDX)"
$npmSbom = & npm sbom --sbom-format=cyclonedx
if ($LASTEXITCODE -ne 0) { throw "npm sbom failed (exit $LASTEXITCODE)" }
Write-Utf8 (Join-Path $artifacts "keevra-npm-sbom.cdx.json") (($npmSbom -join "`n") + "`n")
if (-not (Get-Command cargo-cyclonedx -ErrorAction SilentlyContinue)) {
    Invoke-Native { cargo install cargo-cyclonedx --version 0.5.10 --locked } "cargo install cargo-cyclonedx"
}
Invoke-Native { cargo cyclonedx --manifest-path src-tauri/Cargo.toml --format json } "cargo cyclonedx"
$sbom = Get-ChildItem src-tauri -Filter "*.cdx.json" | Select-Object -First 1
if (-not $sbom) { throw "cargo cyclonedx produced no SBOM" }
Move-Item $sbom.FullName (Join-Path $artifacts "keevra-rust-sbom.cdx.json") -Force

# ------------------------------------------------------------------- notes
Step "Release notes from CHANGELOG"
$lines = Get-Content CHANGELOG.md
$trigger = $false
$bodyLines = foreach ($line in $lines) {
    if (-not $trigger -and $line -match "^## \[$([regex]::Escape($Version))\]") { $trigger = $true }
    elseif ($trigger -and $line -match '^## \[') { break }
    elseif ($trigger) { $line }
}
$header = "Built locally and published unsigned: Windows SmartScreen will warn that the publisher is unknown. " +
"Verify the installer against SHA256SUMS.txt or let the in-app updater check the signed manifest before running it.`r`n`r`n"
Write-Utf8 (Join-Path $repo "release-notes.md") ($header + ($bodyLines -join "`r`n"))

Write-Host ""
Write-Host "artifacts in ${artifacts}:"
Get-ChildItem $artifacts | ForEach-Object { "  {0,-34} {1,10:N0} bytes" -f $_.Name, $_.Length }

if (-not $Publish) {
    Write-Host ""
    Write-Host "Prepared only. Re-run with -Publish -SigningKey <offline key> to publish $tag." -ForegroundColor Yellow
    exit 0
}

# -------------------------------------------------------------------- publish
Step "Publish $tag"
if (-not $SigningKey -or -not (Test-Path $SigningKey)) {
    throw "-SigningKey must point at the offline updates signing key to publish"
}
if (git status --porcelain) {
    throw "working tree is dirty; commit before publishing so the tag matches the build"
}

if (-not (git tag --list $tag)) {
    Invoke-Native { git tag -a $tag -m "Keevra $Version" } "git tag"
}
Invoke-Native { git push origin $tag } "git push tag"

$releaseExists = $false
$previousEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
gh release view $tag --json tagName 2>$null | Out-Null
$releaseExists = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = $previousEap

$assetPaths = @(Get-ChildItem $artifacts | ForEach-Object { $_.FullName })
if ($releaseExists) {
    Invoke-Native { gh release upload $tag $assetPaths --clobber } "gh release upload"
}
else {
    Invoke-Native { gh release create $tag $assetPaths --title "Keevra $Version" --notes-file release-notes.md } "gh release create"
}

Step "Sign the manifest offline"
$unsigned = Join-Path $artifacts "updates.unsigned.json"
$signed = Join-Path $artifacts "updates.json"
Copy-Item $unsigned $signed -Force
Invoke-Native {
    cargo run --quiet --manifest-path tools/update-tool/Cargo.toml --bin update-tool -- `
        sign $signed --key $SigningKey
} "update-tool sign"
Invoke-Native {
    gh release upload $tag $signed (Join-Path $artifacts "updates.json.minisig") --clobber
} "gh release upload manifest"

Step "Verify the published manifest with the app's own code"
$env:KEEVRA_LIVE_TAG = $tag
$env:KEEVRA_LIVE_CURRENT = "0.2.0"
Invoke-Native {
    cargo test --manifest-path src-tauri/Cargo.toml --locked `
        updates::tests::live_manifest_fetch_and_installer_download -- --ignored --nocapture
} "live manifest check"
Remove-Item Env:\KEEVRA_LIVE_TAG, Env:\KEEVRA_LIVE_CURRENT -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "published https://github.com/Moltrax8/Keevra/releases/tag/$tag" -ForegroundColor Green
Write-Host "installer sha256: $installerHash"
