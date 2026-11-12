[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$goModPath = Join-Path $projectRoot "go.mod"
$goDirective = Select-String -LiteralPath $goModPath -Pattern '^go\s+(\d+\.\d+\.\d+)\s*$' | Select-Object -First 1
if (-not $goDirective) {
    throw "Could not read an exact Go version from $goModPath"
}

$goVersion = $goDirective.Matches[0].Groups[1].Value
$wslc = Get-Command wslc.exe -ErrorAction SilentlyContinue
if (-not $wslc) {
    throw "wslc.exe was not found on PATH. Install WSLC before building go-hostdiscovery."
}
if (-not (Test-Path -LiteralPath "V:\Development" -PathType Container)) {
    throw "V:\Development is unavailable; build output requires the development volume."
}

$storageRoot = "V:\Development\go-hostdiscovery"
$outputDirectory = Join-Path $storageRoot "artifacts\bin"
$moduleCache = Join-Path $storageRoot "caches\go-modules"
$buildCache = Join-Path $storageRoot "caches\go-build-linux"
$scratch = Join-Path $storageRoot "tmp\build-wslc"
@($outputDirectory, $moduleCache, $buildCache, $scratch) | ForEach-Object {
    New-Item -ItemType Directory -Force -Path $_ | Out-Null
}

# Bind generated state to the development volume instead of source or anonymous
# container volumes. The source is read-only; dependency changes use go tooling.
$image = "golang:$goVersion-bookworm"
$arguments = @(
    "run", "--rm",
    "--volume", "${projectRoot}:/workspace:ro",
    "--volume", "${outputDirectory}:/output",
    "--volume", "${moduleCache}:/go/pkg/mod",
    "--volume", "${buildCache}:/go-build-cache",
    "--volume", "${scratch}:/tmp",
    "--workdir", "/workspace",
    "--env", "CGO_ENABLED=1",
    "--env", "GOTOOLCHAIN=local",
    "--env", "GOWORK=off",
    "--env", "GOCACHE=/go-build-cache",
    "--env", "GOMODCACHE=/go/pkg/mod",
    "--env", "GOTMPDIR=/tmp",
    "--env", "TMPDIR=/tmp",
    "--env", "TEMP=/tmp",
    "--env", "TMP=/tmp",
    $image,
    "go", "build",
    "-buildvcs=false",
    "-trimpath",
    "-ldflags=-w -s",
    "-o", "/output/hostdiscovery",
    "./cmd/hostdiscovery"
)

$previousTemp = @{}
try {
    foreach ($name in @("TEMP", "TMP", "TMPDIR")) {
        $previousTemp[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
        [Environment]::SetEnvironmentVariable($name, $scratch, "Process")
    }
    Write-Host "Building go-hostdiscovery with WSLC image $image"
    & $wslc.Source @arguments
    $buildExitCode = $LASTEXITCODE
}
finally {
    foreach ($name in $previousTemp.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousTemp[$name], "Process")
    }
}
if ($buildExitCode -ne 0) {
    exit $buildExitCode
}
Write-Host "Built $outputDirectory\hostdiscovery"
