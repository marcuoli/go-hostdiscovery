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

$outputDirectory = Join-Path $projectRoot "bin"
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

$image = "golang:$goVersion-bookworm"
$sourceMount = "${projectRoot}:/workspace"
$arguments = @(
    "run", "--rm",
    "--volume", $sourceMount,
    "--volume", "wslc-go-mod-cache:/go/pkg/mod",
    "--volume", "wslc-go-build-cache:/root/.cache/go-build",
    "--workdir", "/workspace",
    "--env", "CGO_ENABLED=1",
    "--env", "GOTOOLCHAIN=local",
    $image,
    "go", "build",
    "-buildvcs=false",
    "-trimpath",
    "-ldflags=-w -s",
    "-o", "/workspace/bin/hostdiscovery",
    "./cmd/hostdiscovery"
)

Write-Host "Building go-hostdiscovery with WSLC image $image"
& $wslc.Source @arguments
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Built $outputDirectory\hostdiscovery"
