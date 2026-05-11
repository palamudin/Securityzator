[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [switch]$SkipGraphSourceMapValidation,
    [switch]$SkipControlCatalogValidation
)

$ErrorActionPreference = "Stop"

$env:DOTNET_CLI_HOME = Join-Path $PSScriptRoot ".dotnet"
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
$env:DOTNET_ADD_GLOBAL_TOOLS_TO_PATH = "0"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"

if (-not $SkipGraphSourceMapValidation) {
    $validatorPath = Join-Path $PSScriptRoot "tools\Validate-GraphSourceMap.ps1"
    if (-not (Test-Path -LiteralPath $validatorPath)) {
        throw "Graph source-map validator '$validatorPath' was not found."
    }

    Write-Host "Validating Microsoft Graph source-map alignment..."
    & powershell -NoProfile -ExecutionPolicy Bypass -File $validatorPath

    if ($LASTEXITCODE -ne 0) {
        throw "Graph source-map validation failed."
    }
}

$projects = @(
    "src\\Securityzator.Domain\\Securityzator.Domain.csproj",
    "src\\Securityzator.Application\\Securityzator.Application.csproj",
    "src\\Securityzator.Infrastructure\\Securityzator.Infrastructure.csproj",
    "src\\Securityzator.Web\\Securityzator.Web.csproj",
    "src\\Securityzator.Worker\\Securityzator.Worker.csproj",
    "tools\\Securityzator.SmokeRunner\\Securityzator.SmokeRunner.csproj"
)

foreach ($project in $projects) {
    Write-Host "Building $project ($Configuration)..."

    $projectDirectory = Split-Path -Path (Join-Path $PSScriptRoot $project) -Parent
    $projectAssetsPath = Join-Path $projectDirectory "obj\project.assets.json"
    $buildArguments = @(
        "build",
        $project,
        "--configuration", $Configuration,
        "--nologo",
        "--verbosity", "minimal"
    )

    # Keep the shakedown tool build reliable in constrained environments by
    # reusing the already-restored assets when they are available locally.
    if ($project -like "tools\\Securityzator.SmokeRunner\\*" -and (Test-Path -LiteralPath $projectAssetsPath)) {
        $buildArguments += "--no-restore"
    }

    & dotnet @buildArguments

    if ($LASTEXITCODE -ne 0) {
        throw "Build failed for $project."
    }
}

if (-not $SkipControlCatalogValidation) {
    $controlValidatorPath = Join-Path $PSScriptRoot "tools\Validate-ControlCatalog.ps1"
    if (-not (Test-Path -LiteralPath $controlValidatorPath)) {
        throw "Control catalog validator '$controlValidatorPath' was not found."
    }

    if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
        throw "Control catalog validation requires PowerShell 7 (pwsh)."
    }

    Write-Host "Validating control catalog coverage..."
    & pwsh -NoProfile -ExecutionPolicy Bypass -File $controlValidatorPath -Configuration $Configuration

    if ($LASTEXITCODE -ne 0) {
        throw "Control catalog validation failed."
    }
}

Write-Host "Securityzator build completed successfully."
