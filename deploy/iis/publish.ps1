[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [string]$OutputRoot = "..\..\artifacts\publish\iis",

    [string]$RuntimeIdentifier = "",

    [switch]$SelfContained
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$outputRootPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot $OutputRoot))
$webOutputPath = Join-Path $outputRootPath "web"
$workerOutputPath = Join-Path $outputRootPath "worker"

New-Item -ItemType Directory -Path $webOutputPath -Force | Out-Null
New-Item -ItemType Directory -Path $workerOutputPath -Force | Out-Null

function Invoke-SecurityzatorPublish {
    param(
        [string]$ProjectPath,
        [string]$OutputPath
    )

    $selfContainedValue = if ($SelfContained.IsPresent) { "true" } else { "false" }

    $arguments = @(
        "publish",
        $ProjectPath,
        "--configuration", $Configuration,
        "--output", $OutputPath,
        "--nologo",
        "--verbosity", "minimal",
        "--self-contained", $selfContainedValue
    )

    if (-not [string]::IsNullOrWhiteSpace($RuntimeIdentifier)) {
        $arguments += @("--runtime", $RuntimeIdentifier)
    }

    & dotnet @arguments

    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed for '$ProjectPath'."
    }
}

$webProject = Join-Path $repoRoot "src\Securityzator.Web\Securityzator.Web.csproj"
$workerProject = Join-Path $repoRoot "src\Securityzator.Worker\Securityzator.Worker.csproj"

Write-Host "Publishing web project to '$webOutputPath'..."
Invoke-SecurityzatorPublish -ProjectPath $webProject -OutputPath $webOutputPath

Write-Host "Publishing worker project to '$workerOutputPath'..."
Invoke-SecurityzatorPublish -ProjectPath $workerProject -OutputPath $workerOutputPath

$manifest = @{
    generatedUtc = [DateTimeOffset]::UtcNow.ToString("O")
    configuration = $Configuration
    runtimeIdentifier = $RuntimeIdentifier
    selfContained = $SelfContained.IsPresent
    sdkVersion = (& dotnet --version)
    output = @{
        web = $webOutputPath
        worker = $workerOutputPath
    }
}

$manifestPath = Join-Path $outputRootPath "deployment-manifest.json"
$manifest | ConvertTo-Json -Depth 8 | Set-Content -Path $manifestPath -Encoding utf8

Write-Host "Securityzator publish completed."
Write-Host "Manifest: $manifestPath"
