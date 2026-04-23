[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [string]$ManifestPath,
    [string]$DomainAssemblyPath,
    [string]$ApplicationAssemblyPath,
    [string]$InfrastructureAssemblyPath,
    [switch]$PassThru
)

$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSEdition -ne "Core") {
    $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($null -eq $pwsh) {
        throw "Validate-ControlCatalog.ps1 requires PowerShell 7 (pwsh) to load the .NET 10 assemblies."
    }

    $forwardArgs = @(
        "-NoProfile"
        "-ExecutionPolicy"
        "Bypass"
        "-File"
        $PSCommandPath
        "-Configuration"
        $Configuration
    )

    if (-not [string]::IsNullOrWhiteSpace($ManifestPath)) {
        $forwardArgs += @("-ManifestPath", $ManifestPath)
    }

    if (-not [string]::IsNullOrWhiteSpace($DomainAssemblyPath)) {
        $forwardArgs += @("-DomainAssemblyPath", $DomainAssemblyPath)
    }

    if (-not [string]::IsNullOrWhiteSpace($ApplicationAssemblyPath)) {
        $forwardArgs += @("-ApplicationAssemblyPath", $ApplicationAssemblyPath)
    }

    if (-not [string]::IsNullOrWhiteSpace($InfrastructureAssemblyPath)) {
        $forwardArgs += @("-InfrastructureAssemblyPath", $InfrastructureAssemblyPath)
    }

    if ($PassThru) {
        $forwardArgs += "-PassThru"
    }

    & $pwsh.Source @forwardArgs
    exit $LASTEXITCODE
}

$scriptRoot = if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    Split-Path -Parent $MyInvocation.MyCommand.Path
}
else {
    $PSScriptRoot
}

if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $scriptRoot "..\control-catalog.map.psd1"
}

if ([string]::IsNullOrWhiteSpace($DomainAssemblyPath)) {
    $DomainAssemblyPath = Join-Path $scriptRoot "..\src\Securityzator.Domain\bin\$Configuration\net10.0\Securityzator.Domain.dll"
}

if ([string]::IsNullOrWhiteSpace($ApplicationAssemblyPath)) {
    $ApplicationAssemblyPath = Join-Path $scriptRoot "..\src\Securityzator.Application\bin\$Configuration\net10.0\Securityzator.Application.dll"
}

if ([string]::IsNullOrWhiteSpace($InfrastructureAssemblyPath)) {
    $InfrastructureAssemblyPath = Join-Path $scriptRoot "..\src\Securityzator.Infrastructure\bin\$Configuration\net10.0\Securityzator.Infrastructure.dll"
}

$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [string]$Area,
        [string]$Check,
        [bool]$Passed,
        [string]$Details
    )

    $results.Add([pscustomobject]@{
            Area    = $Area
            Check   = $Check
            Passed  = $Passed
            Details = $Details
        })
}

function Import-DataFileOrNull {
    param(
        [string]$Path,
        [string]$Area
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Add-Result -Area $Area -Check "File exists" -Passed $false -Details "Missing file: $Path"
        return $null
    }

    try {
        $data = Import-PowerShellDataFile -Path $Path
        Add-Result -Area $Area -Check "File imports" -Passed $true -Details $Path
        return $data
    }
    catch {
        Add-Result -Area $Area -Check "File imports" -Passed $false -Details $_.Exception.Message
        return $null
    }
}

function Load-AssemblyOrNull {
    param(
        [string]$Path,
        [string]$Area
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Add-Result -Area $Area -Check "Assembly exists" -Passed $false -Details "Missing assembly: $Path"
        return $null
    }

    try {
        $resolved = (Resolve-Path -LiteralPath $Path).Path
        $assembly = [System.Reflection.Assembly]::LoadFrom($resolved)
        Add-Result -Area $Area -Check "Assembly loads" -Passed $true -Details $resolved
        return $assembly
    }
    catch {
        Add-Result -Area $Area -Check "Assembly loads" -Passed $false -Details $_.Exception.Message
        return $null
    }
}

function Compare-Set {
    param(
        [string]$Area,
        [string]$Check,
        [string[]]$Expected,
        [string[]]$Actual
    )

    $expectedSet = @($Expected | Sort-Object -Unique)
    $actualSet = @($Actual | Sort-Object -Unique)
    $missing = @($expectedSet | Where-Object { $_ -notin $actualSet })
    $extra = @($actualSet | Where-Object { $_ -notin $expectedSet })

    if ($missing.Count -eq 0 -and $extra.Count -eq 0) {
        Add-Result -Area $Area -Check $Check -Passed $true -Details "Aligned"
        return
    }

    $detailParts = @()
    if ($missing.Count -gt 0) {
        $detailParts += "Missing: $($missing -join ', ')"
    }

    if ($extra.Count -gt 0) {
        $detailParts += "Extra: $($extra -join ', ')"
    }

    Add-Result -Area $Area -Check $Check -Passed $false -Details ($detailParts -join ' | ')
}

function Normalize-RecommendationRecord {
    param([object]$Item)

    return "{0}|{1}|{2}|{3}|{4}|{5}|{6}" -f
        [string]$Item.Rank,
        [string]$Item.Title,
        [string]$Item.Category,
        [string]$Item.Product,
        [string]$Item.Status,
        [string]$Item.Impact,
        [string]$Item.RemediationTemplateKey
}

$manifest = Import-DataFileOrNull -Path $ManifestPath -Area "ControlCatalogManifest"

$null = Load-AssemblyOrNull -Path $DomainAssemblyPath -Area "DomainAssembly"
$null = Load-AssemblyOrNull -Path $ApplicationAssemblyPath -Area "ApplicationAssembly"
$infrastructureAssembly = Load-AssemblyOrNull -Path $InfrastructureAssemblyPath -Area "InfrastructureAssembly"

if ($null -ne $manifest -and $null -ne $infrastructureAssembly) {
    $catalogType = $infrastructureAssembly.GetType('Securityzator.Infrastructure.Blueprints.BusinessPremiumBlueprintCatalog', $true)
    $bindingFlags = [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic
    $recommendationMethod = $catalogType.GetMethod('GetRecommendationCatalog', $bindingFlags)
    $templateMethod = $catalogType.GetMethod('GetRemediationTemplates', $bindingFlags)

    Add-Result -Area "CatalogReflection" -Check "Recommendation method exists" -Passed ($null -ne $recommendationMethod) -Details "GetRecommendationCatalog"
    Add-Result -Area "CatalogReflection" -Check "Template method exists" -Passed ($null -ne $templateMethod) -Details "GetRemediationTemplates"

    if ($null -ne $recommendationMethod -and $null -ne $templateMethod) {
        $actualRecommendations = @($recommendationMethod.Invoke($null, @()))
        $actualTemplates = @($templateMethod.Invoke($null, @()))
        $expectedRecommendations = @($manifest.BusinessPremium.RecommendationCatalog)
        $surfacedTemplateKeys = @($expectedRecommendations | ForEach-Object { [string]$_.RemediationTemplateKey })
        $extendedTemplateKeys = @($manifest.BusinessPremium.ExtendedTemplateKeys | ForEach-Object { [string]$_ })
        $expectedTemplateKeys = @($surfacedTemplateKeys + $extendedTemplateKeys | Sort-Object -Unique)
        $actualTemplateKeys = @($actualTemplates | ForEach-Object { [string]$_.Key } | Sort-Object -Unique)
        $queueExecutableExpected = @($manifest.BusinessPremium.QueueExecutableTemplateKeys | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        $queueExecutableActual = @($actualTemplates | Where-Object { $_.SupportsQueueExecution } | ForEach-Object { [string]$_.Key } | Sort-Object -Unique)

        Add-Result -Area "RecommendationCatalog" -Check "Recommendation count" -Passed ($actualRecommendations.Count -eq $expectedRecommendations.Count) -Details "Expected $($expectedRecommendations.Count), actual $($actualRecommendations.Count)"
        Add-Result -Area "TemplateCatalog" -Check "Template count" -Passed ($actualTemplateKeys.Count -eq $expectedTemplateKeys.Count) -Details "Expected $($expectedTemplateKeys.Count), actual $($actualTemplateKeys.Count)"
        Add-Result -Area "RecommendationCatalog" -Check "Unique ranks" -Passed (($actualRecommendations | Select-Object -ExpandProperty Rank | Sort-Object -Unique).Count -eq $actualRecommendations.Count) -Details "Ranks should stay unique."
        Add-Result -Area "RecommendationCatalog" -Check "Unique recommendation keys" -Passed (($surfacedTemplateKeys | Sort-Object -Unique).Count -eq $surfacedTemplateKeys.Count) -Details "Manifest surfaced keys should stay unique."

        Compare-Set `
            -Area "RecommendationCatalog" `
            -Check "Recommendation entries" `
            -Expected (@($expectedRecommendations | ForEach-Object { Normalize-RecommendationRecord $_ })) `
            -Actual (@($actualRecommendations | ForEach-Object { Normalize-RecommendationRecord $_ }))

        Compare-Set `
            -Area "TemplateCatalog" `
            -Check "Template keys" `
            -Expected $expectedTemplateKeys `
            -Actual $actualTemplateKeys

        Compare-Set `
            -Area "TemplateCatalog" `
            -Check "Queue-executable template keys" `
            -Expected $queueExecutableExpected `
            -Actual $queueExecutableActual

        $missingTemplatesForRecommendations = @($surfacedTemplateKeys | Where-Object { $_ -notin $actualTemplateKeys })
        $templateCoverageDetails = if ($missingTemplatesForRecommendations.Count -eq 0) { "Aligned" } else { "Missing: $($missingTemplatesForRecommendations -join ', ')" }
        Add-Result `
            -Area "TemplateCatalog" `
            -Check "Every surfaced recommendation has a template" `
            -Passed ($missingTemplatesForRecommendations.Count -eq 0) `
            -Details $templateCoverageDetails
    }
}

$failed = @($results | Where-Object { -not $_.Passed })
$passed = @($results | Where-Object { $_.Passed })

Write-Host ""
Write-Host "Control catalog validation" -ForegroundColor Cyan
foreach ($result in $results) {
    $status = if ($result.Passed) { "PASS" } else { "FAIL" }
    $color = if ($result.Passed) { "Green" } else { "Red" }
    Write-Host ("[{0}] {1} :: {2}" -f $status, $result.Area, $result.Check) -ForegroundColor $color
    Write-Host ("       {0}" -f $result.Details)
}

Write-Host ""
$summaryColor = if ($failed.Count -eq 0) { "Green" } else { "Yellow" }
Write-Host ("Summary: {0} passed, {1} failed." -f $passed.Count, $failed.Count) -ForegroundColor $summaryColor

if ($PassThru) {
    [pscustomobject]@{
        Passed  = ($failed.Count -eq 0)
        Results = $results
    }
}

if ($failed.Count -gt 0) {
    exit 1
}
