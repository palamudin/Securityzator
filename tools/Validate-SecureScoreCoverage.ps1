[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [string]$StatePath,
    [string]$ConnectionId,
    [int]$Top = 15,
    [switch]$FailOnUnmapped,
    [switch]$FailOnMappingDrift,
    [switch]$PassThru
)

$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSEdition -ne "Core") {
    $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($null -eq $pwsh) {
        throw "Validate-SecureScoreCoverage.ps1 requires PowerShell 7 (pwsh) to load the .NET 10 assemblies."
    }

    $forwardArgs = @(
        "-NoProfile"
        "-ExecutionPolicy"
        "Bypass"
        "-File"
        $PSCommandPath
        "-Configuration"
        $Configuration
        "-Top"
        $Top
    )

    if (-not [string]::IsNullOrWhiteSpace($StatePath)) {
        $forwardArgs += @("-StatePath", $StatePath)
    }

    if (-not [string]::IsNullOrWhiteSpace($ConnectionId)) {
        $forwardArgs += @("-ConnectionId", $ConnectionId)
    }

    if ($FailOnUnmapped) {
        $forwardArgs += "-FailOnUnmapped"
    }

    if ($FailOnMappingDrift) {
        $forwardArgs += "-FailOnMappingDrift"
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

if ([string]::IsNullOrWhiteSpace($StatePath)) {
    $StatePath = Join-Path $scriptRoot "..\src\Securityzator.Web\App_Data\securityzator-state.json"
}

$domainAssemblyPath = Join-Path $scriptRoot "..\src\Securityzator.Domain\bin\$Configuration\net10.0\Securityzator.Domain.dll"
$applicationAssemblyPath = Join-Path $scriptRoot "..\src\Securityzator.Application\bin\$Configuration\net10.0\Securityzator.Application.dll"
$infrastructureAssemblyPath = Join-Path $scriptRoot "..\src\Securityzator.Infrastructure\bin\$Configuration\net10.0\Securityzator.Infrastructure.dll"

foreach ($path in @($StatePath, $domainAssemblyPath, $applicationAssemblyPath, $infrastructureAssemblyPath)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required input '$path' was not found."
    }
}

function Normalize-Title {
    param([string]$Value)
    if ($null -eq $Value) {
        return [string]::Empty
    }

    return $Value.Trim().ToUpperInvariant()
}

function Normalize-Key {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    return $Value.Trim()
}

function New-TemplateMap {
    param([object]$RecommendationCatalog)

    $map = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
    foreach ($item in @($RecommendationCatalog)) {
        $map[(Normalize-Title $item.Title)] = [string]$item.RemediationTemplateKey

        foreach ($alias in @($item.Aliases)) {
            if (-not [string]::IsNullOrWhiteSpace($alias)) {
                $map[(Normalize-Title $alias)] = [string]$item.RemediationTemplateKey
            }
        }
    }

    return $map
}

[System.Reflection.Assembly]::LoadFrom((Resolve-Path $domainAssemblyPath)) | Out-Null
[System.Reflection.Assembly]::LoadFrom((Resolve-Path $applicationAssemblyPath)) | Out-Null
$infrastructureAssembly = [System.Reflection.Assembly]::LoadFrom((Resolve-Path $infrastructureAssemblyPath))
$blueprintServiceType = $infrastructureAssembly.GetType('Securityzator.Infrastructure.Blueprints.StaticProductBlueprintService', $true)
$blueprintService = [Activator]::CreateInstance($blueprintServiceType)
$token = [System.Threading.CancellationToken]::None
$blueprintMethod = $blueprintServiceType.GetMethod('GetPortalBlueprintAsync')
$blueprintArgs = New-Object object[] 1
$blueprintArgs[0] = $token
$blueprintTask = $blueprintMethod.Invoke($blueprintService, $blueprintArgs)
$blueprint = $blueprintTask.GetAwaiter().GetResult()
$templateByKey = @{}
foreach ($template in @($blueprint.RemediationTemplates)) {
    $templateByKey[[string]$template.Key] = $template
}

$templateMap = New-TemplateMap -RecommendationCatalog $blueprint.RecommendationCatalog
$recommendationServiceType = $infrastructureAssembly.GetType('Securityzator.Infrastructure.Recommendations.SecureScoreRecommendationService', $true)
$resolverFlags = [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic
$resolverMethod = $recommendationServiceType.GetMethods($resolverFlags) |
    Where-Object {
        $_.Name -eq 'ResolveRemediationTemplateKey' `
        -and $_.GetParameters().Count -eq 4 `
        -and $_.GetParameters()[0].ParameterType -eq [string] `
        -and $_.GetParameters()[1].ParameterType -eq [string] `
        -and $_.GetParameters()[2].ParameterType -eq [string]
    } |
    Select-Object -First 1

if ($null -eq $resolverMethod) {
    throw "Could not find SecureScore recommendation resolver method through reflection."
}

$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json -Depth 100
$syncStates = @($state.recommendationSyncStates)
if ($syncStates.Count -eq 0) {
    throw "No recommendation sync states were found in '$StatePath'."
}

$selectedSyncState = if (-not [string]::IsNullOrWhiteSpace($ConnectionId)) {
    $syncStates | Where-Object { $_.connectionId -eq $ConnectionId } | Select-Object -First 1
}
else {
    $syncStates |
        Sort-Object `
            @{ Expression = { if ($null -ne $_.lastSuccessUtc) { [datetimeoffset]$_.lastSuccessUtc } else { [datetimeoffset]::MinValue } }; Descending = $true },
            @{ Expression = { if ($null -ne $_.lastAttemptUtc) { [datetimeoffset]$_.lastAttemptUtc } else { [datetimeoffset]::MinValue } }; Descending = $true } |
        Select-Object -First 1
}

if ($null -eq $selectedSyncState) {
    throw "Could not select a recommendation sync state from '$StatePath'."
}

$connection = @($state.connections) | Where-Object { $_.id -eq $selectedSyncState.connectionId } | Select-Object -First 1
$coverageRecords = foreach ($recommendation in @($selectedSyncState.recommendations)) {
    $storedTemplateKey = Normalize-Key $recommendation.remediationTemplateKey
    $resolverArgs = New-Object object[] 4
    $resolverArgs[0] = [string]$recommendation.title
    $resolverArgs[1] = [string]$recommendation.product
    $resolverArgs[2] = [string]$recommendation.category
    $resolverArgs[3] = $templateMap
    $computedTemplateKey = Normalize-Key ($resolverMethod.Invoke($null, $resolverArgs))
    $template = if ($null -ne $computedTemplateKey -and $templateByKey.ContainsKey($computedTemplateKey)) {
        $templateByKey[$computedTemplateKey]
    }
    else {
        $null
    }
    $classification = if ($null -eq $computedTemplateKey) {
        "Unmapped"
    }
    elseif ($null -eq $template) {
        "MissingTemplate"
    }
    elseif ($template.SupportsQueueExecution) {
        "RunnableNow"
    }
    else {
        "MappedFamily"
    }
    [pscustomobject]@{
        ControlId           = [string]$recommendation.controlId
        Title               = [string]$recommendation.title
        Category            = [string]$recommendation.category
        Product             = [string]$recommendation.product
        Rank                = [int]$recommendation.rank
        StoredTemplateKey   = $storedTemplateKey
        ComputedTemplateKey = $computedTemplateKey
        Classification      = $classification
        DeliveryMode        = if ($null -ne $template) { [string]$template.DeliveryMode } else { [string]::Empty }
        SupportsQueue       = if ($null -ne $template) { [bool]$template.SupportsQueueExecution } else { $false }
        MappingDrift        = ($storedTemplateKey -ne $computedTemplateKey)
    }
}

$total = $coverageRecords.Count
$runnable = @($coverageRecords | Where-Object Classification -eq "RunnableNow")
$mappedFamily = @($coverageRecords | Where-Object Classification -eq "MappedFamily")
$unmapped = @($coverageRecords | Where-Object Classification -eq "Unmapped")
$missingTemplate = @($coverageRecords | Where-Object Classification -eq "MissingTemplate")
$mappingDrift = @($coverageRecords | Where-Object MappingDrift)

$mappedCount = $runnable.Count + $mappedFamily.Count
$mappedPercent = if ($total -eq 0) { 0 } else { [math]::Round(($mappedCount / $total) * 100, 2) }
$runnablePercent = if ($total -eq 0) { 0 } else { [math]::Round(($runnable.Count / $total) * 100, 2) }
$topTemplates = $coverageRecords |
    Where-Object { $_.Classification -ne "Unmapped" -and $_.Classification -ne "MissingTemplate" } |
    Group-Object ComputedTemplateKey |
    Sort-Object -Property Count, Name -Descending |
    Select-Object -First $Top |
    ForEach-Object {
        [pscustomobject]@{
            TemplateKey = $_.Name
            Count       = $_.Count
        }
    }

$topUnmappedProducts = $unmapped |
    Group-Object Product |
    Sort-Object -Property Count, Name -Descending |
    Select-Object -First $Top |
    ForEach-Object {
        [pscustomobject]@{
            Product = $_.Name
            Count   = $_.Count
        }
    }

$topUnmappedTitles = $unmapped |
    Sort-Object -Property Rank, Title |
    Select-Object -First $Top Title, Product, Category, Rank
$summary = [pscustomobject]@{
    ConnectionId            = [string]$selectedSyncState.connectionId
    ConnectionDisplayName   = if ($null -ne $connection) { [string]$connection.displayName } else { "Unknown connection" }
    TenantId                = if ($null -ne $connection) { [string]$connection.tenantId } else { [string]::Empty }
    LastSuccessUtc          = $selectedSyncState.lastSuccessUtc
    TotalControls           = $total
    MappedControls          = $mappedCount
    MappedPercent           = $mappedPercent
    RunnableControls        = $runnable.Count
    RunnablePercent         = $runnablePercent
    MappedFamilyControls    = $mappedFamily.Count
    UnmappedControls        = $unmapped.Count
    MissingTemplateControls = $missingTemplate.Count
    MappingDriftControls    = $mappingDrift.Count
}

Write-Host ""
Write-Host "Secure Score coverage validation" -ForegroundColor Cyan
Write-Host ("Connection: {0}" -f $summary.ConnectionDisplayName)
Write-Host ("Tenant:     {0}" -f $summary.TenantId)
Write-Host ("Snapshot:   {0}" -f $summary.LastSuccessUtc)
Write-Host ""
Write-Host ("Total controls:           {0}" -f $summary.TotalControls)
Write-Host ("Mapped controls:          {0} ({1}%)" -f $summary.MappedControls, $summary.MappedPercent) -ForegroundColor Green
Write-Host ("Runnable now:             {0} ({1}%)" -f $summary.RunnableControls, $summary.RunnablePercent) -ForegroundColor Green
Write-Host ("Mapped to broader family: {0}" -f $summary.MappedFamilyControls) -ForegroundColor Yellow
Write-Host ("Unmapped:                 {0}" -f $summary.UnmappedControls) -ForegroundColor Yellow
Write-Host ("Missing template:         {0}" -f $summary.MissingTemplateControls) -ForegroundColor Red
Write-Host ("Stored mapping drift:     {0}" -f $summary.MappingDriftControls) -ForegroundColor Yellow

if ($topTemplates.Count -gt 0) {
    Write-Host ""
    Write-Host "Top mapped template families:" -ForegroundColor Cyan
    foreach ($item in $topTemplates) {
        Write-Host ("- {0}: {1}" -f $item.TemplateKey, $item.Count)
    }
}

if ($topUnmappedProducts.Count -gt 0) {
    Write-Host ""
    Write-Host "Top unmapped products:" -ForegroundColor Cyan
    foreach ($item in $topUnmappedProducts) {
        Write-Host ("- {0}: {1}" -f $item.Product, $item.Count)
    }
}

if ($topUnmappedTitles.Count -gt 0) {
    Write-Host ""
    Write-Host ("First {0} unmapped titles:" -f $topUnmappedTitles.Count) -ForegroundColor Cyan
    foreach ($item in $topUnmappedTitles) {
        Write-Host ("- [{0}] {1} ({2} / {3})" -f $item.Rank, $item.Title, $item.Product, $item.Category)
    }
}

if ($PassThru) {
    [pscustomobject]@{
        Summary             = $summary
        TopTemplates        = $topTemplates
        TopUnmappedProducts = $topUnmappedProducts
        TopUnmappedTitles   = $topUnmappedTitles
        Records             = $coverageRecords
    }
}

if ($FailOnUnmapped -and ($unmapped.Count -gt 0 -or $missingTemplate.Count -gt 0)) {
    exit 1
}

if ($FailOnMappingDrift -and $mappingDrift.Count -gt 0) {
    exit 1
}
