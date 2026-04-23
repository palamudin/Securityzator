[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [string]$StatePath,
    [string]$ConnectionId
)

$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSEdition -ne "Core") {
    $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($null -eq $pwsh) {
        throw "Backfill-RecommendationMappings.ps1 requires PowerShell 7 (pwsh) to load the .NET 10 assemblies."
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

    if (-not [string]::IsNullOrWhiteSpace($StatePath)) {
        $forwardArgs += @("-StatePath", $StatePath)
    }

    if (-not [string]::IsNullOrWhiteSpace($ConnectionId)) {
        $forwardArgs += @("-ConnectionId", $ConnectionId)
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

$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json -Depth 100
$selectedConnection = if (-not [string]::IsNullOrWhiteSpace($ConnectionId)) {
    @($state.connections) | Where-Object { $_.id -eq $ConnectionId } | Select-Object -First 1
}
else {
    @($state.connections) | Select-Object -First 1
}

if ($null -eq $selectedConnection) {
    throw "No matching connection was found in '$StatePath'."
}

[System.Reflection.Assembly]::LoadFrom((Resolve-Path $domainAssemblyPath)) | Out-Null
[System.Reflection.Assembly]::LoadFrom((Resolve-Path $applicationAssemblyPath)) | Out-Null
[System.Reflection.Assembly]::LoadFrom((Resolve-Path $infrastructureAssemblyPath)) | Out-Null
$stateStoreType = [Securityzator.Infrastructure.Storage.JsonFileSecurityzatorStateStore]
$stateStore = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject($stateStoreType)
$stateStoreType.GetField('_gate', [System.Reflection.BindingFlags]'Instance,NonPublic').SetValue($stateStore, [System.Threading.SemaphoreSlim]::new(1, 1))
$serializerOptions = [System.Text.Json.JsonSerializerOptions]::new([System.Text.Json.JsonSerializerDefaults]::Web)
$serializerOptions.WriteIndented = $true
$stateStoreType.GetField('_serializerOptions', [System.Reflection.BindingFlags]'Instance,NonPublic').SetValue($stateStore, $serializerOptions)
$stateStoreType.GetField('_dataFilePath', [System.Reflection.BindingFlags]'Instance,NonPublic').SetValue($stateStore, (Resolve-Path $StatePath).Path)
$stateStoreType.GetField('_mutexName', [System.Reflection.BindingFlags]'Instance,NonPublic').SetValue($stateStore, 'Local\Securityzator.StateStore')

$blueprintService = [Securityzator.Infrastructure.Blueprints.StaticProductBlueprintService]::new()
$service = [Securityzator.Infrastructure.Recommendations.SecureScoreRecommendationService]::new($stateStore, $null, $null, $null, $blueprintService)

$ownerOperatorId = [Guid]$selectedConnection.ownerOperatorId
$result = $service.BackfillMappingsAsync([Guid]$selectedConnection.id, $ownerOperatorId).GetAwaiter().GetResult()
$coverage = $service.ListCoverageSummariesAsync($ownerOperatorId).GetAwaiter().GetResult() |
    Where-Object { $_.ConnectionId -eq ([Guid]$selectedConnection.id) } |
    Select-Object -First 1

Write-Host ""
Write-Host "Recommendation mapping backfill" -ForegroundColor Cyan
Write-Host ("Connection: {0}" -f $selectedConnection.displayName)
Write-Host ("Succeeded:  {0}" -f $result.Succeeded)
Write-Host ("Updated:    {0} of {1}" -f $result.UpdatedRecommendationCount, $result.TotalRecommendationCount)
Write-Host ("Message:    {0}" -f $result.Message)

if ($null -ne $coverage) {
    Write-Host ""
    Write-Host "Coverage after backfill" -ForegroundColor Cyan
    Write-Host ("Mapped:     {0}" -f $coverage.MappedControls)
    Write-Host ("Runnable:   {0}" -f $coverage.RunnableControls)
    Write-Host ("Broader:    {0}" -f $coverage.MappedFamilyControls)
    Write-Host ("Unmapped:   {0}" -f $coverage.UnmappedControls)
    Write-Host ("Drift:      {0}" -f $coverage.MappingDriftControls)
}
