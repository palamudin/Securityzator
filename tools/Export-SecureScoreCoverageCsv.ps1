[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [string]$StatePath,
    [string]$ConnectionId,
    [string]$OutputPath,
    [switch]$EndpointOnly,
    [switch]$PassThru
)

$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSEdition -ne "Core") {
    throw "Export-SecureScoreCoverageCsv.ps1 must be run with PowerShell 7 (pwsh)."
}

$scriptRoot = if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { $PSScriptRoot }
if ([string]::IsNullOrWhiteSpace($StatePath)) { $StatePath = Join-Path $scriptRoot "..\src\Securityzator.Web\App_Data\securityzator-state.json" }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $name = if ($EndpointOnly) { "secure-score-endpoint-mapping.csv" } else { "secure-score-control-mapping.csv" }
    $OutputPath = Join-Path $scriptRoot "..\artifacts\reports\$name"
}

$coverageScriptPath = Join-Path $scriptRoot "Validate-SecureScoreCoverage.ps1"
foreach ($path in @($coverageScriptPath, $StatePath)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required input '$path' was not found." }
}

if (-not [string]::IsNullOrWhiteSpace($ConnectionId)) {
    $coverage = & $coverageScriptPath -Configuration $Configuration -StatePath $StatePath -ConnectionId $ConnectionId -PassThru
}
else {
    $coverage = & $coverageScriptPath -Configuration $Configuration -StatePath $StatePath -PassThru
}

$records = @($coverage.Records | ForEach-Object {
    $storedKey = [string]$_.StoredTemplateKey
    $computedKey = [string]$_.ComputedTemplateKey
    $isEndpoint = (
        (-not [string]::IsNullOrWhiteSpace($storedKey) -and $storedKey.StartsWith("defender-endpoint-", [System.StringComparison]::OrdinalIgnoreCase)) -or
        (-not [string]::IsNullOrWhiteSpace($computedKey) -and $computedKey.StartsWith("defender-endpoint-", [System.StringComparison]::OrdinalIgnoreCase))
    )

    [pscustomobject]@{
        ConnectionDisplayName = [string]$coverage.Summary.ConnectionDisplayName
        TenantId              = [string]$coverage.Summary.TenantId
        SnapshotUtc           = [string]$coverage.Summary.LastSuccessUtc
        ControlId             = [string]$_.ControlId
        Rank                  = [int]$_.Rank
        Title                 = [string]$_.Title
        Product               = [string]$_.Product
        Category              = [string]$_.Category
        StoredTemplateKey     = $storedKey
        ComputedTemplateKey   = $computedKey
        Classification        = [string]$_.Classification
        DeliveryMode          = [string]$_.DeliveryMode
        SupportsQueue         = [bool]$_.SupportsQueue
        MappingDrift          = [bool]$_.MappingDrift
        IsEndpointFamily      = $isEndpoint
    }
})

if ($EndpointOnly) { $records = @($records | Where-Object IsEndpointFamily) }
$outputDirectory = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$records | Sort-Object Rank, Title | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Secure Score CSV export complete" -ForegroundColor Cyan
Write-Host ("Connection: {0}" -f $coverage.Summary.ConnectionDisplayName)
Write-Host ("Scope:      {0}" -f ($(if ($EndpointOnly) { "Endpoint families only" } else { "All mapped controls" })))
Write-Host ("Rows:       {0}" -f $records.Count)
Write-Host ("Output:     {0}" -f (Resolve-Path $OutputPath))

if ($PassThru) { $records }


