[CmdletBinding()]
param(
    [string]$SourceMapPath,
    [string]$RequirementsManifestPath,
    [string]$RequirementsDocumentPath,
    [string]$ControlCatalogManifestPath,
    [string]$SourceMapDocumentPath,
    [switch]$PassThru
)

$ErrorActionPreference = "Stop"
$scriptRoot = if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    Split-Path -Parent $MyInvocation.MyCommand.Path
}
else {
    $PSScriptRoot
}

if ([string]::IsNullOrWhiteSpace($SourceMapPath)) {
    $SourceMapPath = Join-Path $scriptRoot "..\graph.source-map.psd1"
}

if ([string]::IsNullOrWhiteSpace($RequirementsManifestPath)) {
    $RequirementsManifestPath = Join-Path $scriptRoot "..\bootstrap.requirements.psd1"
}

if ([string]::IsNullOrWhiteSpace($RequirementsDocumentPath)) {
    $RequirementsDocumentPath = Join-Path $scriptRoot "..\requirements.txt"
}

if ([string]::IsNullOrWhiteSpace($ControlCatalogManifestPath)) {
    $ControlCatalogManifestPath = Join-Path $scriptRoot "..\control-catalog.map.psd1"
}

if ([string]::IsNullOrWhiteSpace($SourceMapDocumentPath)) {
    $SourceMapDocumentPath = Join-Path $scriptRoot "..\docs\microsoft-graph-source-map.md"
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

function Get-NormalizedPermissionSet {
    param(
        [object[]]$Permissions
    )

    $normalized = @()
    foreach ($permission in @($Permissions)) {
        $resourceAppId = [string]$permission.ResourceAppId
        $value = [string]$permission.Value
        $feature = [string]$permission.Feature
        $normalized += "$resourceAppId|$value|$feature"
    }

    return @($normalized | Sort-Object -Unique)
}

function Get-NormalizedRoleSet {
    param(
        [object[]]$Roles
    )

    $normalized = @()
    foreach ($role in @($Roles)) {
        $value = [string]$role.Value
        $feature = [string]$role.Feature
        $normalized += "$value|$feature"
    }

    return @($normalized | Sort-Object -Unique)
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

function Test-DocumentPatterns {
    param(
        [string]$Area,
        [string]$Path,
        [string[]]$Patterns
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Add-Result -Area $Area -Check "File exists" -Passed $false -Details "Missing file: $Path"
        return
    }

    $content = Get-Content -LiteralPath $Path -Raw
    foreach ($pattern in $Patterns) {
        $passed = $content -like "*$pattern*"
        Add-Result -Area $Area -Check "Contains '$pattern'" -Passed $passed -Details $Path
    }
}

$sourceMap = Import-DataFileOrNull -Path $SourceMapPath -Area "SourceMap"
$manifest = Import-DataFileOrNull -Path $RequirementsManifestPath -Area "BootstrapManifest"

if ($null -ne $sourceMap) {
    $requiredSourceMapSections = @(
        "CanonicalSources",
        "PermanentMapRules",
        "Bootstrap",
        "BootstrapProfiles",
        "SdkCaveats"
    )

    foreach ($section in $requiredSourceMapSections) {
        $exists = $sourceMap.ContainsKey($section)
        Add-Result -Area "SourceMap" -Check "Has section '$section'" -Passed $exists -Details $SourceMapPath
    }

    $repoUrls = @(
        $sourceMap.CanonicalSources.Documentation.Repository,
        $sourceMap.CanonicalSources.Metadata.Repository,
        $sourceMap.CanonicalSources.PowerShellSdk.Repository
    )

    foreach ($repoUrl in $repoUrls) {
        $isMicrosoftGraphRepo = $repoUrl -like "https://github.com/microsoftgraph/*"
        Add-Result -Area "SourceMap" -Check "Canonical repo path '$repoUrl'" -Passed $isMicrosoftGraphRepo -Details "Expected microsoftgraph GitHub repository."
    }

    $expectedManifestLeaf = Split-Path -Leaf $RequirementsManifestPath
    $expectedRequirementsLeaf = Split-Path -Leaf $RequirementsDocumentPath
    $expectedControlCatalogLeaf = Split-Path -Leaf $ControlCatalogManifestPath
    Add-Result `
        -Area "SourceMap" `
        -Check "Bootstrap manifest path" `
        -Passed ($sourceMap.Bootstrap.RequirementsManifest -eq $expectedManifestLeaf) `
        -Details "Expected $expectedManifestLeaf"
    Add-Result `
        -Area "SourceMap" `
        -Check "Requirements document path" `
        -Passed ($sourceMap.Bootstrap.RequirementsDocument -eq $expectedRequirementsLeaf) `
        -Details "Expected $expectedRequirementsLeaf"
    Add-Result `
        -Area "SourceMap" `
        -Check "Control catalog manifest path" `
        -Passed ($sourceMap.Bootstrap.ControlCatalog.ManifestPath -eq $expectedControlCatalogLeaf) `
        -Details "Expected $expectedControlCatalogLeaf"
}

if ($null -ne $sourceMap -and $null -ne $manifest) {
    $expectedSourceMapLeaf = Split-Path -Leaf $SourceMapPath
    Add-Result `
        -Area "BootstrapManifest" `
        -Check "Metadata.SourceMapPath" `
        -Passed ($manifest.Metadata.SourceMapPath -eq $expectedSourceMapLeaf) `
        -Details "Expected $expectedSourceMapLeaf"
    Add-Result `
        -Area "BootstrapManifest" `
        -Check "Metadata.CanonicalDocsRepo" `
        -Passed ($manifest.Metadata.CanonicalDocsRepo -eq $sourceMap.CanonicalSources.Documentation.Repository) `
        -Details $sourceMap.CanonicalSources.Documentation.Repository
    Add-Result `
        -Area "BootstrapManifest" `
        -Check "Metadata.MetadataRepo" `
        -Passed ($manifest.Metadata.MetadataRepo -eq $sourceMap.CanonicalSources.Metadata.Repository) `
        -Details $sourceMap.CanonicalSources.Metadata.Repository
    Add-Result `
        -Area "BootstrapManifest" `
        -Check "Metadata.PowerShellSdkRepo" `
        -Passed ($manifest.Metadata.PowerShellSdkRepo -eq $sourceMap.CanonicalSources.PowerShellSdk.Repository) `
        -Details $sourceMap.CanonicalSources.PowerShellSdk.Repository

    $profileNames = @($sourceMap.BootstrapProfiles.Keys | Sort-Object)
    foreach ($profileName in $profileNames) {
        $manifestProfile = $manifest.Profiles[$profileName]
        if ($null -eq $manifestProfile) {
            Add-Result -Area "BootstrapManifest" -Check "Profile '$profileName' exists" -Passed $false -Details "Missing manifest profile."
            continue
        }

        Add-Result -Area "BootstrapManifest" -Check "Profile '$profileName' exists" -Passed $true -Details "Found"

        Compare-Set `
            -Area "BootstrapManifest" `
            -Check "Profile '$profileName' app permissions" `
            -Expected (Get-NormalizedPermissionSet -Permissions $sourceMap.BootstrapProfiles[$profileName].AppPermissions) `
            -Actual (Get-NormalizedPermissionSet -Permissions $manifestProfile.AppPermissions)

        Compare-Set `
            -Area "BootstrapManifest" `
            -Check "Profile '$profileName' directory roles" `
            -Expected (Get-NormalizedRoleSet -Roles $sourceMap.BootstrapProfiles[$profileName].DirectoryRoles) `
            -Actual (Get-NormalizedRoleSet -Roles $manifestProfile.DirectoryRoles)
    }
}

Test-DocumentPatterns `
    -Area "RequirementsDocument" `
    -Path $RequirementsDocumentPath `
    -Patterns @(
        "graph.source-map.psd1",
        "control-catalog.map.psd1",
        "docs/microsoft-graph-source-map.md",
        "microsoft-graph-docs-contrib",
        "msgraph-metadata"
    )

Test-DocumentPatterns `
    -Area "SourceMapDocument" `
    -Path $SourceMapDocumentPath `
    -Patterns @(
        "graph.source-map.psd1",
        "control-catalog.map.psd1",
        "microsoft-graph-docs-contrib",
        "msgraph-metadata",
        "msgraph-sdk-powershell"
    )

$failed = @($results | Where-Object { -not $_.Passed })
$passed = @($results | Where-Object { $_.Passed })

Write-Host ""
Write-Host "Graph source-map validation" -ForegroundColor Cyan
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
