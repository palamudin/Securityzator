[CmdletBinding()]
param(
    [switch]$UseAuthTxt,
    [switch]$UseAzureCliDeviceCode,
    [string]$TenantId,
    [string]$AuthPath
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($AuthPath)) {
    $scriptRoot = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $PSScriptRoot
    }
    elseif (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
        Split-Path -Parent $PSCommandPath
    }
    else {
        (Get-Location).Path
    }

    $AuthPath = Join-Path (Split-Path -Parent $scriptRoot) "Auth.txt"
}

$safeLinksPolicyName = "SS-AUTO | Safe Links baseline"
$safeLinksRuleName = "SS-AUTO | Safe Links baseline"
$safeAttachmentPolicyName = "SS-AUTO | Safe Attachments baseline"
$safeAttachmentRuleName = "SS-AUTO | Safe Attachments baseline"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Note {
    param([string]$Message)
    Write-Host "    $Message"
}

function Get-AzureCliPath {
    $commandsToCheck = @("az", "az.cmd")
    foreach ($commandName in $commandsToCheck) {
        $command = Get-Command $commandName -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return $command.Source
        }
    }

    $fallbacks = @(
        "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
        "C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
    )

    foreach ($path in $fallbacks) {
        if (Test-Path -LiteralPath $path) {
            return $path
        }
    }

    throw "Azure CLI could not be found on this host."
}

function Get-AuthSettingsFromFile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Auth file '$Path' was not found."
    }

    $content = Get-Content -LiteralPath $Path
    $settings = @{}

    foreach ($line in $content) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if ($line -match "^\s*([^:=\s]+)\s*[:=]\s*(.+?)\s*$") {
            $settings[$matches[1].Trim().ToLowerInvariant()] = $matches[2].Trim()
        }
    }

    return [pscustomobject]@{
        TenantId = $settings["tenantid"]
    }
}

function Ensure-AzureCliSession {
    param(
        [string]$AzureCliPath,
        [string]$TenantId,
        [bool]$UseAzureCliDeviceCode
    )

    $account = $null
    try {
        $accountJson = & $AzureCliPath account show --output json 2>$null
        if (-not [string]::IsNullOrWhiteSpace($accountJson)) {
            $account = $accountJson | ConvertFrom-Json
        }
    }
    catch {
        $account = $null
    }

    if ($null -ne $account -and ([string]::IsNullOrWhiteSpace($TenantId) -or $account.tenantId -eq $TenantId)) {
        return $account
    }

    if (-not $UseAzureCliDeviceCode) {
        throw "No matching Azure CLI session was found. Re-run with -UseAzureCliDeviceCode."
    }

    $loginTenant = $TenantId
    if ([string]::IsNullOrWhiteSpace($loginTenant)) {
        throw "TenantId is required when Azure CLI device-code sign-in is requested."
    }

    Write-Note "Opening Azure CLI device-code sign-in for tenant $loginTenant."
    & $AzureCliPath login --tenant $loginTenant --allow-no-subscriptions --use-device-code | Out-Null

    $accountJson = & $AzureCliPath account show --output json
    if ([string]::IsNullOrWhiteSpace($accountJson)) {
        throw "Azure CLI sign-in completed, but no active account was returned."
    }

    return ($accountJson | ConvertFrom-Json)
}

function Get-FirstOrDefault {
    param([object[]]$Items)

    if ($null -eq $Items) {
        return $null
    }

    return @($Items | Select-Object -First 1)[0]
}

function Convert-ToStringArray {
    param([object]$Values)

    if ($null -eq $Values) {
        return @()
    }

    return @(
        $Values |
            ForEach-Object { [string]$_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )
}

function Ensure-OrganizationCustomizationEnabled {
    $organizationConfig = Get-OrganizationConfig -ErrorAction Stop
    if ($null -ne $organizationConfig -and [bool]$organizationConfig.IsDehydrated) {
        Enable-OrganizationCustomization -ErrorAction Stop | Out-Null
        Start-Sleep -Seconds 5
        return $true
    }

    return $false
}

if ($UseAuthTxt) {
    Write-Step "Loading tenant identifier from Auth.txt"
    $authSettings = Get-AuthSettingsFromFile -Path $AuthPath

    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        $TenantId = $authSettings.TenantId
    }

    Write-Note "Loaded tenant identifier from Auth.txt."
}

$azureCliPath = Get-AzureCliPath

Write-Step "Checking Azure CLI tenant context"
$account = Ensure-AzureCliSession -AzureCliPath $azureCliPath -TenantId $TenantId -UseAzureCliDeviceCode:$UseAzureCliDeviceCode
$targetTenantId = if ([string]::IsNullOrWhiteSpace($TenantId)) { $account.tenantId } else { $TenantId }
$exchangeToken = & $azureCliPath account get-access-token --tenant $targetTenantId --resource https://outlook.office365.com --query accessToken -o tsv

if ([string]::IsNullOrWhiteSpace($exchangeToken)) {
    throw "Azure CLI did not return an Exchange Online access token."
}

Write-Step "Applying Exchange Safe Links and Safe Attachments baseline"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Import-Module ExchangeOnlineManagement -ErrorAction Stop
Connect-ExchangeOnline `
    -AccessToken $exchangeToken `
    -UserPrincipalName $account.user.name `
    -CommandName Get-OrganizationConfig,Enable-OrganizationCustomization,Get-AcceptedDomain,Get-AtpPolicyForO365,Set-AtpPolicyForO365,Get-SafeLinksPolicy,Get-SafeLinksRule,Set-SafeLinksPolicy,Set-SafeLinksRule,New-SafeLinksPolicy,New-SafeLinksRule,Get-SafeAttachmentPolicy,Get-SafeAttachmentRule,Set-SafeAttachmentPolicy,Set-SafeAttachmentRule,New-SafeAttachmentPolicy,New-SafeAttachmentRule `
    -ShowBanner:$false `
    -ShowProgress:$false `
    -ErrorAction Stop | Out-Null

try {
    $organizationCustomizationEnabled = Ensure-OrganizationCustomizationEnabled
    $organizationConfig = Get-OrganizationConfig -ErrorAction Stop
    $acceptedDomains = @(
        Get-AcceptedDomain -ErrorAction Stop |
            ForEach-Object { [string]$_.DomainName } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )

    if ($acceptedDomains.Count -eq 0) {
        throw "Get-AcceptedDomain did not return any accepted domains for this tenant."
    }

    Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true -ErrorAction Stop | Out-Null

    $safeLinksPolicy = Get-FirstOrDefault -Items ((Get-SafeLinksPolicy -ErrorAction Stop) | Where-Object { $_.Name -eq $safeLinksPolicyName })
    $safeLinksRule = Get-FirstOrDefault -Items ((Get-SafeLinksRule -ErrorAction Stop) | Where-Object { $_.Name -eq $safeLinksRuleName })
    $safeAttachmentPolicy = Get-FirstOrDefault -Items ((Get-SafeAttachmentPolicy -ErrorAction Stop) | Where-Object { $_.Name -eq $safeAttachmentPolicyName })
    $safeAttachmentRule = Get-FirstOrDefault -Items ((Get-SafeAttachmentRule -ErrorAction Stop) | Where-Object { $_.Name -eq $safeAttachmentRuleName })

    if ($null -eq $safeLinksPolicy) {
        New-SafeLinksPolicy `
            -Name $safeLinksPolicyName `
            -EnableSafeLinksForEmail $true `
            -EnableSafeLinksForTeams $true `
            -EnableSafeLinksForOffice $true `
            -TrackClicks $true `
            -AllowClickThrough $false `
            -ScanUrls $true `
            -EnableForInternalSenders $true `
            -DeliverMessageAfterScan $true `
            -DisableUrlRewrite $false `
            -ErrorAction Stop | Out-Null
    }
    else {
        Set-SafeLinksPolicy `
            -Identity $safeLinksPolicyName `
            -EnableSafeLinksForEmail $true `
            -EnableSafeLinksForTeams $true `
            -EnableSafeLinksForOffice $true `
            -TrackClicks $true `
            -AllowClickThrough $false `
            -ScanUrls $true `
            -EnableForInternalSenders $true `
            -DeliverMessageAfterScan $true `
            -DisableUrlRewrite $false `
            -ErrorAction Stop | Out-Null
    }

    if ($null -eq $safeLinksRule) {
        New-SafeLinksRule `
            -Name $safeLinksRuleName `
            -SafeLinksPolicy $safeLinksPolicyName `
            -RecipientDomainIs $acceptedDomains `
            -Enabled $true `
            -Priority 0 `
            -ErrorAction Stop | Out-Null
    }
    else {
        Set-SafeLinksRule `
            -Identity $safeLinksRuleName `
            -RecipientDomainIs $acceptedDomains `
            -Enabled $true `
            -ErrorAction Stop | Out-Null
    }

    if ($null -eq $safeAttachmentPolicy) {
        New-SafeAttachmentPolicy `
            -Name $safeAttachmentPolicyName `
            -Enable $true `
            -Action Block `
            -Redirect $false `
            -ErrorAction Stop | Out-Null
    }
    else {
        Set-SafeAttachmentPolicy `
            -Identity $safeAttachmentPolicyName `
            -Enable $true `
            -Action Block `
            -Redirect $false `
            -ErrorAction Stop | Out-Null
    }

    if ($null -eq $safeAttachmentRule) {
        New-SafeAttachmentRule `
            -Name $safeAttachmentRuleName `
            -SafeAttachmentPolicy $safeAttachmentPolicyName `
            -RecipientDomainIs $acceptedDomains `
            -Enabled $true `
            -Priority 0 `
            -ErrorAction Stop | Out-Null
    }
    else {
        Set-SafeAttachmentRule `
            -Identity $safeAttachmentRuleName `
            -RecipientDomainIs $acceptedDomains `
            -Enabled $true `
            -ErrorAction Stop | Out-Null
    }

    $globalProtection = Get-FirstOrDefault -Items (Get-AtpPolicyForO365 -ErrorAction Stop)
    $appliedSafeLinksPolicy = Get-FirstOrDefault -Items ((Get-SafeLinksPolicy -ErrorAction Stop) | Where-Object { $_.Name -eq $safeLinksPolicyName })
    $appliedSafeLinksRule = Get-FirstOrDefault -Items ((Get-SafeLinksRule -ErrorAction Stop) | Where-Object { $_.Name -eq $safeLinksRuleName })
    $appliedSafeAttachmentPolicy = Get-FirstOrDefault -Items ((Get-SafeAttachmentPolicy -ErrorAction Stop) | Where-Object { $_.Name -eq $safeAttachmentPolicyName })
    $appliedSafeAttachmentRule = Get-FirstOrDefault -Items ((Get-SafeAttachmentRule -ErrorAction Stop) | Where-Object { $_.Name -eq $safeAttachmentRuleName })

    [pscustomobject]@{
        TenantId                           = $targetTenantId
        ExchangeOrganization               = $organizationConfig.Name
        SignedInUser                       = $account.user.name
        OrganizationCustomizationEnabled   = $organizationCustomizationEnabled
        AcceptedDomains                    = $acceptedDomains
        GlobalProtection                   = [pscustomobject]@{
            EnableAtpForSpoTeamsOdb        = $globalProtection.EnableATPForSPOTeamsODB
            EnableSafeDocs                 = $globalProtection.EnableSafeDocs
            AllowSafeDocsOpen              = $globalProtection.AllowSafeDocsOpen
        }
        SafeLinksPolicy                    = [pscustomobject]@{
            Name                           = $appliedSafeLinksPolicy.Name
            EnableSafeLinksForEmail        = $appliedSafeLinksPolicy.EnableSafeLinksForEmail
            EnableSafeLinksForTeams        = $appliedSafeLinksPolicy.EnableSafeLinksForTeams
            EnableSafeLinksForOffice       = $appliedSafeLinksPolicy.EnableSafeLinksForOffice
            TrackClicks                    = $appliedSafeLinksPolicy.TrackClicks
            AllowClickThrough              = $appliedSafeLinksPolicy.AllowClickThrough
            ScanUrls                       = $appliedSafeLinksPolicy.ScanUrls
            EnableForInternalSenders       = $appliedSafeLinksPolicy.EnableForInternalSenders
            DeliverMessageAfterScan        = $appliedSafeLinksPolicy.DeliverMessageAfterScan
            DisableUrlRewrite              = $appliedSafeLinksPolicy.DisableUrlRewrite
            RecipientDomains               = Convert-ToStringArray -Values $appliedSafeLinksRule.RecipientDomainIs
        }
        SafeAttachmentPolicy               = [pscustomobject]@{
            Name                           = $appliedSafeAttachmentPolicy.Name
            Enable                         = $appliedSafeAttachmentPolicy.Enable
            Action                         = $appliedSafeAttachmentPolicy.Action
            Redirect                       = $appliedSafeAttachmentPolicy.Redirect
            RecipientDomains               = Convert-ToStringArray -Values $appliedSafeAttachmentRule.RecipientDomainIs
        }
        Notes                              = @(
            "Safe Documents remains licensing-dependent and was not changed by this Business Premium baseline."
        )
    } | ConvertTo-Json -Depth 8
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}
