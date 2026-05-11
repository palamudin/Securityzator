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

$spamFilterPolicyName = "SS-AUTO | Spam baseline"
$spamFilterRuleName = "SS-AUTO | Spam baseline"
$outboundSpamPolicyName = "SS-AUTO | Outbound forwarding baseline"
$outboundSpamRuleName = "SS-AUTO | Outbound forwarding baseline"

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

Write-Step "Applying Exchange spam and forwarding baseline"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Import-Module ExchangeOnlineManagement -ErrorAction Stop
Connect-ExchangeOnline `
    -AccessToken $exchangeToken `
    -UserPrincipalName $account.user.name `
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

    $spamPolicy = Get-FirstOrDefault -Items ((Get-HostedContentFilterPolicy -ErrorAction Stop) | Where-Object { $_.Name -eq $spamFilterPolicyName })
    $spamRule = Get-FirstOrDefault -Items ((Get-HostedContentFilterRule -ErrorAction Stop) | Where-Object { $_.Name -eq $spamFilterRuleName })
    $outboundPolicy = Get-FirstOrDefault -Items ((Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop) | Where-Object { $_.Name -eq $outboundSpamPolicyName })
    $outboundRule = Get-FirstOrDefault -Items ((Get-HostedOutboundSpamFilterRule -ErrorAction Stop) | Where-Object { $_.Name -eq $outboundSpamRuleName })

    if ($null -eq $spamPolicy) {
        New-HostedContentFilterPolicy `
            -Name $spamFilterPolicyName `
            -SpamAction Quarantine `
            -HighConfidenceSpamAction Quarantine `
            -PhishSpamAction Quarantine `
            -HighConfidencePhishAction Quarantine `
            -BulkSpamAction Quarantine `
            -BulkThreshold 6 `
            -QuarantineRetentionPeriod 30 `
            -ErrorAction Stop | Out-Null
    }
    else {
        Set-HostedContentFilterPolicy `
            -Identity $spamFilterPolicyName `
            -SpamAction Quarantine `
            -HighConfidenceSpamAction Quarantine `
            -PhishSpamAction Quarantine `
            -HighConfidencePhishAction Quarantine `
            -BulkSpamAction Quarantine `
            -BulkThreshold 6 `
            -QuarantineRetentionPeriod 30 `
            -ErrorAction Stop | Out-Null
    }

    if ($null -eq $spamRule) {
        New-HostedContentFilterRule `
            -Name $spamFilterRuleName `
            -HostedContentFilterPolicy $spamFilterPolicyName `
            -RecipientDomainIs $acceptedDomains `
            -Enabled $true `
            -Priority 0 `
            -ErrorAction Stop | Out-Null
    }
    else {
        Set-HostedContentFilterRule `
            -Identity $spamFilterRuleName `
            -RecipientDomainIs $acceptedDomains `
            -ErrorAction Stop | Out-Null

        Enable-HostedContentFilterRule `
            -Identity $spamFilterRuleName `
            -Confirm:$false `
            -ErrorAction Stop | Out-Null
    }

    if ($null -eq $outboundPolicy) {
        New-HostedOutboundSpamFilterPolicy `
            -Name $outboundSpamPolicyName `
            -AutoForwardingMode Automatic `
            -NotifyOutboundSpam $false `
            -RecipientLimitExternalPerHour 500 `
            -RecipientLimitInternalPerHour 1000 `
            -RecipientLimitPerDay 1000 `
            -ActionWhenThresholdReached BlockUserForToday `
            -ErrorAction Stop | Out-Null
    }
    else {
        Set-HostedOutboundSpamFilterPolicy `
            -Identity $outboundSpamPolicyName `
            -AutoForwardingMode Automatic `
            -NotifyOutboundSpam $false `
            -RecipientLimitExternalPerHour 500 `
            -RecipientLimitInternalPerHour 1000 `
            -RecipientLimitPerDay 1000 `
            -ActionWhenThresholdReached BlockUserForToday `
            -ErrorAction Stop | Out-Null
    }

    if ($null -eq $outboundRule) {
        New-HostedOutboundSpamFilterRule `
            -Name $outboundSpamRuleName `
            -HostedOutboundSpamFilterPolicy $outboundSpamPolicyName `
            -SenderDomainIs $acceptedDomains `
            -Enabled $true `
            -Priority 0 `
            -ErrorAction Stop | Out-Null
    }
    else {
        Set-HostedOutboundSpamFilterRule `
            -Identity $outboundSpamRuleName `
            -SenderDomainIs $acceptedDomains `
            -ErrorAction Stop | Out-Null

        Enable-HostedOutboundSpamFilterRule `
            -Identity $outboundSpamRuleName `
            -Confirm:$false `
            -ErrorAction Stop | Out-Null
    }

    $appliedSpamPolicy = Get-FirstOrDefault -Items ((Get-HostedContentFilterPolicy -ErrorAction Stop) | Where-Object { $_.Name -eq $spamFilterPolicyName })
    $appliedOutboundPolicy = Get-FirstOrDefault -Items ((Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop) | Where-Object { $_.Name -eq $outboundSpamPolicyName })

    [pscustomobject]@{
        TenantId                        = $targetTenantId
        ExchangeOrganization            = $organizationConfig.Name
        SignedInUser                    = $account.user.name
        OrganizationCustomizationEnabled = $organizationCustomizationEnabled
        AcceptedDomains                 = $acceptedDomains
        InboundSpamPolicy               = [pscustomobject]@{
            Name                        = $appliedSpamPolicy.Name
            SpamAction                  = $appliedSpamPolicy.SpamAction
            HighConfidenceSpamAction    = $appliedSpamPolicy.HighConfidenceSpamAction
            PhishSpamAction             = $appliedSpamPolicy.PhishSpamAction
            HighConfidencePhishAction   = $appliedSpamPolicy.HighConfidencePhishAction
            BulkSpamAction              = $appliedSpamPolicy.BulkSpamAction
            BulkThreshold               = $appliedSpamPolicy.BulkThreshold
            QuarantineRetentionPeriod   = $appliedSpamPolicy.QuarantineRetentionPeriod
        }
        OutboundSpamPolicy              = [pscustomobject]@{
            Name                        = $appliedOutboundPolicy.Name
            AutoForwardingMode          = $appliedOutboundPolicy.AutoForwardingMode
            NotifyOutboundSpam          = $appliedOutboundPolicy.NotifyOutboundSpam
            RecipientLimitExternalPerHour = $appliedOutboundPolicy.RecipientLimitExternalPerHour
            RecipientLimitInternalPerHour = $appliedOutboundPolicy.RecipientLimitInternalPerHour
            RecipientLimitPerDay        = $appliedOutboundPolicy.RecipientLimitPerDay
            ActionWhenThresholdReached  = $appliedOutboundPolicy.ActionWhenThresholdReached
        }
    } | ConvertTo-Json -Depth 8
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}
