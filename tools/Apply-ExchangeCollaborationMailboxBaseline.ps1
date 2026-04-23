[CmdletBinding()]
param(
    [switch]$UseAuthTxt,
    [switch]$UseAzureCliDeviceCode,
    [switch]$UseExchangeDeviceLogin,
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
    foreach ($commandName in @("az", "az.cmd")) {
        $command = Get-Command $commandName -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return $command.Source
        }
    }

    foreach ($path in @(
        "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
        "C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd")) {
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

    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        throw "TenantId is required when Azure CLI device-code sign-in is requested."
    }

    Write-Note "Opening Azure CLI device-code sign-in for tenant $TenantId."
    & $AzureCliPath login --tenant $TenantId --allow-no-subscriptions --use-device-code | Out-Null

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

function Get-OptionalPropertyValue {
    param(
        [object]$InputObject,
        [string]$PropertyName
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
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

function Get-DefaultOwaMailboxPolicy {
    $defaultPolicy = Get-FirstOrDefault -Items ((Get-OwaMailboxPolicy -ErrorAction Stop) | Where-Object { [bool](Get-OptionalPropertyValue -InputObject $_ -PropertyName 'IsDefault') })
    if ($null -ne $defaultPolicy) {
        return $defaultPolicy
    }

    return Get-FirstOrDefault -Items (Get-OwaMailboxPolicy -ErrorAction Stop)
}

function Get-DefaultSharingPolicy {
    $defaultPolicy = Get-FirstOrDefault -Items ((Get-SharingPolicy -ErrorAction Stop) | Where-Object { [bool](Get-OptionalPropertyValue -InputObject $_ -PropertyName 'Default') -or [bool](Get-OptionalPropertyValue -InputObject $_ -PropertyName 'IsDefault') })
    if ($null -ne $defaultPolicy) {
        return $defaultPolicy
    }

    return Get-FirstOrDefault -Items (Get-SharingPolicy -ErrorAction Stop)
}

function Get-OrganizationSnapshot {
    $organizationConfig = Get-OrganizationConfig -ErrorAction Stop

    return [ordered]@{
        AuditDisabled = [bool](Get-OptionalPropertyValue -InputObject $organizationConfig -PropertyName 'AuditDisabled')
        MailTipsAllTipsEnabled = [bool](Get-OptionalPropertyValue -InputObject $organizationConfig -PropertyName 'MailTipsAllTipsEnabled')
        AppsForOfficeEnabled = [bool](Get-OptionalPropertyValue -InputObject $organizationConfig -PropertyName 'AppsForOfficeEnabled')
        OAuth2ClientProfileEnabled = [bool](Get-OptionalPropertyValue -InputObject $organizationConfig -PropertyName 'OAuth2ClientProfileEnabled')
    }
}

function Get-OwaSnapshot {
    $owaPolicy = Get-DefaultOwaMailboxPolicy

    return [ordered]@{
        PolicyExists = $null -ne $owaPolicy
        Identity = if ($null -eq $owaPolicy) { '' } else { [string]$owaPolicy.Identity }
        Name = if ($null -eq $owaPolicy) { '' } else { [string]$owaPolicy.Name }
        IsDefault = if ($null -eq $owaPolicy) { $false } else { [bool](Get-OptionalPropertyValue -InputObject $owaPolicy -PropertyName 'IsDefault') }
        AdditionalStorageProvidersAvailable = if ($null -eq $owaPolicy) { $true } else { [bool](Get-OptionalPropertyValue -InputObject $owaPolicy -PropertyName 'AdditionalStorageProvidersAvailable') }
    }
}

function Get-SharingSnapshot {
    $sharingPolicy = Get-DefaultSharingPolicy
    $domains = Convert-ToStringArray -Values (Get-OptionalPropertyValue -InputObject $sharingPolicy -PropertyName 'Domains')

    return [ordered]@{
        PolicyExists = $null -ne $sharingPolicy
        Identity = if ($null -eq $sharingPolicy) { '' } else { [string]$sharingPolicy.Identity }
        Name = if ($null -eq $sharingPolicy) { '' } else { [string]$sharingPolicy.Name }
        Domains = $domains
        HasAnonymousCalendarSharing = @($domains | Where-Object { $_ -like 'Anonymous:*' }).Count -gt 0
    }
}

function Test-ExchangeMailboxBaselineCompliance {
    param(
        [hashtable]$OrganizationSnapshot,
        [hashtable]$OwaSnapshot
    )

    return (
        $OrganizationSnapshot.AuditDisabled -eq $false -and
        $OrganizationSnapshot.MailTipsAllTipsEnabled -eq $true -and
        $OrganizationSnapshot.AppsForOfficeEnabled -eq $false -and
        $OrganizationSnapshot.OAuth2ClientProfileEnabled -eq $true -and
        $OwaSnapshot.PolicyExists -and
        $OwaSnapshot.AdditionalStorageProvidersAvailable -eq $false
    )
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

if (-not $UseExchangeDeviceLogin) {
    $exchangeToken = & $azureCliPath account get-access-token --tenant $targetTenantId --resource https://outlook.office365.com --query accessToken -o tsv
    if ([string]::IsNullOrWhiteSpace($exchangeToken)) {
        throw "Azure CLI did not return an Exchange Online access token."
    }
}

Write-Step "Applying Exchange collaboration and mailbox baseline"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Import-Module ExchangeOnlineManagement -ErrorAction Stop

if ($UseExchangeDeviceLogin) {
    if ($PSVersionTable.PSEdition -ne 'Core') {
        throw "UseExchangeDeviceLogin requires PowerShell 7. Re-run this helper with 'pwsh'."
    }

    Connect-ExchangeOnline `
        -Device `
        -CommandName Get-OrganizationConfig,Enable-OrganizationCustomization,Set-OrganizationConfig,Get-OwaMailboxPolicy,Set-OwaMailboxPolicy,Get-SharingPolicy `
        -ShowBanner:$false `
        -ShowProgress:$false `
        -ErrorAction Stop | Out-Null
}
else {
    Connect-ExchangeOnline `
        -AccessToken $exchangeToken `
        -UserPrincipalName $account.user.name `
        -CommandName Get-OrganizationConfig,Enable-OrganizationCustomization,Set-OrganizationConfig,Get-OwaMailboxPolicy,Set-OwaMailboxPolicy,Get-SharingPolicy `
        -ShowBanner:$false `
        -ShowProgress:$false `
        -ErrorAction Stop | Out-Null
}

try {
    $organizationCustomizationEnabled = Ensure-OrganizationCustomizationEnabled
    $beforeOrganization = Get-OrganizationSnapshot
    $beforeOwa = Get-OwaSnapshot
    $alreadyCompliant = Test-ExchangeMailboxBaselineCompliance -OrganizationSnapshot $beforeOrganization -OwaSnapshot $beforeOwa

    if (-not $alreadyCompliant) {
        Set-OrganizationConfig `
            -AuditDisabled $false `
            -MailTipsAllTipsEnabled $true `
            -AppsForOfficeEnabled $false `
            -OAuth2ClientProfileEnabled $true `
            -ErrorAction Stop | Out-Null

        if ($beforeOwa.PolicyExists) {
            Set-OwaMailboxPolicy `
                -Identity $beforeOwa.Identity `
                -AdditionalStorageProvidersAvailable $false `
                -ErrorAction Stop | Out-Null
        }
    }

    $afterOrganization = Get-OrganizationSnapshot
    $afterOwa = Get-OwaSnapshot
    $afterSharing = Get-SharingSnapshot

    $notes = New-Object System.Collections.Generic.List[string]
    if ($organizationCustomizationEnabled) {
        $notes.Add("Exchange Online organization customization was enabled automatically before the baseline was applied.")
    }

    $needsManualFollowUp = $false
    if (-not $afterSharing.PolicyExists) {
        $needsManualFollowUp = $true
        $notes.Add("No default sharing policy was detected for Exchange calendar sharing review.")
    }
    elseif ($afterSharing.HasAnonymousCalendarSharing) {
        $needsManualFollowUp = $true
        $notes.Add("The default sharing policy still allows Anonymous calendar sharing. Securityzator did not remove sharing domains automatically in this slice.")
    }
    elseif ($afterSharing.Domains.Count -gt 0) {
        $needsManualFollowUp = $true
        $notes.Add("The default sharing policy still contains external sharing entries. Review whether broader calendar sharing should remain available.")
    }

    $notes.Add("Customer Lockbox remains a licensing-dependent control and was not changed by this Business Premium baseline.")

    [pscustomobject]@{
        TenantId = $targetTenantId
        SignedInUser = $account.user.name
        OrganizationCustomizationEnabled = $organizationCustomizationEnabled
        AlreadyCompliant = $alreadyCompliant
        NeedsManualFollowUp = $needsManualFollowUp
        Organization = $afterOrganization
        OwaMailboxPolicy = $afterOwa
        SharingPolicy = $afterSharing
        Notes = $notes
    } | ConvertTo-Json -Depth 8
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}
