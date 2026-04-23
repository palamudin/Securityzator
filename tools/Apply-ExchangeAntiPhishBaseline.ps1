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

$antiPhishPolicyName = "SS-AUTO | Anti-phish baseline"
$antiPhishRuleName = "SS-AUTO | Anti-phish baseline"
$recommendedRoleDisplayNames = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "Authentication Administrator",
    "Conditional Access Administrator",
    "Cloud Application Administrator",
    "Application Administrator"
)

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

function Test-StringArrayEquals {
    param(
        [string[]]$Left,
        [string[]]$Right
    )

    $leftValue = (@($Left | Sort-Object -Unique) -join '|')
    $rightValue = (@($Right | Sort-Object -Unique) -join '|')

    return $leftValue -eq $rightValue
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

function Invoke-GraphCollection {
    param(
        [string]$AccessToken,
        [string]$InitialUrl
    )

    $results = @()
    $nextUrl = $InitialUrl
    $headers = @{ Authorization = "Bearer $AccessToken" }

    while (-not [string]::IsNullOrWhiteSpace($nextUrl)) {
        $response = Invoke-RestMethod -Method Get -Uri $nextUrl -Headers $headers -ErrorAction Stop
        if ($null -ne $response.value) {
            $results += @($response.value)
        }

        $nextUrl = $response.'@odata.nextLink'
    }

    return $results
}

function Get-RecommendedProtectedUsers {
    param([string]$AccessToken)

    $roles = Invoke-GraphCollection -AccessToken $AccessToken -InitialUrl "https://graph.microsoft.com/v1.0/directoryRoles?`$select=id,displayName"
    $matchingRoles = @($roles | Where-Object { $recommendedRoleDisplayNames -contains [string]$_.displayName })

    $users = foreach ($role in $matchingRoles) {
        $members = Invoke-GraphCollection -AccessToken $AccessToken -InitialUrl ("https://graph.microsoft.com/v1.0/directoryRoles/{0}/members?`$select=id,displayName,userPrincipalName,mail,userType,accountEnabled" -f $role.id)
        foreach ($member in $members) {
            $odataType = [string]$member.'@odata.type'
            $userPrincipalName = [string]$member.userPrincipalName
            $preferredAddress = if ([string]::IsNullOrWhiteSpace([string]$member.mail)) { $userPrincipalName } else { [string]$member.mail }

            if (($odataType -eq '#microsoft.graph.user' -or -not [string]::IsNullOrWhiteSpace($userPrincipalName)) `
                -and [bool]$member.accountEnabled `
                -and [string]$member.userType -eq 'Member' `
                -and -not [string]::IsNullOrWhiteSpace($preferredAddress)) {
                $displayName = [string]$member.displayName
                [pscustomobject]@{
                    DisplayName = $displayName
                    PreferredAddress = $preferredAddress
                    AntiPhishIdentity = if ([string]::IsNullOrWhiteSpace($displayName)) { $preferredAddress } else { "$displayName;$preferredAddress" }
                }
            }
        }
    }

    return @(
        $users |
            Sort-Object PreferredAddress -Unique |
            Select-Object -First 25
    )
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

function Get-AntiPhishSnapshot {
    param(
        [string]$PolicyName,
        [string]$RuleName
    )

    $policy = Get-FirstOrDefault -Items ((Get-AntiPhishPolicy -ErrorAction Stop) | Where-Object { $_.Name -eq $PolicyName })
    $rule = Get-FirstOrDefault -Items ((Get-AntiPhishRule -ErrorAction Stop) | Where-Object { $_.Name -eq $RuleName })
    $recipientDomains = Convert-ToStringArray -Values ($rule | ForEach-Object { $_.RecipientDomainIs })
    $targetedDomains = Convert-ToStringArray -Values (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'TargetedDomainsToProtect')
    $targetedUsers = Convert-ToStringArray -Values (Get-OptionalPropertyValue -InputObject $policy -PropertyName 'TargetedUsersToProtect')

    return [ordered]@{
        PolicyExists = $null -ne $policy
        RuleExists = $null -ne $rule
        PolicyName = if ($null -eq $policy) { $PolicyName } else { [string]$policy.Name }
        RuleName = if ($null -eq $rule) { $RuleName } else { [string]$rule.Name }
        RuleState = [string](Get-OptionalPropertyValue -InputObject $rule -PropertyName 'State')
        EnableMailboxIntelligence = if ($null -eq $policy) { $false } else { [bool](Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableMailboxIntelligence') }
        EnableMailboxIntelligenceProtection = if ($null -eq $policy) { $false } else { [bool](Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableMailboxIntelligenceProtection') }
        MailboxIntelligenceProtectionAction = if ($null -eq $policy) { '' } else { [string](Get-OptionalPropertyValue -InputObject $policy -PropertyName 'MailboxIntelligenceProtectionAction') }
        ImpersonationProtectionState = if ($null -eq $policy) { '' } else { [string](Get-OptionalPropertyValue -InputObject $policy -PropertyName 'ImpersonationProtectionState') }
        EnableOrganizationDomainsProtection = if ($null -eq $policy) { $false } else { [bool](Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableOrganizationDomainsProtection') }
        EnableTargetedDomainsProtection = if ($null -eq $policy) { $false } else { [bool](Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableTargetedDomainsProtection') }
        TargetedDomainProtectionAction = if ($null -eq $policy) { '' } else { [string](Get-OptionalPropertyValue -InputObject $policy -PropertyName 'TargetedDomainProtectionAction') }
        EnableTargetedUserProtection = if ($null -eq $policy) { $false } else { [bool](Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableTargetedUserProtection') }
        TargetedUserProtectionAction = if ($null -eq $policy) { '' } else { [string](Get-OptionalPropertyValue -InputObject $policy -PropertyName 'TargetedUserProtectionAction') }
        EnableSimilarDomainsSafetyTips = if ($null -eq $policy) { $false } else { [bool](Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableSimilarDomainsSafetyTips') }
        EnableSimilarUsersSafetyTips = if ($null -eq $policy) { $false } else { [bool](Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableSimilarUsersSafetyTips') }
        EnableUnusualCharactersSafetyTips = if ($null -eq $policy) { $false } else { [bool](Get-OptionalPropertyValue -InputObject $policy -PropertyName 'EnableUnusualCharactersSafetyTips') }
        PhishThresholdLevel = if ($null -eq $policy) { 0 } else { [int](Get-OptionalPropertyValue -InputObject $policy -PropertyName 'PhishThresholdLevel') }
        RecipientDomains = $recipientDomains
        TargetedDomains = $targetedDomains
        TargetedUsers = $targetedUsers
    }
}

function Test-AntiPhishCompliance {
    param(
        [hashtable]$Snapshot,
        [string[]]$AcceptedDomains,
        [string[]]$ProtectedUsersToProtect
    )

    $baseCompliance =
        $Snapshot.PolicyExists -and
        $Snapshot.RuleExists -and
        $Snapshot.EnableMailboxIntelligence -eq $true -and
        $Snapshot.EnableMailboxIntelligenceProtection -eq $true -and
        $Snapshot.MailboxIntelligenceProtectionAction -eq 'MoveToJmf' -and
        $Snapshot.ImpersonationProtectionState -eq 'Manual' -and
        $Snapshot.EnableOrganizationDomainsProtection -eq $true -and
        $Snapshot.EnableTargetedDomainsProtection -eq $true -and
        $Snapshot.TargetedDomainProtectionAction -eq 'Quarantine' -and
        $Snapshot.EnableSimilarDomainsSafetyTips -eq $true -and
        $Snapshot.EnableSimilarUsersSafetyTips -eq $true -and
        $Snapshot.EnableUnusualCharactersSafetyTips -eq $true -and
        $Snapshot.PhishThresholdLevel -ge 2 -and
        (Test-StringArrayEquals -Left $Snapshot.RecipientDomains -Right $AcceptedDomains) -and
        (Test-StringArrayEquals -Left $Snapshot.TargetedDomains -Right $AcceptedDomains)

    if (-not $baseCompliance) {
        return $false
    }

    return $true
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
$graphToken = & $azureCliPath account get-access-token --tenant $targetTenantId --resource-type ms-graph --query accessToken -o tsv

if (-not $UseExchangeDeviceLogin) {
    $exchangeToken = & $azureCliPath account get-access-token --tenant $targetTenantId --resource https://outlook.office365.com --query accessToken -o tsv
    if ([string]::IsNullOrWhiteSpace($exchangeToken)) {
        throw "Azure CLI did not return an Exchange Online access token."
    }
}

if ([string]::IsNullOrWhiteSpace($graphToken)) {
    throw "Azure CLI did not return a Microsoft Graph access token."
}

$protectedUserDiscoveryError = $null
$protectedUsers = @()

try {
    $protectedUsers = Get-RecommendedProtectedUsers -AccessToken $graphToken
}
catch {
    $protectedUserDiscoveryError = $_.Exception.Message
}

$protectedUsersToProtect = @($protectedUsers | ForEach-Object { [string]$_.AntiPhishIdentity } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

Write-Step "Applying Exchange anti-phish baseline"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Import-Module ExchangeOnlineManagement -ErrorAction Stop
if ($UseExchangeDeviceLogin) {
    if ($PSVersionTable.PSEdition -ne 'Core') {
        throw "UseExchangeDeviceLogin requires PowerShell 7. Re-run this helper with 'pwsh'."
    }

    Connect-ExchangeOnline `
        -Device `
        -CommandName Get-OrganizationConfig,Enable-OrganizationCustomization,Get-AcceptedDomain,Get-AntiPhishPolicy,Get-AntiPhishRule,Set-AntiPhishPolicy,Set-AntiPhishRule,New-AntiPhishPolicy,New-AntiPhishRule,Enable-AntiPhishRule `
        -ShowBanner:$false `
        -ShowProgress:$false `
        -ErrorAction Stop | Out-Null
}
else {
    Connect-ExchangeOnline `
        -AccessToken $exchangeToken `
        -UserPrincipalName $account.user.name `
        -CommandName Get-OrganizationConfig,Enable-OrganizationCustomization,Get-AcceptedDomain,Get-AntiPhishPolicy,Get-AntiPhishRule,Set-AntiPhishPolicy,Set-AntiPhishRule,New-AntiPhishPolicy,New-AntiPhishRule,Enable-AntiPhishRule `
        -ShowBanner:$false `
        -ShowProgress:$false `
        -ErrorAction Stop | Out-Null
}

try {
    $organizationCustomizationEnabled = Ensure-OrganizationCustomizationEnabled
    $acceptedDomains = @(
        Get-AcceptedDomain -ErrorAction Stop |
            ForEach-Object { [string]$_.DomainName } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )

    if ($acceptedDomains.Count -eq 0) {
        throw "Get-AcceptedDomain did not return any accepted domains for this tenant."
    }

    $beforeAntiPhish = Get-AntiPhishSnapshot -PolicyName $antiPhishPolicyName -RuleName $antiPhishRuleName
    $needsManualFollowUp = $protectedUsersToProtect.Count -eq 0
    $alreadyCompliant = Test-AntiPhishCompliance -Snapshot $beforeAntiPhish -AcceptedDomains $acceptedDomains -ProtectedUsersToProtect $protectedUsersToProtect

    if (-not $alreadyCompliant) {
        $policyParameters = @{
            EnableMailboxIntelligence = $true
            EnableMailboxIntelligenceProtection = $true
            MailboxIntelligenceProtectionAction = 'MoveToJmf'
            ImpersonationProtectionState = 'Manual'
            EnableOrganizationDomainsProtection = $true
            EnableTargetedDomainsProtection = $true
            TargetedDomainsToProtect = $acceptedDomains
            TargetedDomainProtectionAction = 'Quarantine'
            EnableSimilarDomainsSafetyTips = $true
            EnableSimilarUsersSafetyTips = $true
            EnableUnusualCharactersSafetyTips = $true
            PhishThresholdLevel = 2
            ErrorAction = 'Stop'
        }

        if ($beforeAntiPhish.PolicyExists) {
            $policyParameters['Identity'] = $antiPhishPolicyName
            Set-AntiPhishPolicy @policyParameters | Out-Null
        }
        else {
            $policyParameters['Name'] = $antiPhishPolicyName
            New-AntiPhishPolicy @policyParameters | Out-Null
        }

        if ($beforeAntiPhish.RuleExists) {
            Set-AntiPhishRule `
                -Identity $antiPhishRuleName `
                -RecipientDomainIs $acceptedDomains `
                -Priority 0 `
                -ErrorAction Stop | Out-Null

            if ($beforeAntiPhish.RuleState -ne 'Enabled') {
                Enable-AntiPhishRule -Identity $antiPhishRuleName -Confirm:$false -ErrorAction Stop | Out-Null
            }
        }
        else {
            New-AntiPhishRule `
                -Name $antiPhishRuleName `
                -AntiPhishPolicy $antiPhishPolicyName `
                -RecipientDomainIs $acceptedDomains `
                -Enabled $true `
                -Priority 0 `
                -ErrorAction Stop | Out-Null
        }
    }

    $appliedAntiPhish = Get-AntiPhishSnapshot -PolicyName $antiPhishPolicyName -RuleName $antiPhishRuleName
    if ($protectedUsersToProtect.Count -gt 0) {
        $needsManualFollowUp = -not $appliedAntiPhish.EnableTargetedUserProtection -or $appliedAntiPhish.TargetedUsers.Count -eq 0
    }
    $notes = New-Object System.Collections.Generic.List[string]

    if ($organizationCustomizationEnabled) {
        $notes.Add("Exchange Online organization customization was enabled automatically before the anti-phish baseline was applied.")
    }

    if (-not [string]::IsNullOrWhiteSpace($protectedUserDiscoveryError)) {
        $notes.Add("Protected-user discovery warning: $protectedUserDiscoveryError")
    }

    if ($needsManualFollowUp) {
        $notes.Add("Targeted user impersonation protection still needs operator review. This session can harden mailbox intelligence, domain impersonation, and safety tips, but the targeted-user impersonation parameters are not currently being applied automatically in this helper.")
    }

    $notes.Add("Phishing ZAP remains covered through the Defender for Office spam baseline where PhishZapEnabled is managed.")

    [pscustomobject]@{
        TenantId = $targetTenantId
        SignedInUser = $account.user.name
        OrganizationCustomizationEnabled = $organizationCustomizationEnabled
        ProtectedUserCount = $protectedUsersToProtect.Count
        AlreadyCompliant = $alreadyCompliant
        NeedsManualFollowUp = $needsManualFollowUp
        AntiPhish = $appliedAntiPhish
        Notes = $notes
    } | ConvertTo-Json -Depth 8
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}
