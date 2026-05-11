[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [switch]$UseAuthTxt,
    [switch]$UseAzureCliDeviceCode,
    [string]$TenantId,
    [string]$AuthPath,
    [string]$OutputRoot
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

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputRoot = Join-Path (Join-Path (Split-Path -Parent $scriptRoot) "artifacts\\runlogs") ("ca-user-exclusions-$timestamp")
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
        Write-Note "Reusing existing Azure CLI session for tenant $($account.tenantId)."
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

function Get-GraphHeaders {
    param(
        [string]$AzureCliPath,
        [string]$TenantId
    )

    $accessToken = & $AzureCliPath account get-access-token --tenant $TenantId --resource-type ms-graph --query accessToken -o tsv
    if ([string]::IsNullOrWhiteSpace($accessToken)) {
        throw "Azure CLI did not return a Microsoft Graph access token."
    }

    return @{
        Authorization = "Bearer $accessToken"
        Accept        = "application/json"
    }
}

function Invoke-GraphRequest {
    param(
        [string]$Method,
        [string]$Uri,
        [hashtable]$Headers,
        [object]$Body
    )

    $requestHeaders = @{}
    foreach ($key in $Headers.Keys) {
        $requestHeaders[$key] = $Headers[$key]
    }

    if ($null -eq $Body) {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $requestHeaders
    }

    $requestHeaders["Content-Type"] = "application/json"
    $json = $Body | ConvertTo-Json -Depth 50
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $requestHeaders -Body $json
}

function Invoke-GraphGetAll {
    param(
        [string]$Uri,
        [hashtable]$Headers
    )

    $items = @()
    $next = $Uri

    while (-not [string]::IsNullOrWhiteSpace($next)) {
        $response = Invoke-GraphRequest -Method "GET" -Uri $next -Headers $Headers -Body $null

        if ($response.PSObject.Properties.Name -contains "value") {
            $items += @($response.value)
            $next = $response.'@odata.nextLink'
            continue
        }

        return @($response)
    }

    return $items
}

function Get-ConditionalAccessPolicies {
    param([hashtable]$Headers)

    $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$top=999"
    return Invoke-GraphGetAll -Uri $uri -Headers $Headers
}

function Get-UserByPrincipalName {
    param(
        [string]$ResolvedUserPrincipalName,
        [hashtable]$Headers
    )

    $uri = "https://graph.microsoft.com/v1.0/users/$([Uri]::EscapeDataString($ResolvedUserPrincipalName))?`$select=id,displayName,userPrincipalName,accountEnabled"
    return Invoke-GraphRequest -Method "GET" -Uri $uri -Headers $Headers -Body $null
}

function Ensure-ExcludeUsersProperty {
    param([object]$UsersNode)

    if (-not ($UsersNode.PSObject.Properties.Name -contains "excludeUsers")) {
        Add-Member -InputObject $UsersNode -MemberType NoteProperty -Name excludeUsers -Value @()
    }

    if ($null -eq $UsersNode.excludeUsers) {
        $UsersNode.excludeUsers = @()
    }

    return @($UsersNode.excludeUsers)
}

function Convert-PolicyStateSummary {
    param([object[]]$Policies)

    $enabled = @($Policies | Where-Object { $_.state -eq "enabled" }).Count
    $reportOnly = @($Policies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" }).Count
    $disabled = @($Policies | Where-Object { $_.state -eq "disabled" }).Count

    return [pscustomobject]@{
        Total      = @($Policies).Count
        Enabled    = $enabled
        ReportOnly = $reportOnly
        Disabled   = $disabled
    }
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

if ([string]::IsNullOrWhiteSpace($TenantId)) {
    $TenantId = $account.tenantId
}

Write-Note "Using Azure CLI account '$($account.user.name)' in tenant '$TenantId'."

Write-Step "Acquiring Microsoft Graph token"
$headers = Get-GraphHeaders -AzureCliPath $azureCliPath -TenantId $TenantId

Write-Step "Resolving target user"
$user = Get-UserByPrincipalName -ResolvedUserPrincipalName $UserPrincipalName -Headers $headers
if ([string]::IsNullOrWhiteSpace($user.id)) {
    throw "User '$UserPrincipalName' could not be resolved in Microsoft Graph."
}

Write-Note "Resolved '$($user.userPrincipalName)' as '$($user.displayName)' with object ID '$($user.id)'."

Write-Step "Loading Conditional Access policy spread"
$policies = @(Get-ConditionalAccessPolicies -Headers $headers)
$spread = Convert-PolicyStateSummary -Policies $policies
Write-Note "Found $($spread.Total) policies: enabled=$($spread.Enabled), report-only=$($spread.ReportOnly), disabled=$($spread.Disabled)."

$results = New-Object System.Collections.Generic.List[object]

foreach ($policy in $policies) {
    $policyName = [string]$policy.displayName
    $policyId = [string]$policy.id
    $policyState = [string]$policy.state

    Write-Note "Processing '$policyName' ($policyState)."

    try {
        if ($null -eq $policy.conditions -or $null -eq $policy.conditions.users) {
            $results.Add([pscustomobject]@{
                PolicyId              = $policyId
                PolicyName            = $policyName
                State                 = $policyState
                Result                = "Skipped"
                Reason                = "Policy did not return a users condition block."
                ExcludeUsersBefore    = 0
                ExcludeUsersAfter     = 0
                AlreadyExcluded       = $false
                AddedUserPrincipalName = $null
            }) | Out-Null
            continue
        }

        $conditions = $policy.conditions | ConvertTo-Json -Depth 50 | ConvertFrom-Json
        $excludeUsersBefore = @(Ensure-ExcludeUsersProperty -UsersNode $conditions.users)
        $alreadyExcluded = $excludeUsersBefore -contains $user.id

        if ($alreadyExcluded) {
            $results.Add([pscustomobject]@{
                PolicyId               = $policyId
                PolicyName             = $policyName
                State                  = $policyState
                Result                 = "AlreadyExcluded"
                Reason                 = "User object ID already present in excludeUsers."
                ExcludeUsersBefore     = @($excludeUsersBefore).Count
                ExcludeUsersAfter      = @($excludeUsersBefore).Count
                AlreadyExcluded        = $true
                AddedUserPrincipalName = $null
            }) | Out-Null
            continue
        }

        $updatedExcludeUsers = @(
            @($excludeUsersBefore) + $user.id |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Select-Object -Unique
        )

        $conditions.users.excludeUsers = $updatedExcludeUsers

        Invoke-GraphRequest `
            -Method "PATCH" `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$([Uri]::EscapeDataString($policyId))" `
            -Headers $headers `
            -Body @{
                conditions = $conditions
            } | Out-Null

        $results.Add([pscustomobject]@{
            PolicyId               = $policyId
            PolicyName             = $policyName
            State                  = $policyState
            Result                 = "Updated"
            Reason                 = "Added target user object ID to excludeUsers."
            ExcludeUsersBefore     = @($excludeUsersBefore).Count
            ExcludeUsersAfter      = @($updatedExcludeUsers).Count
            AlreadyExcluded        = $false
            AddedUserPrincipalName = $user.userPrincipalName
        }) | Out-Null
    }
    catch {
        $results.Add([pscustomobject]@{
            PolicyId               = $policyId
            PolicyName             = $policyName
            State                  = $policyState
            Result                 = "Failed"
            Reason                 = $_.Exception.Message
            ExcludeUsersBefore     = $null
            ExcludeUsersAfter      = $null
            AlreadyExcluded        = $false
            AddedUserPrincipalName = $null
        }) | Out-Null
    }
}

$updatedCount = @($results | Where-Object Result -eq "Updated").Count
$alreadyExcludedCount = @($results | Where-Object Result -eq "AlreadyExcluded").Count
$failedCount = @($results | Where-Object Result -eq "Failed").Count
$skippedCount = @($results | Where-Object Result -eq "Skipped").Count

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

$summary = [pscustomobject]@{
    TimestampUtc          = (Get-Date).ToUniversalTime().ToString("o")
    TenantId              = $TenantId
    RequestedUserPrincipalName = $UserPrincipalName
    ResolvedUserId        = $user.id
    ResolvedDisplayName   = $user.displayName
    ResolvedUserPrincipalName = $user.userPrincipalName
    AccountEnabled        = [bool]$user.accountEnabled
    PolicySpread          = $spread
    UpdatedCount          = $updatedCount
    AlreadyExcludedCount  = $alreadyExcludedCount
    FailedCount           = $failedCount
    SkippedCount          = $skippedCount
    Policies              = @($results)
}

$summaryJsonPath = Join-Path $OutputRoot "summary.json"
$summaryMarkdownPath = Join-Path $OutputRoot "summary.md"

$summary | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $summaryJsonPath -Encoding UTF8

$markdown = New-Object System.Collections.Generic.List[string]
[void]$markdown.Add("# Conditional Access exclusion update")
[void]$markdown.Add("")
[void]$markdown.Add("- Timestamp UTC: $((Get-Date).ToUniversalTime().ToString('o'))")
[void]$markdown.Add("- Tenant: $TenantId")
[void]$markdown.Add("- Target user: $($user.userPrincipalName) ($($user.id))")
[void]$markdown.Add("- Policies found: $($spread.Total)")
[void]$markdown.Add("- Policies updated: $updatedCount")
[void]$markdown.Add("- Policies already excluding user: $alreadyExcludedCount")
[void]$markdown.Add("- Policies failed: $failedCount")
[void]$markdown.Add("- Policies skipped: $skippedCount")
[void]$markdown.Add("")
[void]$markdown.Add("| Policy | State | Result | Reason |")
[void]$markdown.Add("| --- | --- | --- | --- |")

foreach ($result in $results) {
    $policyName = [string]$result.PolicyName
    $reason = ([string]$result.Reason).Replace("|", "\|")
    [void]$markdown.Add("| $policyName | $($result.State) | $($result.Result) | $reason |")
}

$markdown | Set-Content -LiteralPath $summaryMarkdownPath -Encoding UTF8

Write-Step "Summary"
Write-Note "Policies updated: $updatedCount"
Write-Note "Policies already excluding '$($user.userPrincipalName)': $alreadyExcludedCount"
Write-Note "Policies failed: $failedCount"
Write-Note "Policies skipped: $skippedCount"
Write-Note "Summary JSON: $summaryJsonPath"
Write-Note "Summary Markdown: $summaryMarkdownPath"

if ($failedCount -gt 0) {
    throw "One or more Conditional Access policies could not be updated. Review '$summaryJsonPath' for details."
}
