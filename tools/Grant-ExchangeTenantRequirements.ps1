[CmdletBinding()]
param(
    [switch]$UseAuthTxt,
    [switch]$UseAzureCliDeviceCode,
    [switch]$Assign,
    [string]$TenantId,
    [string]$ClientId,
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
        ClientId = $settings["appid"]
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

    if ($null -ne $account -and $account.tenantId -eq $TenantId) {
        Write-Note "Reusing existing Azure CLI session for tenant $TenantId."
        return $account
    }

    if (-not $UseAzureCliDeviceCode) {
        throw "No matching Azure CLI session was found for tenant '$TenantId'. Re-run with -UseAzureCliDeviceCode."
    }

    Write-Note "Opening Azure CLI device-code sign-in for tenant $TenantId."
    & $AzureCliPath login --tenant $TenantId --allow-no-subscriptions --use-device-code | Out-Null

    $accountJson = & $AzureCliPath account show --output json
    if ([string]::IsNullOrWhiteSpace($accountJson)) {
        throw "Azure CLI sign-in completed, but no active account was returned."
    }

    $account = $accountJson | ConvertFrom-Json
    if ($account.tenantId -ne $TenantId) {
        throw "Azure CLI signed into tenant '$($account.tenantId)', but '$TenantId' was required."
    }

    return $account
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
    $json = $Body | ConvertTo-Json -Depth 20
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

function Get-ServicePrincipalByAppId {
    param(
        [string]$AppId,
        [hashtable]$Headers,
        [string]$Select = "id,appId,displayName,appRoles"
    )

    $filter = [Uri]::EscapeDataString("appId eq '$AppId'")
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$filter&`$select=$Select"
    $servicePrincipals = Invoke-GraphGetAll -Uri $uri -Headers $Headers
    if ($servicePrincipals.Count -eq 0) {
        throw "Service principal with appId '$AppId' was not found."
    }

    return $servicePrincipals[0]
}

function Get-RoleDefinitions {
    param([hashtable]$Headers)

    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName"
    return Invoke-GraphGetAll -Uri $uri -Headers $Headers
}

function Ensure-AppRoleAssignment {
    param(
        [object]$ClientServicePrincipal,
        [object]$ResourceServicePrincipal,
        [string]$AppRoleValue,
        [hashtable]$Headers,
        [bool]$Assign
    )

    $role = @($ResourceServicePrincipal.appRoles) |
        Where-Object {
            $_.value -eq $AppRoleValue -and
            @($_.allowedMemberTypes) -contains "Application"
        } |
        Select-Object -First 1

    if ($null -eq $role) {
        throw "Application role '$AppRoleValue' was not found on '$($ResourceServicePrincipal.displayName)'."
    }

    $assignments = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($ClientServicePrincipal.id)/appRoleAssignments" -Headers $Headers
    $existing = $assignments |
        Where-Object {
            $_.resourceId -eq $ResourceServicePrincipal.id -and
            $_.appRoleId -eq $role.id
        } |
        Select-Object -First 1

    if ($null -ne $existing) {
        return "Present"
    }

    if (-not $Assign) {
        return "Missing"
    }

    Invoke-GraphRequest -Method "POST" -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($ClientServicePrincipal.id)/appRoleAssignments" -Headers $Headers -Body @{
        principalId = $ClientServicePrincipal.id
        resourceId  = $ResourceServicePrincipal.id
        appRoleId   = $role.id
    } | Out-Null

    return "Granted"
}

function Ensure-DirectoryRoleAssignment {
    param(
        [string]$PrincipalId,
        [string]$RoleDisplayName,
        [object[]]$RoleDefinitions,
        [hashtable]$Headers,
        [bool]$Assign
    )

    $roleDefinition = $RoleDefinitions | Where-Object { $_.displayName -eq $RoleDisplayName } | Select-Object -First 1
    if ($null -eq $roleDefinition) {
        throw "Directory role '$RoleDisplayName' was not found."
    }

    $principalFilter = [Uri]::EscapeDataString("principalId eq '$PrincipalId'")
    $assignments = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=$principalFilter&`$select=id,principalId,roleDefinitionId,directoryScopeId" -Headers $Headers
    $existing = $assignments |
        Where-Object {
            $_.roleDefinitionId -eq $roleDefinition.id -and
            $_.directoryScopeId -eq "/"
        } |
        Select-Object -First 1

    if ($null -ne $existing) {
        return "Present"
    }

    if (-not $Assign) {
        return "Missing"
    }

    Invoke-GraphRequest -Method "POST" -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" -Headers $Headers -Body @{
        "@odata.type"    = "#microsoft.graph.unifiedRoleAssignment"
        principalId      = $PrincipalId
        roleDefinitionId = $roleDefinition.id
        directoryScopeId = "/"
    } | Out-Null

    return "Assigned"
}

if ($UseAuthTxt) {
    Write-Step "Loading app identifiers from Auth.txt"
    $authSettings = Get-AuthSettingsFromFile -Path $AuthPath

    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        $TenantId = $authSettings.TenantId
    }

    if ([string]::IsNullOrWhiteSpace($ClientId)) {
        $ClientId = $authSettings.ClientId
    }

    Write-Note "Loaded tenant and client identifiers from Auth.txt."
}

if ([string]::IsNullOrWhiteSpace($TenantId) -or [string]::IsNullOrWhiteSpace($ClientId)) {
    throw "TenantId and ClientId are required. Use -UseAuthTxt or pass them explicitly."
}

$azureCliPath = Get-AzureCliPath

Write-Step "Checking Azure CLI tenant context"
$account = Ensure-AzureCliSession -AzureCliPath $azureCliPath -TenantId $TenantId -UseAzureCliDeviceCode:$UseAzureCliDeviceCode
$headers = Get-GraphHeaders -AzureCliPath $azureCliPath -TenantId $TenantId

Write-Step "Resolving service principals and role definitions"
$clientServicePrincipal = Get-ServicePrincipalByAppId -AppId $ClientId -Headers $headers -Select "id,appId,displayName"
$exchangeServicePrincipal = Get-ServicePrincipalByAppId -AppId "00000002-0000-0ff1-ce00-000000000000" -Headers $headers
$roleDefinitions = Get-RoleDefinitions -Headers $headers

Write-Step "Checking Exchange tenant prerequisites"
$exchangeAppRoleStatus = Ensure-AppRoleAssignment `
    -ClientServicePrincipal $clientServicePrincipal `
    -ResourceServicePrincipal $exchangeServicePrincipal `
    -AppRoleValue "Exchange.ManageAsApp" `
    -Headers $headers `
    -Assign:$Assign

$exchangeAdminRoleStatus = Ensure-DirectoryRoleAssignment `
    -PrincipalId $clientServicePrincipal.id `
    -RoleDisplayName "Exchange Administrator" `
    -RoleDefinitions $roleDefinitions `
    -Headers $headers `
    -Assign:$Assign

Write-Note "Office 365 Exchange Online / Exchange.ManageAsApp: $exchangeAppRoleStatus"
Write-Note "Exchange Administrator: $exchangeAdminRoleStatus"

[pscustomobject]@{
    TenantId                     = $TenantId
    ClientId                     = $ClientId
    ClientDisplayName            = $clientServicePrincipal.displayName
    AzureCliAccount              = $account.user.name
    ExchangeManageAsAppStatus    = $exchangeAppRoleStatus
    ExchangeAdministratorStatus  = $exchangeAdminRoleStatus
} | ConvertTo-Json -Depth 10
