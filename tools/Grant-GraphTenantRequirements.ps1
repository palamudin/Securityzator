[CmdletBinding()]
param(
    [switch]$UseAuthTxt,
    [switch]$UseAzureCliDeviceCode,
    [switch]$Assign,
    [ValidateSet("Current", "Roadmap")]
    [string]$PermissionProfile = "Current",
    [bool]$IncludeExchange = $true,
    [bool]$IncludeTeams = $true,
    [string]$TenantId,
    [string]$ClientId,
    [string]$AuthPath,
    [string]$RequirementsPath
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $scriptRoot = if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
        Split-Path -Parent $PSCommandPath
    }
    else {
        (Get-Location).Path
    }
}
else {
    $scriptRoot = $PSScriptRoot
}

if ([string]::IsNullOrWhiteSpace($AuthPath)) {
    $AuthPath = Join-Path (Split-Path -Parent $scriptRoot) "Auth.txt"
}

if ([string]::IsNullOrWhiteSpace($RequirementsPath)) {
    $RequirementsPath = Join-Path (Split-Path -Parent $scriptRoot) "bootstrap.requirements.psd1"
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

function Test-FeatureEnabled {
    param(
        [string]$Feature,
        [bool]$IncludeExchange,
        [bool]$IncludeTeams
    )

    switch ($Feature) {
        "exchange" { return $IncludeExchange }
        "teams" { return $IncludeTeams }
        default { return $true }
    }
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

function Get-PermissionPlan {
    param(
        [string]$Profile,
        [bool]$IncludeExchange,
        [bool]$IncludeTeams,
        [string]$RequirementsPath
    )

    $requirements = Import-PowerShellDataFile -Path $RequirementsPath
    $profileRequirements = $requirements.Profiles[$Profile]
    if ($null -eq $profileRequirements) {
        throw "Bootstrap profile '$Profile' was not found in '$RequirementsPath'."
    }

    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($permission in @($profileRequirements.AppPermissions)) {
        if (-not (Test-FeatureEnabled -Feature $permission.Feature -IncludeExchange:$IncludeExchange -IncludeTeams:$IncludeTeams)) {
            continue
        }

        $plan.Add([pscustomobject]@{
            ResourceAppId       = $permission.ResourceAppId
            ResourceDisplayName = $permission.ResourceDisplayName
            AppRoleValue        = $permission.Value
        })
    }

    return $plan
}

function Get-DirectoryRolePlan {
    param(
        [string]$Profile,
        [bool]$IncludeExchange,
        [bool]$IncludeTeams,
        [string]$RequirementsPath
    )

    $requirements = Import-PowerShellDataFile -Path $RequirementsPath
    $profileRequirements = $requirements.Profiles[$Profile]
    if ($null -eq $profileRequirements) {
        throw "Bootstrap profile '$Profile' was not found in '$RequirementsPath'."
    }

    $roles = New-Object System.Collections.Generic.List[string]
    foreach ($role in @($profileRequirements.DirectoryRoles)) {
        if (-not (Test-FeatureEnabled -Feature $role.Feature -IncludeExchange:$IncludeExchange -IncludeTeams:$IncludeTeams)) {
            continue
        }

        $roles.Add($role.Value)
    }

    return $roles
}

function Ensure-AppRoleAssignment {
    param(
        [object]$ClientServicePrincipal,
        [string]$ResourceAppId,
        [string]$AppRoleValue,
        [hashtable]$Headers,
        [bool]$Assign
    )

    $resourceServicePrincipal = Get-ServicePrincipalByAppId -AppId $ResourceAppId -Headers $Headers
    $role = @($resourceServicePrincipal.appRoles) |
        Where-Object {
            $_.value -eq $AppRoleValue -and
            @($_.allowedMemberTypes) -contains "Application"
        } |
        Select-Object -First 1

    if ($null -eq $role) {
        throw "Application role '$AppRoleValue' was not found on '$($resourceServicePrincipal.displayName)'."
    }

    $assignments = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($ClientServicePrincipal.id)/appRoleAssignments" -Headers $Headers
    $existing = $assignments |
        Where-Object {
            $_.resourceId -eq $resourceServicePrincipal.id -and
            $_.appRoleId -eq $role.id
        } |
        Select-Object -First 1

    if ($null -ne $existing) {
        return [pscustomobject]@{
            Resource = $resourceServicePrincipal.displayName
            Permission = $AppRoleValue
            Status = "Present"
        }
    }

    if (-not $Assign) {
        return [pscustomobject]@{
            Resource = $resourceServicePrincipal.displayName
            Permission = $AppRoleValue
            Status = "Missing"
        }
    }

    Invoke-GraphRequest -Method "POST" -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($ClientServicePrincipal.id)/appRoleAssignments" -Headers $Headers -Body @{
        principalId = $ClientServicePrincipal.id
        resourceId  = $resourceServicePrincipal.id
        appRoleId   = $role.id
    } | Out-Null

    return [pscustomobject]@{
        Resource = $resourceServicePrincipal.displayName
        Permission = $AppRoleValue
        Status = "Granted"
    }
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
        return [pscustomobject]@{
            Role = $RoleDisplayName
            Status = "Present"
        }
    }

    if (-not $Assign) {
        return [pscustomobject]@{
            Role = $RoleDisplayName
            Status = "Missing"
        }
    }

    Invoke-GraphRequest -Method "POST" -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" -Headers $Headers -Body @{
        "@odata.type"    = "#microsoft.graph.unifiedRoleAssignment"
        principalId      = $PrincipalId
        roleDefinitionId = $roleDefinition.id
        directoryScopeId = "/"
    } | Out-Null

    return [pscustomobject]@{
        Role = $RoleDisplayName
        Status = "Assigned"
    }
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

Write-Step "Resolving service principal and role definitions"
$clientServicePrincipal = Get-ServicePrincipalByAppId -AppId $ClientId -Headers $headers -Select "id,appId,displayName"
$roleDefinitions = Get-RoleDefinitions -Headers $headers
$permissionPlan = Get-PermissionPlan -Profile $PermissionProfile -IncludeExchange:$IncludeExchange -IncludeTeams:$IncludeTeams -RequirementsPath $RequirementsPath
$directoryRolePlan = Get-DirectoryRolePlan -Profile $PermissionProfile -IncludeExchange:$IncludeExchange -IncludeTeams:$IncludeTeams -RequirementsPath $RequirementsPath

$permissionResults = New-Object System.Collections.Generic.List[object]
$roleResults = New-Object System.Collections.Generic.List[object]

Write-Step "Checking application permissions"
foreach ($permission in $permissionPlan) {
    $result = Ensure-AppRoleAssignment `
        -ClientServicePrincipal $clientServicePrincipal `
        -ResourceAppId $permission.ResourceAppId `
        -AppRoleValue $permission.AppRoleValue `
        -Headers $headers `
        -Assign:$Assign

    $permissionResults.Add($result)
    Write-Note "$($result.Resource) / $($result.Permission): $($result.Status)"
}

Write-Step "Checking directory roles"
foreach ($roleName in ($directoryRolePlan | Sort-Object -Unique)) {
    $result = Ensure-DirectoryRoleAssignment `
        -PrincipalId $clientServicePrincipal.id `
        -RoleDisplayName $roleName `
        -RoleDefinitions $roleDefinitions `
        -Headers $headers `
        -Assign:$Assign

    $roleResults.Add($result)
    Write-Note "$($result.Role): $($result.Status)"
}

[pscustomobject]@{
    TenantId          = $TenantId
    ClientId          = $ClientId
    ClientDisplayName = $clientServicePrincipal.displayName
    AzureCliAccount   = $account.user.name
    PermissionProfile = $PermissionProfile
    PermissionResults = $permissionResults
    DirectoryRoles    = $roleResults
} | ConvertTo-Json -Depth 10
