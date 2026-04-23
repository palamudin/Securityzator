[CmdletBinding()]
param(
    [switch]$Full,
    [switch]$InstallModules,
    [switch]$BindExchangeCertificate,
    [switch]$GrantTenantRequirements,
    [switch]$AssignDirectoryRoles,
    [switch]$UseAzureCliDeviceCode,
    [switch]$UseAuthTxt,
    [switch]$SkipGraphSourceMapValidation,
    [ValidateSet("Current", "Roadmap")]
    [string]$PermissionProfile = "Current",
    [bool]$IncludeExchange = $true,
    [bool]$IncludeTeams = $true,
    [string]$TenantId,
    [string]$ClientId,
    [string]$ClientSecret,
    [string]$ConnectionId,
    [string]$RequirementsPath = (Join-Path $PSScriptRoot "bootstrap.requirements.psd1"),
    [string]$GraphSourceMapPath = (Join-Path $PSScriptRoot "graph.source-map.psd1"),
    [string]$BootstrapAuthStatePath = (Join-Path $PSScriptRoot ".bootstrap-auth.json"),
    [string]$AuthPath = (Join-Path $PSScriptRoot "Auth.txt"),
    [string]$StatePath = (Join-Path $PSScriptRoot "src\Securityzator.Web\App_Data\securityzator-state.json")
)

$ErrorActionPreference = "Stop"
$script:BootstrapRequirements = $null
$script:GraphSourceMap = $null

if ($Full) {
    $InstallModules = $true
    $BindExchangeCertificate = $true
    $GrantTenantRequirements = $true
    $AssignDirectoryRoles = $true
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

function Test-CommandAvailable {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-BootstrapRequirements {
    if ($null -ne $script:BootstrapRequirements) {
        return $script:BootstrapRequirements
    }

    if (-not (Test-Path -LiteralPath $RequirementsPath)) {
        throw "Bootstrap requirements file '$RequirementsPath' was not found."
    }

    $script:BootstrapRequirements = Import-PowerShellDataFile -Path $RequirementsPath
    return $script:BootstrapRequirements
}

function Get-GraphSourceMap {
    if ($null -ne $script:GraphSourceMap) {
        return $script:GraphSourceMap
    }

    if (-not (Test-Path -LiteralPath $GraphSourceMapPath)) {
        return $null
    }

    $script:GraphSourceMap = Import-PowerShellDataFile -Path $GraphSourceMapPath
    return $script:GraphSourceMap
}

function Write-GraphSourceMapNote {
    $sourceMap = Get-GraphSourceMap
    if ($null -eq $sourceMap) {
        return
    }

    Write-Step "Loading Microsoft Graph source map"
    Write-Note "Docs source: $($sourceMap.CanonicalSources.Documentation.Repository)"
    Write-Note "Metadata source: $($sourceMap.CanonicalSources.Metadata.Repository)"
    Write-Note "SDK reference: $($sourceMap.CanonicalSources.PowerShellSdk.Repository)"
}

function Invoke-GraphSourceMapValidation {
    if ($SkipGraphSourceMapValidation) {
        Write-Note "Skipping Microsoft Graph source-map validation by request."
        return
    }

    $validatorPath = Join-Path $PSScriptRoot "tools\Validate-GraphSourceMap.ps1"
    if (-not (Test-Path -LiteralPath $validatorPath)) {
        throw "Graph source-map validator '$validatorPath' was not found."
    }

    Write-Step "Validating Microsoft Graph source map"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $validatorPath

    if ($LASTEXITCODE -ne 0) {
        throw "Graph source-map validation failed."
    }
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

    return $null
}

function Get-ActiveAzureCliSession {
    $azureCliPath = Get-AzureCliPath
    if ([string]::IsNullOrWhiteSpace($azureCliPath)) {
        return $null
    }

    try {
        $accountJson = & $azureCliPath account show --output json 2>$null
        if ([string]::IsNullOrWhiteSpace($accountJson)) {
            return $null
        }

        return [pscustomobject]@{
            Path    = $azureCliPath
            Account = ($accountJson | ConvertFrom-Json)
        }
    }
    catch {
        return $null
    }
}

function Get-GraphHeadersForCurrentContext {
    if (-not [string]::IsNullOrWhiteSpace($env:SECURITYZATOR_GRAPH_ACCESS_TOKEN)) {
        return @{
            Authorization = "Bearer $($env:SECURITYZATOR_GRAPH_ACCESS_TOKEN)"
            Accept        = "application/json"
        }
    }

    if (Test-Path -LiteralPath $BootstrapAuthStatePath) {
        $authState = Get-Content -LiteralPath $BootstrapAuthStatePath -Raw | ConvertFrom-Json
        if (-not [string]::IsNullOrWhiteSpace($authState.accessToken)) {
            return @{
                Authorization = "Bearer $($authState.accessToken)"
                Accept        = "application/json"
            }
        }
    }

    return $null
}

function Set-BootstrapAuthState {
    param(
        [string]$AzureCliPath,
        [string]$TenantId,
        [string]$AccessToken
    )

    $state = [pscustomobject]@{
        azureCliPath = $AzureCliPath
        tenantId     = $TenantId
        accessToken  = $AccessToken
        cachedUtc    = (Get-Date).ToUniversalTime().ToString("o")
    }

    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $BootstrapAuthStatePath -Encoding UTF8
}

function Clear-BootstrapAuthState {
    if (Test-Path -LiteralPath $BootstrapAuthStatePath) {
        Remove-Item -LiteralPath $BootstrapAuthStatePath -Force
    }
}

function Get-InstalledModuleVersion {
    param([string]$Name)

    $module = Get-Module -ListAvailable -Name $Name |
        Sort-Object Version -Descending |
        Select-Object -First 1

    return $module
}

function Ensure-ModuleInstalled {
    param(
        [string]$Name,
        [System.Collections.Generic.List[object]]$SummaryItems
    )

    $existing = Get-InstalledModuleVersion -Name $Name
    if ($null -ne $existing) {
        $SummaryItems.Add([pscustomobject]@{
                Name = $Name
                Status = "Present"
                Version = $existing.Version.ToString()
                Path = $existing.Path
            })
        Write-Note "$Name already present ($($existing.Version))."
        return
    }

    Write-Note "Installing $Name for CurrentUser."
    if (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue) {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted | Out-Null
    }

    Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber

    $installed = Get-InstalledModuleVersion -Name $Name
    if ($null -eq $installed) {
        throw "Module '$Name' did not appear after installation."
    }

    $SummaryItems.Add([pscustomobject]@{
            Name = $Name
            Status = "Installed"
            Version = $installed.Version.ToString()
            Path = $installed.Path
        })
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
        ClientSecret = if ($settings.ContainsKey("clientsecretvalue")) { $settings["clientsecretvalue"] } else { $null }
    }
}

function Get-StateDocument {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "State file '$Path' was not found."
    }

    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

function Get-StateConnections {
    param([string]$Path)

    $document = Get-StateDocument -Path $Path
    if ($document.PSObject.Properties.Name -contains "connections") {
        return @($document.connections)
    }

    if ($document.PSObject.Properties.Name -contains "azureConnections") {
        return @($document.azureConnections)
    }

    return @()
}

function Resolve-Connection {
    param(
        [string]$Path,
        [string]$ConnectionId,
        [string]$TenantId,
        [string]$ClientId
    )

    $connections = Get-StateConnections -Path $Path
    if ($connections.Count -eq 0) {
        throw "No saved connections were found in '$Path'."
    }

    if (-not [string]::IsNullOrWhiteSpace($ConnectionId)) {
        $match = $connections | Where-Object { $_.id -eq $ConnectionId } | Select-Object -First 1
        if ($null -eq $match) {
            throw "Connection '$ConnectionId' was not found in '$Path'."
        }

        return $match
    }

    if (-not [string]::IsNullOrWhiteSpace($TenantId) -and -not [string]::IsNullOrWhiteSpace($ClientId)) {
        $match = $connections |
            Where-Object { $_.tenantId -eq $TenantId -and $_.clientId -eq $ClientId } |
            Select-Object -First 1

        if ($null -ne $match) {
            return $match
        }
    }

    if ($connections.Count -eq 1) {
        return $connections[0]
    }

    $available = $connections | ForEach-Object { "$($_.displayName) [$($_.id)]" }
    throw "Multiple connections were found. Specify -ConnectionId. Available connections: $($available -join ', ')"
}

function Ensure-GraphConnection {
    param(
        [string]$TenantId,
        [bool]$UseAzureCliDeviceCode
    )

    $scopes = @(
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "Directory.Read.All"
    )

    Write-Note "Opening Microsoft Graph delegated sign-in for tenant bootstrap."
    if ($UseAzureCliDeviceCode) {
        $azureCliPath = Get-AzureCliPath
        if ([string]::IsNullOrWhiteSpace($azureCliPath)) {
            throw "Azure CLI was requested, but az could not be found on this host."
        }

        $env:SECURITYZATOR_USE_AZURE_CLI_GRAPH = "1"
        $env:SECURITYZATOR_AZURE_CLI_PATH = $azureCliPath
        $env:SECURITYZATOR_TENANT_ID = $TenantId
        $env:SECURITYZATOR_GRAPH_ACCESS_TOKEN = $null
        Clear-BootstrapAuthState

        $hasMatchingAzureCliSession = $false
        try {
            $accountJson = & $azureCliPath account show --output json 2>$null
            if (-not [string]::IsNullOrWhiteSpace($accountJson)) {
                $account = $accountJson | ConvertFrom-Json
                $hasMatchingAzureCliSession = $account.tenantId -eq $TenantId
            }
        }
        catch {
            $hasMatchingAzureCliSession = $false
        }

        if ($hasMatchingAzureCliSession) {
            Write-Note "Reusing existing Azure CLI session."
        }
        else {
            Write-Note "Using Azure CLI device-code sign-in."
            & $azureCliPath login --tenant $TenantId --allow-no-subscriptions --use-device-code | Out-Null
        }

        $accessToken = & $azureCliPath account get-access-token --tenant $TenantId --resource-type ms-graph --query accessToken -o tsv
        if ([string]::IsNullOrWhiteSpace($accessToken)) {
            throw "Azure CLI did not return a Microsoft Graph access token."
        }

        $env:SECURITYZATOR_GRAPH_ACCESS_TOKEN = $accessToken
        Set-BootstrapAuthState -AzureCliPath $azureCliPath -TenantId $TenantId -AccessToken $accessToken

        return
    }

    $env:SECURITYZATOR_USE_AZURE_CLI_GRAPH = "0"
    $env:SECURITYZATOR_AZURE_CLI_PATH = $null
    $env:SECURITYZATOR_TENANT_ID = $null
    $env:SECURITYZATOR_GRAPH_ACCESS_TOKEN = $null
    Clear-BootstrapAuthState
    try {
        Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome | Out-Null
    }
    catch {
        if ($_.Exception.Message -notmatch "A window handle must be configured") {
            throw
        }

        Write-Note "Interactive browser auth is unavailable in this terminal. Falling back to device-code sign-in."
        Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome -UseDeviceCode | Out-Null
    }
}

function Invoke-GraphRequest {
    param(
        [string]$Method,
        [string]$Uri,
        [object]$Body
    )

    $activeGraphHeaders = Get-GraphHeadersForCurrentContext
    if ($null -ne $activeGraphHeaders) {
        $headers = @{}
        foreach ($key in $activeGraphHeaders.Keys) {
            $headers[$key] = $activeGraphHeaders[$key]
        }

        if ($null -eq $Body) {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
        }

        $json = $Body | ConvertTo-Json -Depth 20
        $headers["Content-Type"] = "application/json"
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
    }

    $configuredAzureCliPath = $env:SECURITYZATOR_AZURE_CLI_PATH
    if (
        $env:SECURITYZATOR_USE_AZURE_CLI_GRAPH -eq "1" -and
        -not [string]::IsNullOrWhiteSpace($configuredAzureCliPath) -and
        (Test-Path -LiteralPath $configuredAzureCliPath)
    ) {
        $arguments = @(
            "rest",
            "--method", $Method,
            "--url", $Uri,
            "--output", "json"
        )

        if ($null -ne $Body) {
            $json = $Body | ConvertTo-Json -Depth 20 -Compress
            $arguments += @(
                "--headers", "Content-Type=application/json",
                "--body", $json
            )
        }

        $responseJson = & $configuredAzureCliPath @arguments
        if ([string]::IsNullOrWhiteSpace($responseJson)) {
            return $null
        }

        return $responseJson | ConvertFrom-Json -Depth 100
    }

    $activeAzureCliSession = Get-ActiveAzureCliSession
    if ($null -ne $activeAzureCliSession) {
        $arguments = @(
            "rest",
            "--method", $Method,
            "--url", $Uri,
            "--output", "json"
        )

        if ($null -ne $Body) {
            $json = $Body | ConvertTo-Json -Depth 20 -Compress
            $arguments += @(
                "--headers", "Content-Type=application/json",
                "--body", $json
            )
        }

        $responseJson = & $activeAzureCliSession.Path @arguments
        if ([string]::IsNullOrWhiteSpace($responseJson)) {
            return $null
        }

        return $responseJson | ConvertFrom-Json -Depth 100
    }

    if ($null -eq $Body) {
        return Invoke-MgGraphRequest -Method $Method -Uri $Uri -OutputType PSObject
    }

    $json = $Body | ConvertTo-Json -Depth 20
    return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $json -ContentType "application/json" -OutputType PSObject
}

function Invoke-GraphGetAll {
    param([string]$Uri)

    $items = @()
    $next = $Uri
    while (-not [string]::IsNullOrWhiteSpace($next)) {
        $response = Invoke-GraphRequest -Method "GET" -Uri $next -Body $null
        if ($response.PSObject.Properties.Name -contains "error") {
            $code = $response.error.code
            $message = $response.error.message
            throw "Graph request failed for '$Uri'. Code: $code. Message: $message"
        }

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
        [string]$Select = "id,appId,displayName,appRoles"
    )

    $filter = [Uri]::EscapeDataString("appId eq '$AppId'")
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$filter&`$select=$Select"

    $servicePrincipals = Invoke-GraphGetAll -Uri $uri
    if ($servicePrincipals.Count -eq 0) {
        throw "Service principal with appId '$AppId' was not found."
    }

    return $servicePrincipals[0]
}

function Get-RoleDefinitions {
    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName"
    return Invoke-GraphGetAll -Uri $uri
}

function Get-PermissionPlan {
    param(
        [string]$Profile,
        [bool]$IncludeExchange,
        [bool]$IncludeTeams
    )

    $plan = New-Object System.Collections.Generic.List[object]
    $requirements = Get-BootstrapRequirements
    $profileRequirements = $requirements.Profiles[$Profile]

    if ($null -eq $profileRequirements) {
        throw "Bootstrap profile '$Profile' was not found in '$RequirementsPath'."
    }

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
        [bool]$IncludeTeams
    )

    $requirements = Get-BootstrapRequirements
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

function Ensure-ServicePrincipalAppRoleAssignment {
    param(
        [object]$ClientServicePrincipal,
        [string]$ResourceAppId,
        [string]$AppRoleValue
    )

    $resourceServicePrincipal = Get-ServicePrincipalByAppId -AppId $ResourceAppId -Select "id,appId,displayName,appRoles"

    $role = @($ResourceServicePrincipal.appRoles) |
        Where-Object {
            $_.value -eq $AppRoleValue -and
            @($_.allowedMemberTypes) -contains "Application"
        } |
        Select-Object -First 1

    if ($null -eq $role) {
        $availableValues = @($resourceServicePrincipal.appRoles) |
            Where-Object { @($_.allowedMemberTypes) -contains "Application" } |
            ForEach-Object { $_.value } |
            Sort-Object

        throw "App role '$AppRoleValue' was not found on resource '$($resourceServicePrincipal.displayName)' (appId $ResourceAppId). Available application roles: $($availableValues -join ', ')"
    }

    $assignments = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($ClientServicePrincipal.id)/appRoleAssignments"
    $existing = $assignments |
        Where-Object {
            $_.resourceId -eq $resourceServicePrincipal.id -and
            $_.appRoleId -eq $role.id
        } |
        Select-Object -First 1

    if ($null -ne $existing) {
        return "Present"
    }

    try {
        Invoke-GraphRequest -Method "POST" -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($ClientServicePrincipal.id)/appRoleAssignments" -Body @{
            principalId = $ClientServicePrincipal.id
            resourceId  = $resourceServicePrincipal.id
            appRoleId   = $role.id
        } | Out-Null
    }
    catch {
        if ($_.Exception.Message -match "already exists") {
            return "Present"
        }

        throw
    }

    return "Granted"
}

function Ensure-ServicePrincipalDirectoryRoleAssignment {
    param(
        [string]$PrincipalId,
        [string]$RoleDisplayName,
        [object[]]$RoleDefinitions
    )

    $roleDefinition = $RoleDefinitions | Where-Object { $_.displayName -eq $RoleDisplayName } | Select-Object -First 1
    if ($null -eq $roleDefinition) {
        throw "Directory role '$RoleDisplayName' was not found."
    }

    $principalFilter = [Uri]::EscapeDataString("principalId eq '$PrincipalId'")
    $assignments = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=$principalFilter&`$select=id,principalId,roleDefinitionId,directoryScopeId"
    $existing = $assignments |
        Where-Object {
            $_.roleDefinitionId -eq $roleDefinition.id -and
            $_.directoryScopeId -eq "/"
        } |
        Select-Object -First 1

    if ($null -ne $existing) {
        return "Present"
    }

    try {
        Invoke-GraphRequest -Method "POST" -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" -Body @{
            "@odata.type"     = "#microsoft.graph.unifiedRoleAssignment"
            principalId       = $PrincipalId
            roleDefinitionId  = $roleDefinition.id
            directoryScopeId  = "/"
        } | Out-Null
    }
    catch {
        if ($_.Exception.Message -match "already exists") {
            return "Present"
        }

        throw
    }

    return "Assigned"
}

$summary = [ordered]@{
    runtimeChecks = New-Object System.Collections.Generic.List[object]
    modules = New-Object System.Collections.Generic.List[object]
    certificate = New-Object System.Collections.Generic.List[object]
    appPermissions = New-Object System.Collections.Generic.List[object]
    directoryRoles = New-Object System.Collections.Generic.List[object]
    blockers = New-Object System.Collections.Generic.List[string]
}

Write-Step "Checking local runtime"
$summary.runtimeChecks.Add([pscustomobject]@{
        Requirement = ".NET SDK"
        Status = if (Test-CommandAvailable -Name "dotnet") { "Present" } else { "Missing" }
    })
$summary.runtimeChecks.Add([pscustomobject]@{
        Requirement = "PowerShell 7 (pwsh)"
        Status = if (Test-CommandAvailable -Name "pwsh") { "Present" } else { "Missing" }
    })

foreach ($runtimeCheck in $summary.runtimeChecks) {
    Write-Note "$($runtimeCheck.Requirement): $($runtimeCheck.Status)"
}

if ($InstallModules -or $GrantTenantRequirements -or $AssignDirectoryRoles) {
    Write-GraphSourceMapNote
    Invoke-GraphSourceMapValidation
}

if ($UseAuthTxt) {
    Write-Step "Loading app credentials from Auth.txt"
    $authSettings = Get-AuthSettingsFromFile -Path $AuthPath

    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        $TenantId = $authSettings.TenantId
    }

    if ([string]::IsNullOrWhiteSpace($ClientId)) {
        $ClientId = $authSettings.ClientId
    }

    if ([string]::IsNullOrWhiteSpace($ClientSecret)) {
        $ClientSecret = $authSettings.ClientSecret
    }

    Write-Note "Loaded tenant and application identifiers from Auth.txt."
}

if ($InstallModules) {
    Write-Step "Ensuring PowerShell modules"
    $requirements = Get-BootstrapRequirements
    foreach ($moduleRequirement in @($requirements.Modules)) {
        if ($moduleRequirement.Feature -eq "graph-bootstrap" -and -not ($GrantTenantRequirements -or $AssignDirectoryRoles)) {
            continue
        }

        if (-not (Test-FeatureEnabled -Feature $moduleRequirement.Feature -IncludeExchange:$IncludeExchange -IncludeTeams:$IncludeTeams)) {
            continue
        }

        Ensure-ModuleInstalled -Name $moduleRequirement.Name -SummaryItems $summary.modules
    }
}

if ($BindExchangeCertificate) {
    Write-Step "Binding local Exchange automation certificate"

    if ([string]::IsNullOrWhiteSpace($TenantId) -or [string]::IsNullOrWhiteSpace($ClientId) -or [string]::IsNullOrWhiteSpace($ClientSecret)) {
        throw "TenantId, ClientId, and ClientSecret are required to bind the Exchange automation certificate. Use -UseAuthTxt or pass them explicitly."
    }

    $connection = Resolve-Connection -Path $StatePath -ConnectionId $ConnectionId -TenantId $TenantId -ClientId $ClientId
    $bindScript = Join-Path $PSScriptRoot "tools\Bind-ExchangeAutomationCertificate.ps1"
    $bindOutput = & $bindScript `
        -TenantId $TenantId `
        -ClientId $ClientId `
        -ClientSecret $ClientSecret `
        -ConnectionId $connection.id `
        -StatePath $StatePath

    $bindResult = $bindOutput | ConvertFrom-Json
    $summary.certificate.Add($bindResult)
    Write-Note "Bound certificate thumbprint $($bindResult.certificateThumbprint) to connection '$($connection.displayName)'."
}

if ($GrantTenantRequirements -or $AssignDirectoryRoles) {
    Write-Step "Bootstrapping tenant prerequisites"

    if (-not (Get-InstalledModuleVersion -Name "Microsoft.Graph.Authentication")) {
        throw "Microsoft.Graph.Authentication is required for tenant bootstrap. Run with -InstallModules first."
    }

    if ([string]::IsNullOrWhiteSpace($TenantId) -or [string]::IsNullOrWhiteSpace($ClientId)) {
        throw "TenantId and ClientId are required for tenant bootstrap. Use -UseAuthTxt or pass them explicitly."
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Ensure-GraphConnection -TenantId $TenantId -UseAzureCliDeviceCode:$UseAzureCliDeviceCode

    try {
        $clientServicePrincipal = Get-ServicePrincipalByAppId -AppId $ClientId -Select "id,appId,displayName"

        if ($GrantTenantRequirements) {
            $permissionPlan = Get-PermissionPlan -Profile $PermissionProfile -IncludeExchange:$IncludeExchange -IncludeTeams:$IncludeTeams

            foreach ($permission in $permissionPlan) {
                $status = Ensure-ServicePrincipalAppRoleAssignment `
                    -ClientServicePrincipal $clientServicePrincipal `
                    -ResourceAppId $permission.ResourceAppId `
                    -AppRoleValue $permission.AppRoleValue

                $summary.appPermissions.Add([pscustomobject]@{
                        Resource = $permission.ResourceDisplayName
                        Permission = $permission.AppRoleValue
                        Status = $status
                    })
                Write-Note "$($permission.ResourceDisplayName) / $($permission.AppRoleValue): $status"
            }
        }

        if ($AssignDirectoryRoles) {
            $roleDefinitions = Get-RoleDefinitions
            $rolesToAssign = Get-DirectoryRolePlan -Profile $PermissionProfile -IncludeExchange:$IncludeExchange -IncludeTeams:$IncludeTeams

            foreach ($roleName in ($rolesToAssign | Sort-Object -Unique)) {
                $status = Ensure-ServicePrincipalDirectoryRoleAssignment `
                    -PrincipalId $clientServicePrincipal.id `
                    -RoleDisplayName $roleName `
                    -RoleDefinitions $roleDefinitions

                $summary.directoryRoles.Add([pscustomobject]@{
                        Role = $roleName
                        Status = $status
                    })
                Write-Note "${roleName}: $status"
            }
        }
    }
    finally {
        Clear-BootstrapAuthState
        if ($env:SECURITYZATOR_USE_AZURE_CLI_GRAPH -ne "1") {
            Disconnect-MgGraph | Out-Null
        }
    }
}

if (-not $InstallModules -and -not $BindExchangeCertificate -and -not $GrantTenantRequirements -and -not $AssignDirectoryRoles) {
    Write-Step "No mutating action selected"
    Write-Note "Run .\\bootstrap.ps1 -Full -UseAuthTxt -ConnectionId <connection-id> for a zero-to-ready bootstrap."
    Write-Note "Or combine actions such as -InstallModules, -BindExchangeCertificate, -GrantTenantRequirements, and -AssignDirectoryRoles."
}

$summaryObject = [pscustomobject]$summary
Write-Host ""
Write-Host "Bootstrap summary:" -ForegroundColor Green
$summaryObject | ConvertTo-Json -Depth 20
