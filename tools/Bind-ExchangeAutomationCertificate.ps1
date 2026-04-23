param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    [Parameter(Mandatory = $true)]
    [string]$ClientId,
    [Parameter(Mandatory = $true)]
    [string]$ClientSecret,
    [Parameter(Mandatory = $true)]
    [string]$ConnectionId,
    [string]$StatePath = (Join-Path $PSScriptRoot "..\src\Securityzator.Web\App_Data\securityzator-state.json"),
    [string]$CertificateSubject = "CN=Securityzator Exchange Automation",
    [int]$CertificateValidityMonths = 12
)

$ErrorActionPreference = "Stop"

function ConvertTo-Base64Url {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    $value = [Convert]::ToBase64String($Bytes)
    $value = $value.TrimEnd("=")
    $value = $value.Replace("+", "-")
    $value = $value.Replace("/", "_")
    return $value
}

function Get-GraphAccessToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret
    )

    $tokenResponse = Invoke-RestMethod `
        -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body @{
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = "https://graph.microsoft.com/.default"
            grant_type    = "client_credentials"
        } `
        -ContentType "application/x-www-form-urlencoded"

    return $tokenResponse.access_token
}

function Get-GraphHeaders {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )

    return @{
        Authorization = "Bearer $AccessToken"
        Accept        = "application/json"
    }
}

function New-KeyCredential {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $customIdentifier = $Certificate.GetCertHash()
    $publicKey = [Convert]::ToBase64String($Certificate.RawData)

    return @{
        type               = "AsymmetricX509Cert"
        usage              = "Verify"
        displayName        = "Securityzator Exchange Automation"
        key                = $publicKey
        customKeyIdentifier = [Convert]::ToBase64String($customIdentifier)
        startDateTime      = $Certificate.NotBefore.ToUniversalTime().ToString("o")
        endDateTime        = $Certificate.NotAfter.ToUniversalTime().ToString("o")
    }
}

function Find-OrCreateAutomationCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Subject,
        [Parameter(Mandatory = $true)]
        [int]$ValidityMonths
    )

    $storePath = "Cert:\CurrentUser\My"
    $existing = Get-ChildItem -Path $storePath |
        Where-Object { $_.Subject -eq $Subject -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if ($null -ne $existing -and $existing.NotAfter -gt (Get-Date).AddDays(30)) {
        return $existing
    }

    return New-SelfSignedCertificate `
        -Subject $Subject `
        -CertStoreLocation $storePath `
        -KeyExportPolicy Exportable `
        -KeySpec Signature `
        -KeyLength 2048 `
        -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddMonths($ValidityMonths)
}

function Get-ApplicationByAppId {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        [Parameter(Mandatory = $true)]
        [string]$ClientId
    )

    $encoded = [Uri]::EscapeDataString("appId eq '$ClientId'")
    $uri = "https://graph.microsoft.com/v1.0/applications?`$filter=$encoded&`$select=id,appId,displayName,keyCredentials"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $Headers

    if (-not $response.value -or $response.value.Count -eq 0) {
        throw "Application with appId '$ClientId' was not found."
    }

    return $response.value[0]
}

function Ensure-KeyCredential {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Application,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $thumbprintBase64 = [Convert]::ToBase64String($Certificate.GetCertHash())
    $existing = @($Application.keyCredentials) | Where-Object {
        $_.customKeyIdentifier -eq $thumbprintBase64
    }

    if ($existing.Count -gt 0) {
        return $false
    }

    $keyCredentials = @()
    foreach ($keyCredential in @($Application.keyCredentials)) {
        $entry = @{}
        foreach ($property in $keyCredential.PSObject.Properties) {
            if ($property.Name -eq "keyId") {
                continue
            }

            $entry[$property.Name] = $property.Value
        }

        $keyCredentials += $entry
    }

    $keyCredentials += (New-KeyCredential -Certificate $Certificate)

    $body = @{
        keyCredentials = $keyCredentials
    } | ConvertTo-Json -Depth 10

    Invoke-RestMethod `
        -Method Patch `
        -Uri "https://graph.microsoft.com/v1.0/applications/$($Application.id)" `
        -Headers ($Headers + @{ "Content-Type" = "application/json" }) `
        -Body $body

    return $true
}

function Update-StateFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$ConnectionId,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "State file '$Path' was not found."
    }

    $raw = Get-Content -LiteralPath $Path -Raw
    $document = $raw | ConvertFrom-Json
    $connectionCollection = if ($document.PSObject.Properties.Name -contains "connections") {
        @($document.connections)
    }
    elseif ($document.PSObject.Properties.Name -contains "azureConnections") {
        @($document.azureConnections)
    }
    else {
        @()
    }

    $connection = $connectionCollection | Where-Object { $_.id -eq $ConnectionId } | Select-Object -First 1

    if ($null -eq $connection) {
        throw "Connection '$ConnectionId' was not found in state file."
    }

    $connection.automationCertificateThumbprint = $Certificate.Thumbprint
    $connection.automationCertificateStoreLocation = "CurrentUser"
    $connection.automationCertificateStoreName = "My"
    $connection.automationCertificateSubject = $Certificate.Subject
    $connection.automationCertificateExpiresUtc = $Certificate.NotAfter.ToUniversalTime().ToString("o")
    $connection.validationStatus = 0
    $connection.lastValidationError = $null
    $connection.canReadRecommendations = $false
    $connection.canReadGroups = $false
    $connection.canReadConditionalAccess = $false
    $connection.canManageTeamsMeetingPolicy = $false
    $connection.automationCertificateStatus = 0
    $connection.automationCertificateMessage = "Securityzator Defender automation certificate was generated locally and bound to the Entra app registration."
    $connection.teamsAutomationMessage = $null

    $updated = $document | ConvertTo-Json -Depth 100
    Set-Content -LiteralPath $Path -Value $updated -Encoding UTF8
}

$certificate = Find-OrCreateAutomationCertificate -Subject $CertificateSubject -ValidityMonths $CertificateValidityMonths
$token = Get-GraphAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
$headers = Get-GraphHeaders -AccessToken $token
$application = Get-ApplicationByAppId -Headers $headers -ClientId $ClientId
$credentialAdded = Ensure-KeyCredential -Headers $headers -Application $application -Certificate $certificate
Update-StateFile -Path $StatePath -ConnectionId $ConnectionId -Certificate $certificate

$result = [pscustomobject]@{
    connectionId         = $ConnectionId
    applicationId        = $application.id
    clientId             = $ClientId
    certificateThumbprint = $certificate.Thumbprint
    certificateSubject   = $certificate.Subject
    certificateNotAfter  = $certificate.NotAfter.ToUniversalTime().ToString("o")
    keyCredentialAdded   = $credentialAdded
    statePath            = (Resolve-Path -LiteralPath $StatePath).Path
}

$result | ConvertTo-Json -Depth 10
