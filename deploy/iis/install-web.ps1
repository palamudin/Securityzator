#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$PublishWebPath = "..\..\artifacts\publish\iis\web",

    [string]$SiteName = "Securityzator",

    [string]$AppPoolName = "Securityzator",

    [string]$WebRoot = "C:\inetpub\Securityzator\Web",

    [string]$SharedDataRoot = "C:\ProgramData\Securityzator\Shared",

    [ValidateSet("http", "https")]
    [string]$Protocol = "http",

    [int]$Port = 8080,

    [string]$HostHeader = "",

    [string]$CertificateThumbprint = "",

    [string]$MutexName = "Local\\Securityzator.StateStore",

    [int]$HeartbeatStaleAfterSeconds = 30
)

$ErrorActionPreference = "Stop"
Import-Module WebAdministration -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot "Securityzator.Deployment.psm1") -Force

$publishPath = Resolve-SecurityzatorPath -Path $PublishWebPath -BasePath $PSScriptRoot
$webRootPath = Assert-SecurityzatorSafeDirectory -Path (Resolve-SecurityzatorPath -Path $WebRoot) -Label "web root"
$sharedLayout = Ensure-SecurityzatorSharedStateLayout -SharedDataRoot $SharedDataRoot
$webRootAppData = Ensure-SecurityzatorDirectory -Path (Join-Path $webRootPath "App_Data")

if (Test-Path $webRootPath) {
    $appOfflinePath = Join-Path $webRootPath "app_offline.htm"
    Set-Content -Path $appOfflinePath -Value "Securityzator deployment in progress." -Encoding utf8
}

try {
    Sync-SecurityzatorDirectory -SourcePath $publishPath -DestinationPath $webRootPath | Out-Null
}
finally {
    $appOfflinePath = Join-Path $webRootPath "app_offline.htm"
    if (Test-Path $appOfflinePath) {
        Remove-Item -LiteralPath $appOfflinePath -Force
    }
}

$productionConfig = New-SecurityzatorWebConfiguration `
    -StateFilePath $sharedLayout.StateFilePath `
    -KeyRingPath $sharedLayout.KeyRingPath `
    -MutexName $MutexName `
    -HeartbeatStaleAfterSeconds $HeartbeatStaleAfterSeconds
Write-SecurityzatorJsonFile -Path (Join-Path $webRootPath "appsettings.Production.json") -InputObject $productionConfig

Grant-SecurityzatorDirectoryAccess -Path $sharedLayout.Root -Identity "IIS AppPool\$AppPoolName" -Rights Modify
Grant-SecurityzatorDirectoryAccess -Path $webRootAppData -Identity "IIS AppPool\$AppPoolName" -Rights Modify

if (-not (Test-Path "IIS:\AppPools\$AppPoolName")) {
    New-WebAppPool -Name $AppPoolName | Out-Null
}

Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name managedRuntimeVersion -Value ""
Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name autoStart -Value $true
Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name startMode -Value "AlwaysRunning"

$siteExists = Test-Path "IIS:\Sites\$SiteName"
$bindingInformation = "*:${Port}:$HostHeader"

if (-not $siteExists) {
    New-Website -Name $SiteName -PhysicalPath $webRootPath -ApplicationPool $AppPoolName -Port $Port -IPAddress "*" -HostHeader $HostHeader | Out-Null
}
else {
    Set-ItemProperty "IIS:\Sites\$SiteName" -Name physicalPath -Value $webRootPath
    Set-ItemProperty "IIS:\Sites\$SiteName" -Name applicationPool -Value $AppPoolName
}

if ($Protocol -eq "https" -and -not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
    if (-not (Get-WebBinding -Name $SiteName -Protocol https -ErrorAction SilentlyContinue | Where-Object { $_.bindingInformation -eq $bindingInformation })) {
        New-WebBinding -Name $SiteName -Protocol https -Port $Port -IPAddress "*" -HostHeader $HostHeader -SslFlags 1 | Out-Null
    }

    $sslBindingPath = "IIS:\SslBindings\0.0.0.0!$Port!$HostHeader"
    if (Test-Path $sslBindingPath) {
        Remove-Item $sslBindingPath -Force
    }

    Get-Item "Cert:\LocalMachine\My\$CertificateThumbprint" | New-Item $sslBindingPath | Out-Null
}

Start-WebAppPool -Name $AppPoolName
Start-Website -Name $SiteName

Write-Host "Securityzator web deployment updated."
Write-Host "Site: $SiteName"
Write-Host "App pool: $AppPoolName"
Write-Host "Physical path: $webRootPath"
Write-Host "Shared state root: $($sharedLayout.Root)"
