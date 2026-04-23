#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$PublishWorkerPath = "..\..\artifacts\publish\iis\worker",

    [string]$WorkerRoot = "C:\Services\Securityzator\Worker",

    [string]$SharedDataRoot = "C:\ProgramData\Securityzator\Shared",

    [string]$ServiceName = "Securityzator.Worker",

    [string]$DisplayName = "Securityzator Worker",

    [string]$Description = "Processes queued Securityzator remediation jobs and writes worker heartbeat status back into shared state.",

    [string]$ServiceAccount = "NT AUTHORITY\\LocalService",

    [string]$MutexName = "Local\\Securityzator.StateStore",

    [int]$PollIntervalSeconds = 5,

    [int]$IdleDelaySeconds = 3,

    [int]$HeartbeatStaleAfterSeconds = 30,

    [switch]$StartService
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "Securityzator.Deployment.psm1") -Force

$publishPath = Resolve-SecurityzatorPath -Path $PublishWorkerPath -BasePath $PSScriptRoot
$workerRootPath = Assert-SecurityzatorSafeDirectory -Path (Resolve-SecurityzatorPath -Path $WorkerRoot) -Label "worker root"
$sharedLayout = Ensure-SecurityzatorSharedStateLayout -SharedDataRoot $SharedDataRoot

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService -and $existingService.Status -ne "Stopped") {
    Stop-Service -Name $ServiceName -Force -ErrorAction Stop
}

Sync-SecurityzatorDirectory -SourcePath $publishPath -DestinationPath $workerRootPath | Out-Null

$productionConfig = New-SecurityzatorWorkerConfiguration `
    -StateFilePath $sharedLayout.StateFilePath `
    -KeyRingPath $sharedLayout.KeyRingPath `
    -MutexName $MutexName `
    -PollIntervalSeconds $PollIntervalSeconds `
    -IdleDelaySeconds $IdleDelaySeconds `
    -HeartbeatStaleAfterSeconds $HeartbeatStaleAfterSeconds
Write-SecurityzatorJsonFile -Path (Join-Path $workerRootPath "appsettings.Production.json") -InputObject $productionConfig

Grant-SecurityzatorDirectoryAccess -Path $sharedLayout.Root -Identity $ServiceAccount -Rights Modify
Grant-SecurityzatorDirectoryAccess -Path $workerRootPath -Identity $ServiceAccount -Rights ReadAndExecute

$workerExecutable = Join-Path $workerRootPath "Securityzator.Worker.exe"
if (-not (Test-Path $workerExecutable)) {
    throw "Worker executable '$workerExecutable' was not found. Publish the worker before installing the service."
}

$serviceBinPath = "`"$workerExecutable`""

if (-not $existingService) {
    Invoke-SecurityzatorScCommand -Arguments @(
        "create",
        $ServiceName,
        "binPath=", $serviceBinPath,
        "DisplayName=", $DisplayName,
        "start=", "delayed-auto",
        "obj=", $ServiceAccount
    )
}
else {
    Invoke-SecurityzatorScCommand -Arguments @(
        "config",
        $ServiceName,
        "binPath=", $serviceBinPath,
        "DisplayName=", $DisplayName,
        "start=", "delayed-auto",
        "obj=", $ServiceAccount
    )
}

Invoke-SecurityzatorScCommand -Arguments @(
    "description",
    $ServiceName,
    $Description
)

Invoke-SecurityzatorScCommand -Arguments @(
    "failure",
    $ServiceName,
    "reset=", "86400",
    "actions=", "restart/60000/restart/60000/restart/60000"
)

Invoke-SecurityzatorScCommand -Arguments @(
    "failureflag",
    $ServiceName,
    "1"
)

if ($StartService.IsPresent) {
    Start-Service -Name $ServiceName
}

Write-Host "Securityzator worker service deployment updated."
Write-Host "Service: $ServiceName"
Write-Host "Executable: $workerExecutable"
Write-Host "Shared state root: $($sharedLayout.Root)"
