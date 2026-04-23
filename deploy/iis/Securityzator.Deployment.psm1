Set-StrictMode -Version Latest

function Resolve-SecurityzatorPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string]$BasePath = (Get-Location).Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Assert-SecurityzatorSafeDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string]$Label = "directory"
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $trimmedPath = $fullPath.TrimEnd('\')
    $root = [System.IO.Path]::GetPathRoot($fullPath).TrimEnd('\')

    if ([string]::IsNullOrWhiteSpace($trimmedPath) -or $trimmedPath -eq $root) {
        throw "Refusing to use '$fullPath' as the $Label because it resolves to a drive root."
    }

    return $fullPath
}

function Ensure-SecurityzatorDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $safePath = Assert-SecurityzatorSafeDirectory -Path $Path
    New-Item -ItemType Directory -Path $safePath -Force | Out-Null
    return $safePath
}

function Sync-SecurityzatorDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [string]$DestinationPath
    )

    $source = Assert-SecurityzatorSafeDirectory -Path (Resolve-SecurityzatorPath -Path $SourcePath) -Label "source directory"
    $destination = Ensure-SecurityzatorDirectory -Path (Resolve-SecurityzatorPath -Path $DestinationPath)

    if (-not (Test-Path $source)) {
        throw "Source directory '$source' does not exist."
    }

    $arguments = @(
        $source,
        $destination,
        "/MIR",
        "/FFT",
        "/R:2",
        "/W:2",
        "/NFL",
        "/NDL",
        "/NP",
        "/NJH",
        "/NJS"
    )

    & robocopy @arguments | Out-Null
    $exitCode = $LASTEXITCODE

    if ($exitCode -gt 7) {
        throw "Robocopy failed while syncing '$source' to '$destination'. Exit code: $exitCode."
    }

    return $destination
}

function Ensure-SecurityzatorSharedStateLayout {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SharedDataRoot
    )

    $root = Ensure-SecurityzatorDirectory -Path $SharedDataRoot
    $keyRingPath = Ensure-SecurityzatorDirectory -Path (Join-Path $root "keyring")
    $stateFilePath = Join-Path $root "securityzator-state.json"

    if (-not (Test-Path $stateFilePath)) {
        $initialState = @{
            operators = @()
            connections = @()
            recommendationSyncStates = @()
            remediationRuns = @()
            remediationJobs = @()
            workers = @()
        }

        Write-SecurityzatorJsonFile -Path $stateFilePath -InputObject $initialState
    }

    return @{
        Root = $root
        KeyRingPath = $keyRingPath
        StateFilePath = $stateFilePath
    }
}

function Write-SecurityzatorJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [object]$InputObject
    )

    $directory = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        Ensure-SecurityzatorDirectory -Path $directory | Out-Null
    }

    $json = $InputObject | ConvertTo-Json -Depth 12
    Set-Content -Path $Path -Value $json -Encoding utf8
}

function Grant-SecurityzatorDirectoryAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Identity,

        [ValidateSet("ReadAndExecute", "Modify", "FullControl")]
        [string]$Rights = "Modify"
    )

    $resolvedPath = Ensure-SecurityzatorDirectory -Path $Path
    $acl = Get-Acl -Path $resolvedPath
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Identity,
        $Rights,
        "ContainerInherit, ObjectInherit",
        "None",
        "Allow")

    $acl.SetAccessRule($accessRule)
    Set-Acl -Path $resolvedPath -AclObject $acl
}

function New-SecurityzatorWebConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$StateFilePath,

        [Parameter(Mandatory)]
        [string]$KeyRingPath,

        [string]$MutexName = "Local\\Securityzator.StateStore",

        [string]$GraphBaseUrl = "https://graph.microsoft.com/v1.0",

        [string]$AuthorityBaseUrl = "https://login.microsoftonline.com",

        [int]$HeartbeatStaleAfterSeconds = 30
    )

    return @{
        Logging = @{
            LogLevel = @{
                Default = "Information"
                "Microsoft.AspNetCore" = "Warning"
            }
        }
        AllowedHosts = "*"
        Securityzator = @{
            HostingModel = "IIS"
            GraphBaseUrl = $GraphBaseUrl
            AuthorityBaseUrl = $AuthorityBaseUrl
            UseEnvironmentProxy = $false
            QueueMode = "Background worker"
            SecretStorage = "Server-side only"
            Worker = @{
                HeartbeatStaleAfterSeconds = $HeartbeatStaleAfterSeconds
            }
            DataProtection = @{
                KeyRingPath = $KeyRingPath
            }
            Storage = @{
                DataFilePath = $StateFilePath
                MutexName = $MutexName
            }
        }
    }
}

function New-SecurityzatorWorkerConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$StateFilePath,

        [Parameter(Mandatory)]
        [string]$KeyRingPath,

        [string]$MutexName = "Local\\Securityzator.StateStore",

        [string]$GraphBaseUrl = "https://graph.microsoft.com/v1.0",

        [string]$AuthorityBaseUrl = "https://login.microsoftonline.com",

        [int]$PollIntervalSeconds = 5,

        [int]$IdleDelaySeconds = 3,

        [int]$HeartbeatStaleAfterSeconds = 30
    )

    return @{
        Logging = @{
            LogLevel = @{
                Default = "Information"
                "Microsoft.Hosting.Lifetime" = "Information"
            }
        }
        Securityzator = @{
            GraphBaseUrl = $GraphBaseUrl
            AuthorityBaseUrl = $AuthorityBaseUrl
            UseEnvironmentProxy = $false
            QueueMode = "Background worker"
            Storage = @{
                DataFilePath = $StateFilePath
                MutexName = $MutexName
            }
            DataProtection = @{
                KeyRingPath = $KeyRingPath
            }
            Worker = @{
                PollIntervalSeconds = $PollIntervalSeconds
                IdleDelaySeconds = $IdleDelaySeconds
                HeartbeatStaleAfterSeconds = $HeartbeatStaleAfterSeconds
            }
        }
    }
}

function Invoke-SecurityzatorScCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    & sc.exe @Arguments | Out-Host

    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe failed with exit code $LASTEXITCODE. Arguments: $($Arguments -join ' ')"
    }
}

Export-ModuleMember -Function *-Securityzator*
