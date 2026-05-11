[CmdletBinding()]
param(
    [ValidateSet('AssessmentOnly', 'AppOnlyConfirmed', 'ArmorMeUpAppOnly')]
    [string]$Profile = 'AppOnlyConfirmed',

    [string]$ConnectionId,

    [string]$IncludeGroupId,

    [string]$ExcludeGroupId,

    [ValidateSet('ReportOnly', 'Enabled')]
    [string]$ConditionalAccessMode = 'ReportOnly',

    [string]$OutputDirectory,

    [switch]$PlanOnly,

    [switch]$SkipBuild,

    [switch]$StopOnFirstFailure
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $PSScriptRoot 'tenant-shakedown.manifest.psd1'
$manifest = Import-PowerShellDataFile -Path $manifestPath
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repoRoot ("artifacts\runlogs\tenant-shakedown-{0}" -f $timestamp)
}

$null = New-Item -ItemType Directory -Force -Path $OutputDirectory

$driverLogPath = Join-Path $OutputDirectory 'driver.log'
$summaryJsonPath = Join-Path $OutputDirectory 'summary.json'
$summaryMarkdownPath = Join-Path $OutputDirectory 'summary.md'
$stateFilePath = Join-Path $repoRoot 'src\Securityzator.Web\App_Data\securityzator-state.json'

function Write-RunMessage {
    param(
        [string]$Message
    )

    $line = "[{0}] {1}" -f ([DateTimeOffset]::UtcNow.ToString('u')), $Message
    Write-Host $line
    Add-Content -Path $driverLogPath -Value $line
}

function Get-StateDocument {
    if (-not (Test-Path $stateFilePath)) {
        throw "State file was not found at '$stateFilePath'."
    }

    $raw = Get-Content -Path $stateFilePath -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "State file '$stateFilePath' is empty."
    }

    return $raw | ConvertFrom-Json
}

function Resolve-Connection {
    param(
        [string]$RequestedConnectionId
    )

    $state = Get-StateDocument
    $connections = @($state.Connections)

    if (-not $connections.Count) {
        throw 'No saved Azure connections were found in the Securityzator state file.'
    }

    if (-not [string]::IsNullOrWhiteSpace($RequestedConnectionId)) {
        $selected = $connections | Where-Object { $_.Id -eq $RequestedConnectionId } | Select-Object -First 1
        if ($null -eq $selected) {
            throw "Connection '$RequestedConnectionId' was not found in the state file."
        }

        return $selected
    }

    return $connections |
        Sort-Object { [DateTimeOffset]$_.UpdatedUtc } -Descending |
        Select-Object -First 1
}

function Get-TemplateSelection {
    param(
        [string]$SelectedProfile
    )

    return @(
        $manifest.Templates |
            ForEach-Object { [pscustomobject]$_ } |
            Where-Object { $_.Profiles -contains $SelectedProfile } |
            Sort-Object { [int]$_.Sequence }
    )
}

function Convert-StepToMarkdown {
    param(
        [pscustomobject]$Step
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(("## {0}. {1}" -f $Step.Sequence, $Step.DisplayName))
    $lines.Add('')
    $lines.Add(('- Template key: `{0}`' -f $Step.TemplateKey))
    $lines.Add(('- Surface: `{0}`' -f $Step.Surface))
    $lines.Add(('- Launch mode: `{0}`' -f $Step.LaunchMode))
    $lines.Add(('- Script status: `{0}`' -f $Step.ScriptStatus))

    if (-not [string]::IsNullOrWhiteSpace($Step.Message)) {
        $lines.Add(('- Outcome message: {0}' -f $Step.Message))
    }

    if (-not [string]::IsNullOrWhiteSpace($Step.PolicyId)) {
        $lines.Add(('- Policy/target: `{0}`' -f $Step.PolicyId))
    }

    if (-not [string]::IsNullOrWhiteSpace($Step.PolicyState)) {
        $lines.Add(('- Policy state: `{0}`' -f $Step.PolicyState))
    }

    if (-not [string]::IsNullOrWhiteSpace($Step.RunId)) {
        $lines.Add(('- Run ID: `{0}`' -f $Step.RunId))
    }

    if (-not [string]::IsNullOrWhiteSpace($Step.JobId)) {
        $lines.Add(('- Job ID: `{0}`' -f $Step.JobId))
    }

    if ($Step.JobLogs -and $Step.JobLogs.Count -gt 0) {
        $lines.Add('')
        $lines.Add('Job log:')
        foreach ($entry in $Step.JobLogs) {
            $lines.Add(('- {0}' -f $entry))
        }
    }

    if ($Step.RunLogs -and $Step.RunLogs.Count -gt 0) {
        $lines.Add('')
        $lines.Add('Run log:')
        foreach ($entry in $Step.RunLogs) {
            $lines.Add(('- {0}' -f $entry))
        }
    }

    $lines.Add('')
    return $lines
}

$selectedConnection = Resolve-Connection -RequestedConnectionId $ConnectionId
$ConnectionId = [string]$selectedConnection.Id

$templates = Get-TemplateSelection -SelectedProfile $Profile
if (-not $templates.Count) {
    throw "No templates were found for profile '$Profile'."
}

Write-RunMessage ("Tenant shakedown profile '{0}' resolved {1} template(s)." -f $Profile, $templates.Count)
Write-RunMessage ("Using connection '{0}' ({1})." -f $selectedConnection.DisplayName, $ConnectionId)
Write-RunMessage ("Output directory: {0}" -f $OutputDirectory)

if (-not $PlanOnly -and -not $SkipBuild) {
    Write-RunMessage 'Running build.ps1 before the shakedown sequence.'
    powershell -ExecutionPolicy Bypass -File (Join-Path $repoRoot 'build.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw "build.ps1 failed with exit code $LASTEXITCODE."
    }
}

$steps = New-Object System.Collections.Generic.List[object]

foreach ($template in $templates) {
    $sequence = [int]$template.Sequence
    $templateKey = [string]$template.TemplateKey
    $displayName = [string]$template.DisplayName
    $surface = [string]$template.Surface
    $requiresIncludeGroup = [bool]$template.RequiresIncludeGroup
    $supportedLaunchModes = @($template.SupportedLaunchModes)

    $launchMode = if ($surface -eq 'ConditionalAccess') {
        $ConditionalAccessMode
    }
    else {
        [string]$template.DefaultLaunchMode
    }

    if ($supportedLaunchModes -notcontains $launchMode) {
        $launchMode = [string]$template.DefaultLaunchMode
    }

    if ($requiresIncludeGroup -and [string]::IsNullOrWhiteSpace($IncludeGroupId)) {
        $skippedStep = [pscustomobject]@{
            Sequence = $sequence
            TemplateKey = $templateKey
            DisplayName = $displayName
            Surface = $surface
            LaunchMode = $launchMode
            ScriptStatus = 'Skipped'
            Message = 'Skipped because the template requires -IncludeGroupId and none was supplied.'
            PolicyId = $null
            PolicyState = $null
            JobId = $null
            RunId = $null
            JobLogs = @()
            RunLogs = @()
            OutputJsonPath = $null
            OutputLogPath = $null
        }

        $steps.Add($skippedStep)
        Write-RunMessage ("Skipped {0} because no pilot include group was supplied." -f $templateKey)

        if ($StopOnFirstFailure) {
            break
        }

        continue
    }

    $approvalJustification = "AI-agent tenant shakedown run for '$displayName' using profile '$Profile'."
    $jsonOutputPath = Join-Path $OutputDirectory ("{0:D3}-{1}.json" -f $sequence, $templateKey)
    $stdoutPath = Join-Path $OutputDirectory ("{0:D3}-{1}.stdout.log" -f $sequence, $templateKey)
    $startUtc = [DateTimeOffset]::UtcNow

    if ($PlanOnly) {
        $plannedStep = [pscustomobject]@{
            Sequence = $sequence
            TemplateKey = $templateKey
            DisplayName = $displayName
            Surface = $surface
            LaunchMode = $launchMode
            ScriptStatus = 'Planned'
            Message = [string]$template.Notes
            PolicyId = $null
            PolicyState = $null
            JobId = $null
            RunId = $null
            JobLogs = @()
            RunLogs = @()
            OutputJsonPath = $jsonOutputPath
            OutputLogPath = $stdoutPath
        }

        $steps.Add($plannedStep)
        Write-RunMessage ("Planned {0} in {1} mode." -f $templateKey, $launchMode)
        continue
    }

    $dotnetArgs = @(
        'run',
        '--project', (Join-Path $repoRoot 'tools\Securityzator.SmokeRunner'),
        '--no-build',
        '--',
        '--templateKey', $templateKey,
        '--connectionId', $ConnectionId,
        '--launchMode', $launchMode,
        '--approvalJustification', $approvalJustification,
        '--jsonPath', $jsonOutputPath
    )

    if (-not [string]::IsNullOrWhiteSpace($IncludeGroupId)) {
        $dotnetArgs += @('--includeGroupId', $IncludeGroupId)
    }

    if (-not [string]::IsNullOrWhiteSpace($ExcludeGroupId)) {
        $dotnetArgs += @('--excludeGroupId', $ExcludeGroupId)
    }

    Write-RunMessage ("Starting {0} ({1}) in {2} mode." -f $templateKey, $displayName, $launchMode)

    $commandOutput = & dotnet @dotnetArgs 2>&1
    $exitCode = $LASTEXITCODE
    $outputLines = @($commandOutput | ForEach-Object { $_.ToString() })
    Set-Content -Path $stdoutPath -Value $outputLines

    $report = $null
    if (Test-Path $jsonOutputPath) {
        try {
            $report = Get-Content -Path $jsonOutputPath -Raw | ConvertFrom-Json
        }
        catch {
            Write-RunMessage ("Failed to parse JSON report for {0}: {1}" -f $templateKey, $_.Exception.Message)
        }
    }

    $scriptStatus = if ($exitCode -eq 0 -and $report -and $report.Succeeded) {
        'Succeeded'
    }
    elseif ($exitCode -eq 0 -and $report) {
        'CompletedWithFollowUp'
    }
    else {
        'Failed'
    }

    $step = [pscustomobject]@{
        Sequence = $sequence
        TemplateKey = $templateKey
        DisplayName = $displayName
        Surface = $surface
        LaunchMode = $launchMode
        ScriptStatus = $scriptStatus
        Message = if ($report) { [string]$report.Message } else { ($outputLines -join [Environment]::NewLine) }
        PolicyId = if ($report) { [string]$report.PolicyId } else { $null }
        PolicyState = if ($report) { [string]$report.PolicyState } else { $null }
        JobId = if ($report) { [string]$report.JobId } else { $null }
        RunId = if ($report) { [string]$report.RunId } else { $null }
        JobLogs = if ($report -and $report.Job) { @($report.Job.Logs) } else { @() }
        RunLogs = if ($report -and $report.Run) { @($report.Run.Logs) } else { @() }
        OutputJsonPath = $jsonOutputPath
        OutputLogPath = $stdoutPath
        StartedUtc = $startUtc
        CompletedUtc = [DateTimeOffset]::UtcNow
        ExitCode = $exitCode
    }

    $steps.Add($step)
    Write-RunMessage ("Finished {0} with script status {1}." -f $templateKey, $scriptStatus)

    if (($scriptStatus -eq 'Failed') -and $StopOnFirstFailure) {
        break
    }
}

$stepArray = [object[]]$steps.ToArray()
$succeededCount = @($stepArray | Where-Object { $_.ScriptStatus -eq 'Succeeded' }).Count
$plannedCount = @($stepArray | Where-Object { $_.ScriptStatus -eq 'Planned' }).Count
$skippedCount = @($stepArray | Where-Object { $_.ScriptStatus -eq 'Skipped' }).Count
$followUpCount = @($stepArray | Where-Object { $_.ScriptStatus -eq 'CompletedWithFollowUp' }).Count
$failedCount = @($stepArray | Where-Object { $_.ScriptStatus -eq 'Failed' }).Count

$summary = [pscustomobject]@{
    Name = [string]$manifest.Metadata.Name
    LastReviewed = [string]$manifest.Metadata.LastReviewed
    Profile = $Profile
    ConditionalAccessMode = $ConditionalAccessMode
    PlanOnly = [bool]$PlanOnly
    ConnectionId = $ConnectionId
    ConnectionDisplayName = [string]$selectedConnection.DisplayName
    IncludeGroupId = $IncludeGroupId
    ExcludeGroupId = $ExcludeGroupId
    StartedUtc = ($stepArray | Select-Object -First 1).StartedUtc
    CompletedUtc = [DateTimeOffset]::UtcNow
    Totals = [pscustomobject]@{
        Steps = $stepArray.Count
        Succeeded = $succeededCount
        CompletedWithFollowUp = $followUpCount
        Failed = $failedCount
        Planned = $plannedCount
        Skipped = $skippedCount
    }
    Steps = $stepArray
}

$summary | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryJsonPath

$markdown = New-Object System.Collections.Generic.List[string]
$markdown.Add('# Securityzator tenant shakedown summary')
$markdown.Add('')
$markdown.Add(('- Profile: `{0}`' -f $Profile))
$markdown.Add(('- Conditional Access mode: `{0}`' -f $ConditionalAccessMode))
$markdown.Add(('- Plan only: `{0}`' -f $PlanOnly))
$markdown.Add(('- Connection: `{0}` (`{1}`)' -f $selectedConnection.DisplayName, $ConnectionId))

if (-not [string]::IsNullOrWhiteSpace($IncludeGroupId)) {
    $markdown.Add(('- Pilot include group: `{0}`' -f $IncludeGroupId))
}

if (-not [string]::IsNullOrWhiteSpace($ExcludeGroupId)) {
    $markdown.Add(('- Exclusion group: `{0}`' -f $ExcludeGroupId))
}

$markdown.Add(('- Output directory: `{0}`' -f $OutputDirectory))
$markdown.Add('')
$markdown.Add('| Step | Template | Surface | Launch mode | Script status |')
$markdown.Add('| --- | --- | --- | --- | --- |')

foreach ($step in $stepArray) {
    $markdown.Add((
        '| {0} | `{1}` | {2} | {3} | {4} |' -f
        $step.Sequence,
        $step.TemplateKey,
        $step.Surface,
        $step.LaunchMode,
        $step.ScriptStatus))
}

$markdown.Add('')
$markdown.Add(('Succeeded: {0}' -f $succeededCount))
$markdown.Add(('Completed with follow-up: {0}' -f $followUpCount))
$markdown.Add(('Failed: {0}' -f $failedCount))
$markdown.Add(('Planned: {0}' -f $plannedCount))
$markdown.Add(('Skipped: {0}' -f $skippedCount))
$markdown.Add('')

foreach ($step in $stepArray) {
    foreach ($line in Convert-StepToMarkdown -Step $step) {
        $markdown.Add($line)
    }
}

Set-Content -Path $summaryMarkdownPath -Value $markdown

Write-RunMessage ("Wrote summary JSON to {0}" -f $summaryJsonPath)
Write-RunMessage ("Wrote summary markdown to {0}" -f $summaryMarkdownPath)
