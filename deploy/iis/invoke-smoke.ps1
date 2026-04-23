[CmdletBinding()]
param(
    [string]$BaseUrl = "http://localhost:8080",

    [string]$StateFilePath = "C:\ProgramData\Securityzator\Shared\securityzator-state.json",

    [int]$HeartbeatStaleAfterSeconds = 30
)

$ErrorActionPreference = "Stop"

function Invoke-HealthCheck {
    param([string]$Url)

    $response = Invoke-WebRequest -UseBasicParsing $Url -TimeoutSec 20
    return [pscustomobject]@{
        Url = $Url
        StatusCode = $response.StatusCode
        Body = $response.Content
    }
}

$live = Invoke-HealthCheck -Url ($BaseUrl.TrimEnd("/") + "/health/live")
$ready = Invoke-HealthCheck -Url ($BaseUrl.TrimEnd("/") + "/health/ready")

Write-Host "Live check:  $($live.StatusCode) $($live.Body)"
Write-Host "Ready check: $($ready.StatusCode) $($ready.Body)"

if (Test-Path $StateFilePath) {
    $state = Get-Content $StateFilePath -Raw | ConvertFrom-Json
    $workers = @($state.workers)
    $jobs = @($state.remediationJobs)
    $connections = @($state.connections)

    Write-Host "Connections: $($connections.Count)"
    Write-Host "Jobs:        $($jobs.Count)"
    Write-Host "Workers:     $($workers.Count)"

    if ($workers.Count -gt 0) {
        $now = [DateTimeOffset]::UtcNow
        foreach ($worker in $workers) {
            $lastHeartbeat = [DateTimeOffset]::Parse($worker.lastHeartbeatUtc)
            $isStale = ($now - $lastHeartbeat).TotalSeconds -gt $HeartbeatStaleAfterSeconds
            $status = if ($isStale) { "STALE" } else { "HEALTHY" }
            Write-Host ("Worker {0}: {1} | heartbeat {2:u} | summary: {3}" -f $worker.workerName, $status, $lastHeartbeat.UtcDateTime, $worker.lastSummary)
        }
    }
}
else {
    Write-Warning "State file '$StateFilePath' was not found. The app may not have written its first state document yet."
}
