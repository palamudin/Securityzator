# Worker Recovery Runbook

## Goal

Recover the remediation engine when jobs are not moving and the worker heartbeat in the Jobs page looks stale or stopped.

## Signals

- The Jobs page shows the worker as `Stale`.
- Jobs remain in `Queued` and no healthy worker appears in the heartbeat panel.
- The worker heartbeat has an old timestamp and no recent completion.

## First Checks

1. Confirm the web app is healthy through `/health/live` and `/health/ready`.
2. Confirm the Windows Service exists and is running:
   `Get-Service Securityzator.Worker`
3. Read the latest worker posture from the shared JSON state file.
4. If the worker service is running but the heartbeat is stale, restart the service and watch the Jobs page again.

## Recovery Steps

1. Restart the worker service:
   `Restart-Service Securityzator.Worker`
2. Run the deployment smoke script:
   `powershell -ExecutionPolicy Bypass -File .\deploy\iis\invoke-smoke.ps1 -BaseUrl http://localhost:8080 -StateFilePath C:\ProgramData\Securityzator\Shared\securityzator-state.json`
3. Confirm the heartbeat timestamp advances.
4. Check whether the worker last error points to:
   - Graph permission drift
   - expired or rotated customer secret
   - Conditional Access API failure
   - filesystem/key-ring access problems

## If The Service Will Not Start

1. Confirm the published worker files still exist.
2. Confirm the service account still has access to:
   - the worker publish directory
   - the shared state root
   - the shared key-ring directory
3. Re-run `install-worker-service.ps1` to refresh the binary path, config file, and recovery settings.

## Escalation Trigger

Escalate beyond a simple restart when:

- the worker goes stale repeatedly after restart
- the shared state file cannot be updated
- repeated Graph failures point to tenant-side permission or credential drift
- the worker service account has lost required filesystem access
