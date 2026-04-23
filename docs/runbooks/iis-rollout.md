# IIS Rollout Runbook

## Goal

Publish and deploy Securityzator behind IIS while the platform still uses shared JSON state.

## Prerequisites

- .NET runtime and ASP.NET Core Hosting Bundle matching the repo SDK/runtime line
- IIS installed with the management tools
- An HTTPS termination plan at the IIS layer before internet exposure
- A shared filesystem location for:
  - `securityzator-state.json`
  - data-protection key ring files

## Deployment Steps

1. Publish the web and worker:
   `powershell -ExecutionPolicy Bypass -File .\deploy\iis\publish.ps1`
2. Install or update the IIS web site:
   `powershell -ExecutionPolicy Bypass -File .\deploy\iis\install-web.ps1`
3. Install or update the worker service:
   `powershell -ExecutionPolicy Bypass -File .\deploy\iis\install-worker-service.ps1 -StartService`
4. Run the smoke script:
   `powershell -ExecutionPolicy Bypass -File .\deploy\iis\invoke-smoke.ps1 -BaseUrl http://localhost:8080 -StateFilePath C:\ProgramData\Securityzator\Shared\securityzator-state.json`

## Expected Outcome

- `/health/live` returns healthy
- `/health/ready` returns healthy
- the shared state file exists
- the Jobs page shows a healthy worker heartbeat
- the Connections page can validate at least one saved tenant profile

## Current Storage Posture

This rollout path intentionally keeps state on the server filesystem until Securityzator is ready to move to Azure-hosted database storage. The install scripts write production config files that point both processes at the same shared JSON state and key-ring location.
