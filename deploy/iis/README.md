# IIS Deployment Notes

Securityzator now has a deployment automation path for IIS plus the worker service. The current production posture intentionally keeps state on the filesystem in shared JSON until the product is ready to move into Azure-hosted database storage.

## Target Model

- IIS hosts `Securityzator.Web`.
- `Securityzator.Worker` runs as a Windows Service.
- Shared JSON state and the data-protection key ring live outside the web root, by default under `C:\ProgramData\Securityzator\Shared`.

## Scripts

- `publish.ps1`
  Publishes both the web app and worker into `artifacts\publish\iis`.
- `install-web.ps1`
  Syncs published web output into the IIS site root, writes `appsettings.Production.json`, creates or updates the IIS app pool and site, and points the web app at the shared JSON/key-ring location.
- `install-worker-service.ps1`
  Syncs published worker output, writes `appsettings.Production.json`, creates or updates the Windows Service, configures restart-on-failure behavior, and points the worker at the same shared JSON/key-ring location.
- `invoke-smoke.ps1`
  Checks `/health/live`, `/health/ready`, and summarizes connection/job/worker posture from the shared state file.

## Typical Flow

```powershell
Set-Location C:\path\to\Securityzator

powershell -ExecutionPolicy Bypass -File .\deploy\iis\publish.ps1

powershell -ExecutionPolicy Bypass -File .\deploy\iis\install-web.ps1 `
  -SiteName Securityzator `
  -AppPoolName Securityzator `
  -WebRoot C:\inetpub\Securityzator\Web `
  -SharedDataRoot C:\ProgramData\Securityzator\Shared `
  -Protocol http `
  -Port 8080

powershell -ExecutionPolicy Bypass -File .\deploy\iis\install-worker-service.ps1 `
  -WorkerRoot C:\Services\Securityzator\Worker `
  -SharedDataRoot C:\ProgramData\Securityzator\Shared `
  -StartService

powershell -ExecutionPolicy Bypass -File .\deploy\iis\invoke-smoke.ps1 `
  -BaseUrl http://localhost:8080 `
  -StateFilePath C:\ProgramData\Securityzator\Shared\securityzator-state.json
```

## Web Server Checklist

- Install the matching ASP.NET Core Hosting Bundle for the runtime you choose to deploy.
- Run the web app in an IIS app pool with `No Managed Code`.
- Prefer a 64-bit application pool unless a later dependency forces otherwise.
- Bind HTTPS at the IIS layer before putting the service on the public internet.
- Keep all Graph access server-side. The browser should never handle the saved client secret.

## Worker Service Notes

- The worker now supports Windows Service hosting and reports heartbeats back into shared state.
- The install script configures delayed auto-start and restart-on-failure recovery actions.
- The Jobs page exposes worker freshness, current work, and last-known outcome so operators can tell the difference between a healthy idle worker and a stale one.

## Filesystem State Today

Until the Azure database move happens, both the web app and worker point to:

- `securityzator-state.json`
- `keyring\`

under the shared data root. This keeps deployment simple and predictable while the product remains in controlled rollout mode.

## Important

The repository is pinned to `.NET SDK 10.0.201` via `global.json`. Install the matching runtime and IIS Hosting Bundle on the target servers before deployment.
