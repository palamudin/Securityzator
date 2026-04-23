# Securityzator

Securityzator is a Microsoft 365 tenant hardening platform that started as a browser prototype and is now being rebuilt as an IIS-friendly ASP.NET Core application with a worker-backed remediation engine.

The project’s direction is simple:
- collect Microsoft Secure Score and tenant posture from the backend
- map recommendations into durable playbooks
- let operators launch guarded remediation through audited workflows
- evolve from local/operator bootstrap into a hosted enterprise onboarding model

## What It Does Today

Securityzator already has a real working platform core:
- product sign-in and saved tenant connections
- backend Microsoft Graph authentication and Secure Score sync
- recommendation persistence, filtering, and coverage reporting
- queued remediation jobs with run history and worker heartbeat visibility
- validation of tenant connection readiness across Graph, Intune, Teams, Exchange, and certificate-backed automation lanes

The current proven remediation surface includes:
- Conditional Access quick wins and identity baselines
- Entra identity assessment and the first daily-use hardening lane
- Exchange / Defender for Office baseline slices
- Teams meeting hardening
- Intune-backed Windows endpoint baselines for Defender, firewall/SmartScreen, BitLocker, exploit protection, browser hardening, credential/elevation hardening, and device-health assessment

As of the latest documented validation pass, the platform has:
- `440 / 440` mapped Secure Score controls
- `215 / 440` runnable now
- `225` broader-family mapped controls still awaiting deeper provider coverage

## Architecture

The solution is split into layered projects:
- `src/Securityzator.Web`
  ASP.NET Core MVC web app for operators, connections, recommendations, remediations, and job visibility.
- `src/Securityzator.Worker`
  Background worker that executes queued remediations against the shared control plane.
- `src/Securityzator.Application`
  Contracts and application-layer models for accounts, jobs, recommendations, remediations, connections, and workers.
- `src/Securityzator.Infrastructure`
  Microsoft Graph, Intune, Exchange, Teams, storage, PowerShell, and remediation orchestration implementations.
- `src/Securityzator.Domain`
  Domain-layer anchor project.

Today’s control plane is still file-backed for local and controlled self-hosted rollout. The documented hosted target is:
- browser-based Entra onboarding
- app-only background execution wherever the provider supports it
- delegated admin only for explicit exception flows
- database-backed tenant/workspace storage
- vault-backed secrets and certificate material
- stateless web tier plus worker tier

## Build And Validation

Securityzator is pinned to `.NET SDK 10.0.201` via [global.json](global.json).

Use the stable build path:

```powershell
.\build.ps1
```

That build runs the repository validators automatically:
- `tools/Validate-GraphSourceMap.ps1`
- `tools/Validate-ControlCatalog.ps1`
- `tools/Validate-SecureScoreCoverage.ps1`

## Key Docs

Start here if you want the top-down picture:
- [Deployment Plan](docs/deployment-plan.md)
- [Requirements](requirements.txt)
- [Permissions Topdown Review](docs/permissions-topdown.md)
- [Milestones](docs/milestones.md)
- [Architecture Notes For IIS](docs/architecture-iis.md)
- [Microsoft Graph Source Map Workflow](docs/microsoft-graph-source-map.md)
- [Host Trust And Defender Posture](docs/host-trust-and-defender.md)

## Deployment Modes

Securityzator currently supports two operating models in documentation and code:

### 1. Local Or Managed Operator Bootstrap
Use this when an internal engineer or MSP operator is running the platform on a Windows host. Azure CLI and device-code login are acceptable here as fallback bootstrap tools.

### 2. Hosted Enterprise Service Target
This is the intended product direction. Tenant onboarding should start from the web app through browser-based Entra sign-in and admin consent, then move into mostly app-only execution with delegated exception handling only where Microsoft workload surfaces still require it.

## Current Gaps

Securityzator is already a strong operator tool, but it is not yet a finished client-facing SaaS. The main remaining platform gaps are:
- file-backed state instead of database-backed tenant isolation
- local operator bootstrap instead of full Entra-backed platform identity
- vault-backed secret and certificate handling not yet complete
- some provider lanes still require delegated exception handling
- broader external SaaS, AD-backed, macOS, Linux, SharePoint, Purview, and advanced Defender families still need deeper provider coverage

## Repository Notes

This repo intentionally excludes local secrets, app state, key rings, build output, diagnostic logs, and generated reports through `.gitignore`.

The old prototype reference remains in `POC.html` while the ASP.NET Core platform continues to absorb and replace that functionality with durable backend workflows.
