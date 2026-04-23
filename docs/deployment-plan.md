# Securityzator Deployment Plan

Last reviewed: `2026-04-13`

## Goal
Move Securityzator from a strong local/self-hosted operator tool into a client-facing enterprise service that can onboard a tenant through browser-based admin consent, align prerequisites, and then run mostly app-only automation per customer.

## Deployment modes

### Mode 1. Local or managed operator bootstrap
Use this when Securityzator is being run by an internal operator, MSP engineer, or implementation team on a Windows host.

Characteristics:
- Windows-host-local modules are acceptable
- Azure CLI and device code can be used as a bootstrap fallback
- local certificate store access is acceptable
- shared filesystem state is acceptable for development or controlled rollout

### Mode 2. Hosted enterprise service target
Use this for the long-term product direction: multi-customer or per-customer hosted delivery with client-facing onboarding.

Characteristics:
- browser-based Microsoft Entra interactive sign-in
- tenant admin consent initiated from inside the product
- app-only background execution wherever the provider supports it
- just-in-time delegated exception handling only for the workloads that still need it
- database-backed tenant data isolation
- vault-backed secret and certificate material
- stateless web tier plus worker tier

## Control planes

### 1. Bootstrap plane
Purpose:
- let a tenant admin onboard the customer tenant from the product UI
- create or align the Securityzator app footprint
- grant consent and required directory roles
- persist tenant configuration into the platform data store

Hosted best-practice target:
- browser redirect or popup sign-in with Microsoft Entra ID
- admin-consent flow from the app
- no stored Global Administrator username/password
- no Azure CLI dependency in the client-facing path

### 2. App-only execution plane
Purpose:
- run recurring collection, validation, and remediation jobs without a user present
- use the app identity and least-privilege application permissions

Hosted best-practice target:
- worker services use app-only tokens
- secrets and cert references come from managed secret storage
- jobs, runs, and tenant metadata come from a database-backed control plane

### 3. Delegated exception plane
Purpose:
- handle the shrinking set of provider actions that still do not support clean app-only automation

Hosted best-practice target:
- prompt an authorized tenant admin for just-in-time approval or sign-in
- do not treat this as standing impersonation
- keep these exceptions explicit in the UI and audit trail

## Current host inventory

| Area | Requirement | Current host state | Status |
| --- | --- | --- | --- |
| Operating model | Windows host capable of IIS + Windows services | Current repo host is Windows and is being used for local web/worker automation | Ready for local mode |
| .NET SDK | `10.0.201+` | `10.0.201` | Ready |
| ASP.NET Core runtime | `10.0.5+` | `10.0.5` | Ready |
| PowerShell 7 | `pwsh` on path | `C:\Users\Enforcer\AppData\Local\Microsoft\WindowsApps\pwsh.exe` | Ready |
| Windows PowerShell | Present for older modules | Current shell is Windows PowerShell | Ready |
| Azure CLI | `az` on path for delegated bootstrap fallback | Not detected on `PATH` in this validation pass | Needs attention for local bootstrap |
| Exchange module | `ExchangeOnlineManagement` | `3.9.2` installed | Ready |
| Teams module | `MicrosoftTeams` | `7.7.0` installed | Ready |
| Graph bootstrap module | `Microsoft.Graph.Authentication` | `2.36.1` installed | Ready |
| Automation certificate | Bound in host store and app registration | Reference cert recorded in `requirements.txt` | Ready on this host |

## Hosted rollout phases

### Phase 1. Platform foundation
- replace file-backed state with database-backed tenant/workspace storage
- move secret and certificate handling behind a vault-backed boundary
- keep the web tier stateless
- keep the worker tier separate from browser sessions

### Phase 2. Enterprise identity for operators
- replace local operator/password bootstrap with Microsoft Entra login
- support tenant-aware workspace membership and authorization
- keep cookie/session handling only as the web session wrapper, not as the identity source

### Phase 3. Tenant onboarding wizard
- start onboarding from inside the product UI
- redirect the tenant admin to Microsoft Entra sign-in
- request admin consent for required application permissions
- create or align the Securityzator service principal footprint
- bind redirect URIs, certificates, and per-tenant config
- persist tenant config in the database

### Phase 4. Tenant readiness and alignment
- run connection validation after onboarding
- check Graph, Intune, Entra daily-use write readiness, Teams readiness, Exchange readiness, and certificate posture
- surface missing permissions, roles, licensing gaps, and workload gaps before any enforcement

### Phase 5. Pilot execution
- start with assessment-first and report-only slices where supported
- use pilot groups for endpoint and risky tenant-wide changes
- keep justifications, approvals, and logs on every launch

### Phase 6. Broad rollout
- expand from pilot to approved production scope
- keep app-only automation as the default
- use delegated exception handling only where a provider still requires it

## Local bootstrap fallback

This path remains valid for internal rollout, support, and break-glass operations, but it is not the primary hosted onboarding model.

Fallback flow:
1. install .NET, `pwsh`, Azure CLI, and required modules
2. confirm the automation certificate is present locally
3. run `.\build.ps1`
4. sign in with Azure CLI if needed:
   - `az login --tenant <tenant-id> --allow-no-subscriptions --use-device-code`
5. run the bootstrap script or targeted helpers
6. validate the saved connection from the app
7. run smoke tests for the first baselines

## Module and tool matrix

| Area | Required module or tool | Why it exists | Hosted target stance |
| --- | --- | --- | --- |
| Repo build and diagnostics | `dotnet` | Build, smoke runner, validation | Keep |
| Delegated local bootstrap fallback | `az` | Temporary tenant bootstrap fallback | Fallback only |
| Delegated Graph helpers | `Microsoft.Graph.Authentication` | Permission and role stamping helpers | Fallback only |
| Exchange / Defender for Office | `ExchangeOnlineManagement` | Exchange-backed admin automation | Worker-host only |
| Teams automation | `MicrosoftTeams` | Teams policy automation | Worker-host only |
| Entra / Conditional Access runtime | built-in app Graph calls | Main runtime lane | Keep |
| Intune / endpoint runtime | built-in app Graph calls | Main runtime lane | Keep |

## What blocks seamless hosted delivery today

- local file-backed state instead of database-backed tenant isolation
- local operator accounts instead of enterprise identity
- shared filesystem data-protection and app state assumptions
- local certificate-store dependency for some workload providers
- Azure CLI and `Auth.txt`-style bootstrap assumptions still present in the operator flow
- some workloads still need delegated exception handling rather than pure app-only execution

## Production definition of done

Securityzator is ready for enterprise hosted delivery when:
- the onboarding flow starts in-browser and does not require Azure CLI for the normal customer path
- tenant config, jobs, runs, and operator/workspace membership are database-backed
- secrets and certificates are vault-backed
- the web tier is stateless
- workers can scale independently
- app-only automation is the default for supported providers
- delegated exception handling is explicit, auditable, and limited to unsupported provider surfaces
