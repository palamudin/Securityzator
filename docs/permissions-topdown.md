# Securityzator Permissions Topdown Review

Last reviewed: `2026-04-13`

## Goal
Provide one topdown view of the permission stack so we can validate whether the current tech design is still justified and see which permissions are active now versus only kept for roadmap coverage.

## Current minimum application-permission stack

| Surface | Permission | Why Securityzator needs it now | Keep now |
| --- | --- | --- | --- |
| Microsoft Graph | `SecurityEvents.Read.All` | Secure Score collection and recommendation sync | Yes |
| Microsoft Graph | `Group.Read.All` | Group picker, scoped rollout resolution, group-targeted baselines | Yes |
| Microsoft Graph | `Directory.Read.All` | Privileged-user discovery, Entra hygiene assessment, directory role reads | Yes |
| Microsoft Graph | `Policy.Read.All` | Conditional Access and policy posture reads | Yes |
| Microsoft Graph | `Policy.ReadWrite.ConditionalAccess` | Create/update Conditional Access controls | Yes |
| Microsoft Graph | `Application.Read.All` | Conditional Access application-scope targeting such as Azure management | Yes |
| Microsoft Graph | `Policy.ReadWrite.Authorization` | Entra daily-use hardening writes against `authorizationPolicy` | Yes |
| Microsoft Graph | `Policy.ReadWrite.ConsentRequest` | Entra daily-use hardening writes against `adminConsentRequestPolicy` | Yes |
| Microsoft Graph | `Domain.ReadWrite.All` | Entra daily-use hardening writes against default domain password policy | Yes |
| Microsoft Graph | `Organization.Read.All` | Teams PowerShell app-auth prerequisite | Yes if Teams stays in scope |
| Microsoft Graph | `DeviceManagementManagedDevices.Read.All` | Intune readiness and device health assessment | Yes |
| Microsoft Graph | `DeviceManagementConfiguration.Read.All` | Intune configuration/compliance readiness reads | Yes |
| Microsoft Graph | `DeviceManagementConfiguration.ReadWrite.All` | Intune endpoint policy creation and update | Yes |
| Exchange Online | `Exchange.ManageAsApp` | Exchange / Defender for Office unattended automation | Yes |

## Current service-principal role stack

| Role | Why it exists now | Keep now |
| --- | --- | --- |
| `Exchange Administrator` | Required for Exchange / Defender for Office automation | Yes |
| `Teams Administrator` | Required for Teams meeting policy automation | Yes if Teams stays in scope |

## Current human bootstrap role

| Human role | Why it exists | Keep now |
| --- | --- | --- |
| `Global Administrator` | Initial tenant bootstrap, admin consent, service-principal role assignment, workload validation | Yes for bootstrap only |

## Feature-to-permission map

| Feature family | Required permissions and roles |
| --- | --- |
| Secure Score sync | `SecurityEvents.Read.All` |
| Conditional Access baselines | `Policy.Read.All`, `Policy.ReadWrite.ConditionalAccess`, `Group.Read.All`, `Application.Read.All` |
| Entra identity-hygiene assessment | `Directory.Read.All`, `Policy.Read.All` |
| Entra daily-use hardening | `Directory.Read.All`, `Policy.ReadWrite.Authorization`, `Policy.ReadWrite.ConsentRequest`, `Domain.ReadWrite.All` |
| Intune endpoint baselines | `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementConfiguration.ReadWrite.All`, `Group.Read.All` |
| Teams meeting policy automation | `Organization.Read.All`, `Teams Administrator` |
| Exchange / Defender for Office automation | `Exchange.ManageAsApp`, `Exchange Administrator`, automation certificate |

## Roadmap carry-forward permissions

These are still defensible to keep documented, but they are not all required for today’s proven runnable surface.

| Permission | Why it is kept | Keep as roadmap only |
| --- | --- | --- |
| `Device.ReadWrite.All` | Broader device actions beyond current Intune policy lane | Yes |
| `Directory.ReadWrite.All` | Future tenant-setting and directory-write scenarios | Yes |
| `Group.ReadWrite.All` | Future group lifecycle automation | Yes |
| `SecurityAlert.ReadWrite.All` | Future alert-driven remediation or security-ops flows | Yes |
| `User.ReadWrite.All` | Future user-state remediation paths | Yes |

## Current observed tenant gap

The smoke tenant currently proves that the Entra daily-use hardening code path is valid but the app token is still missing the write roles below:

- `Policy.ReadWrite.Authorization`
- `Policy.ReadWrite.ConsentRequest`
- `Domain.ReadWrite.All`

Observed effect:
- Reads against `authorizationPolicy`, `adminConsentRequestPolicy`, `domains`, and `directoryRoles` succeed.
- The first write to `PATCH /policies/authorizationPolicy` fails with `403 Authorization_RequestDenied`.

## Topdown design read

The current stack is still technically coherent:

- Graph is the primary runtime control plane for Entra, Conditional Access, Intune, and Secure Score.
- Exchange and Teams remain special workload lanes that still need their own admin surface plus service-principal role assignment.
- The permission spread is broader than a pure read-only collector, but it matches the fact that Securityzator is now both a posture collector and a remediation engine.
- The roadmap permissions should stay documented, but they should not be treated as mandatory for a minimum viable tenant bootstrap unless the corresponding provider lane is active.

## Recommended review stance

- Keep the current minimum stack for the features already proven runnable.
- Treat the roadmap-only permissions as opt-in until their provider lane is actually implemented.
- Require explicit validation after every permission change so the app token, not just the Entra portal, confirms the change is real.
