# Securityzator Milestones

## Milestone 1 - Foundation

Status: started

Scope:

- Create the IIS-friendly ASP.NET Core solution.
- Add the layered project structure.
- Add the web shell for dashboard, connections, recommendations, remediations, and jobs.
- Add a worker host placeholder for future queued execution.
- Document the architecture and deployment path.
- Add a deterministic local build path for the current toolchain.

Exit criteria:

- The solution exists beside the original `POC.html`.
- The new web UI explains the product shape and planned port.
- The codebase is ready for milestone 2 without continuing to expand the prototype file.

## Milestone 2 - Identity And Azure Connections

Status: started

Scope:

- Product login and session handling.
- Connection creation workflow for tenant ID, app ID, app secret, and redirect URI.
- Server-side validation and secret masking.
- Persistence model for workspaces and connection records.

Exit criteria:

- An authenticated user can create, edit, and review a connection profile safely.
- The app owns operator auth and no longer relies on browser-side prototype configuration.

## Milestone 3 - Recommendation Collection

Status: started

Scope:

- Microsoft Graph client in the backend.
- Secure Score profile collection with pagination support.
- Persistence for sync snapshots and recommendation records.
- UI for browsing and filtering recommendations.

Exit criteria:

- The new portal can sync and display recommendations without using `POC.html`.

## Milestone 4 - Quick Win Port

Status: started

Scope:

- Port the "Block legacy authentication" quick win into a formal playbook.
- Add the next runnable Conditional Access playbook for requiring MFA on privileged admin groups.
- Add report-only Conditional Access rollout paths for MFA on all users and phishing-resistant MFA on privileged admin groups.
- Add the first Defender-oriented non-Conditional-Access execution slice for Safe Links and Safe Attachments through Exchange Online PowerShell app-only automation.
- Add the first non-Conditional-Access execution slice for the Teams meeting hardening baseline.
- Replace prompt-based input gathering with proper form validation.
- Record launch inputs, results, and any created policy IDs.

Exit criteria:

- Operators can run the proven quick wins from the new app through a controlled server-side flow.
- The Conditional Access identity slice covers legacy auth blocking, privileged-admin MFA, all-user MFA, and phishing-resistant privileged-admin MFA in report-only mode with worker/audit support.
- The first Defender-oriented provider can update Safe Links, Safe Attachments, and SharePoint/OneDrive/Teams mail protection with worker/audit support.
- The first non-Conditional-Access provider can update the Global Teams meeting policy baseline with worker/audit support.

## Milestone 5 - Queue And Audit

Status: started

Scope:

- Background execution pipeline.
- Job state tracking and retry logic.
- Operator-visible run logs.
- Audit history for who launched what and when.

Exit criteria:

- Remediation runs are durable, observable, and no longer depend on a live browser tab.

## Milestone 6 - Hardening

Status: started

Scope:

- RBAC and approval gates.
- Secret rotation posture.
- Production deployment playbooks.
- Monitoring, health checks, and recovery guidance.
- Live validation of saved tenant connections against the Graph surfaces the product actually uses.
- Optional Windows automation-certificate readiness for Exchange, SharePoint, Purview, and future PowerShell-backed providers.
- Worker heartbeat visibility so operators can tell when the background remediation engine is healthy, busy, or stale.

Exit criteria:

- Securityzator is ready for controlled enterprise rollout behind IIS.
- Operators can see whether a saved tenant profile still authenticates, which Graph capabilities are reachable, and whether its secret is aging toward rotation.
- Operators can attach a Windows certificate binding to a tenant profile and validate whether the server host is ready for the next non-Graph Microsoft 365 admin providers.
- Operators can distinguish a healthy idle queue from a silent worker failure by checking the Jobs console heartbeat and last-known worker outcome.
