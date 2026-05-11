# Securityzator Compliance Posture

Last reviewed: `2026-04-23`

## Purpose

This document describes:

- what data Securityzator traverses today
- where that data currently lands
- the main compliance and enterprise-risk pitfalls in the current architecture
- what the target hosted posture should be before broad multi-client beta or commercial launch

This is an engineering and product risk document, not legal advice.

## Executive summary

Securityzator is already strong as:

- a local or managed operator tool
- a controlled pilot system
- a customer-specific testbed

Securityzator is **not yet compliant-by-design for a large multi-client beta** if “multi-client” means:

- shared hosted environment
- shared storage plane
- real customer tenant data
- production-like operator usage across many organizations

The current main blockers are architectural, not just policy wording:

- file-backed state instead of database-backed tenant isolation
- filesystem-stored key material for secret protection
- local operator auth instead of enterprise identity
- locally persisted run logs and artifacts that may contain tenant identifiers, UPNs, object IDs, and policy/device details
- no formal retention, purge, or customer-by-customer data lifecycle controls

If the opportunity is a controlled beta with a few carefully consented design partners, that can still be workable. If the opportunity is a broad hosted beta across hundreds or thousands of clients, the current posture needs material hardening first.

## What data Securityzator traverses today

### 1. Tenant connection data

Securityzator stores and uses:

- tenant ID
- client ID
- redirect URI
- protected client secret
- declared license capability profile
- automation certificate metadata
  - thumbprint
  - store location
  - store name
  - certificate readiness state

Why it exists:

- to authenticate app-only automation
- to validate workload readiness
- to drive tenant-specific job execution

Important note:

- client secrets are protected, but the protection boundary currently depends on the local app data-protection key ring on the same host family

### 2. Identity and directory metadata

Securityzator reads and may log:

- user principal names
- display names
- user object IDs
- group names and group object IDs
- privileged role membership
- domain names
- service principal and app metadata

Why it exists:

- Conditional Access targeting
- Entra hygiene assessment
- privileged-user discovery
- pilot-group assignment
- emergency-access handling

### 3. Security posture and recommendation data

Securityzator reads and stores:

- Microsoft Secure Score recommendations
- recommendation titles, categories, products, and mapped playbooks
- policy existence and state
- control classification and automation readiness

Why it exists:

- scoring
- remediation planning
- audit trail
- reporting/export

### 4. Endpoint and Intune metadata

Securityzator reads and may store or log:

- managed device counts
- device configuration presence
- compliance policy presence
- device encryption state
- device health or protection state
- device names, IDs, or rollout findings where needed for run evidence

Why it exists:

- endpoint baselines
- rollout verification
- device follow-up reporting

### 5. Exchange / Teams / workload admin data

Securityzator may read or log:

- policy identities
- configuration before/after summaries
- tenant admin provider readiness details
- workload error messages from Microsoft APIs or PowerShell modules

Why it exists:

- baseline application
- validation
- troubleshooting

Important note:

- Securityzator is not designed to ingest mailbox contents, email bodies, SharePoint documents, Teams chat messages, or user file contents in the current architecture
- however, administrative metadata can still be sensitive and customer-identifying

### 6. Operational telemetry and artifacts

Securityzator stores:

- queued jobs
- remediation runs
- validation results
- error summaries
- audit notes
- generated JSON, Markdown, CSV, and HTML artifacts

Examples of sensitive-but-not-secret data in artifacts:

- tenant display names
- tenant GUIDs
- policy IDs
- user principal names
- device states
- configuration readback summaries

## Current data traversal

Today’s typical flow is:

1. operator uses the web app
2. web app reads/writes connection and run state from local JSON-backed storage
3. app-only token is acquired from Microsoft Entra
4. Securityzator calls Microsoft Graph and sometimes Exchange/Teams/PowerShell-backed admin surfaces
5. results are written back into local state plus local artifacts and run logs
6. worker and web app share the same storage and key material assumptions

In local or controlled rollout mode, this is acceptable for engineering speed.

For enterprise hosted delivery, this flow needs to become:

1. operator signs in with enterprise identity
2. tenant onboarding and execution state are stored in a database with tenant/workspace boundaries
3. secrets and cert references are stored in a vault-backed service
4. workers execute app-only actions using tenant-scoped configuration
5. logs and artifacts are redacted, retention-controlled, and tenant-scoped

## Current compliance pitfalls

### 1. Shared JSON state is the biggest blocker

Current reality:

- connections, operators, jobs, runs, recommendations, and worker state are stored in shared JSON documents
- tenant separation exists logically, but not as a strong storage boundary

Risk:

- one storage plane holds many organizations’ metadata
- hard to defend at scale for multi-client hosted beta
- harder to implement strong least-privilege access, retention, backup scoping, and incident response

Current posture:

- acceptable for development and tightly controlled pilot use
- not appropriate for large multi-client hosted beta as-is

### 2. Secret protection depends on local key-ring co-location

Current reality:

- client secrets are protected with ASP.NET data protection
- the key ring is stored on the filesystem

Risk:

- if the same host or deployment boundary exposes both protected data and key material, the practical protection boundary is weaker than a vault-backed design
- this is especially concerning in shared hosted environments

Current posture:

- workable for local or controlled rollout
- not ideal for enterprise multi-client hosting

### 3. Local operator auth is not enterprise-grade identity

Current reality:

- operator access is still file-backed/local-app oriented rather than full Entra operator SSO

Risk:

- weak story for access governance, joiner/mover/leaver control, MFA enforcement, conditional access on the admin plane, and enterprise auditability

Current posture:

- acceptable for internal engineering and narrow pilot
- not strong enough for a serious hosted client-facing service

### 4. Artifacts and logs may contain customer-identifying metadata

Current reality:

- run logs, JSON reports, CSV exports, and debug HTML files can contain:
  - tenant names
  - tenant IDs
  - UPNs
  - policy IDs
  - device state
  - operational error messages

Risk:

- data minimization is incomplete
- redaction is incomplete
- retention is manual
- beta environments could quietly accumulate a lot of customer data if not managed tightly

Current posture:

- useful for engineering
- must be governed much more tightly for multi-client hosting

### 5. No formal retention / deletion model yet

Current reality:

- data persists until manually cleaned up or overwritten
- there is no formal per-tenant retention window, purge workflow, or customer offboarding deletion workflow

Risk:

- weak answer for enterprise procurement, privacy review, and operational governance
- difficult to satisfy customer expectations for beta data cleanup

### 6. No formal tenant-region or residency control

Current reality:

- local filesystem deployment means residency is whatever host or operator machine holds the files

Risk:

- weak answer for regional hosting, data sovereignty, and regulated customers

### 7. Bootstrap fallback paths are operationally sensitive

Current reality:

- local bootstrap can involve Azure CLI, `Auth.txt`, local PowerShell helpers, and delegated administrative flows

Risk:

- very effective for implementation work
- poor primary story for a client-facing hosted platform
- accidental mishandling of bootstrap files or copied credentials is a real operational risk

Important distinction:

- these are acceptable as implementation/support fallbacks
- they should not be the normal customer-facing hosted onboarding model

### 8. Multi-client beta at “2k clients” would change the risk profile drastically

At that scale, the current architecture would create pressure around:

- tenant isolation
- support access boundaries
- artifact sprawl
- storage growth
- backup scope
- incident blast radius
- audit expectations
- customer deletion/export requests

That does not mean the product is not promising.

It means the hosted control plane has to mature before that kind of beta is safe and defensible.

## Current posture: what is defensible now

The current system is defensible for:

- single-tenant internal use
- MSP-managed implementation work
- explicitly consented design-partner pilots
- short-lived test environments
- controlled beta where the hosting and customer expectations are narrow and clearly documented

The current system is **not yet defensible as-is** for:

- broad shared-environment enterprise beta
- large-scale multi-client hosted service
- strong compliance questionnaires about isolation, retention, secret handling, and operator identity

## Target enterprise posture

### Storage and isolation

Target:

- database-backed tenant and workspace model
- strong per-tenant logical isolation at the storage boundary
- role-based access mediated by the database and service layer, not just shared JSON ownership checks

### Secret and certificate handling

Target:

- vault-backed client secret storage
- vault-backed certificate/private-key strategy or HSM-backed equivalent where appropriate
- no reliance on colocated filesystem key rings as the main protection boundary

### Operator identity

Target:

- Microsoft Entra login for platform operators
- enterprise MFA and Conditional Access on the admin plane
- auditable RBAC per workspace/customer

### Audit and logging

Target:

- structured audit trail
- tenant-scoped log views
- redaction/minimization for identifiers where practical
- retention controls
- artifact expiration or archive rules

### Data lifecycle

Target:

- documented retention periods
- per-tenant deletion workflow
- customer offboarding cleanup path
- export path for customer audit evidence where needed

### Hosting model

Target:

- stateless web tier
- separate worker tier
- database-backed queue/control plane
- defined region/residency story
- environment separation for dev, pilot, beta, and production

### Customer onboarding

Target:

- browser-based Entra interactive sign-in
- in-product admin consent
- app-only execution after bootstrap
- delegated admin only for explicit exception paths

## Recommended beta policy before broad rollout

If Securityzator enters a real beta soon, the minimum sane posture is:

### Allowed beta shape

- named design partners only
- explicit consent that the service is beta
- clear statement that the platform is still maturing toward full hosted enterprise posture
- no silent shared-environment assumptions

### Minimum technical guardrails

- separate environment from development day-to-day noise
- no use of loose `Auth.txt`-style workflows in the normal hosted path
- strict `.gitignore` and artifact hygiene
- encrypted host volumes
- limited operator access
- documented log retention and cleanup cadence
- no unnecessary customer artifacts retained after validation runs

### Operational guardrails

- one documented incident-response owner
- one documented backup owner
- one documented deletion/offboarding owner
- customer list with environment placement and data-handling notes

## Recommended pre-launch backlog

Highest priority:

1. Database-backed tenant/workspace storage
2. Vault-backed secret and certificate handling
3. Entra operator login and RBAC
4. Artifact/log retention and cleanup rules
5. Tenant onboarding wizard replacing local bootstrap as the normal path

Second priority:

6. Customer-by-customer audit export and deletion flows
7. Region/residency and hosting topology definition
8. Explicit delegated-exception handling model
9. Better redaction/minimization of logs and artifacts

## Practical decision guidance

### If the opportunity is a small, friendly beta

Securityzator can likely participate if:

- customers understand it is a beta
- environments are controlled
- data handling is documented
- access is restricted
- artifact retention is manually managed

### If the opportunity is a large multi-client beta

Do not treat the current architecture as enough.

Before accepting that shape, finish at least:

- database-backed tenant isolation
- vault-backed secrets
- enterprise operator identity
- retention/purge controls

## Short version

Securityzator is already proving strong security outcomes technically.

The compliance gap is not about whether the controls work. It is about whether the platform can host **many customers’ administrative metadata, secrets, logs, and audit trails** in a way that is cleanly isolated, governable, and easy to defend in enterprise review.

Today:

- promising
- useful
- pilotable
- not yet ready for large shared hosted beta at scale

Target:

- browser-based onboarding
- app-only execution
- database-backed tenant isolation
- vault-backed secret handling
- enterprise operator identity
- retention and deletion controls
