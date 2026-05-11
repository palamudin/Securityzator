# Securityzator Remote Defender Enablement Roadmap

Last reviewed: `2026-04-24`

## Goal

Separate Microsoft Defender setup tasks into the lanes that matter operationally:

- `Remote now`
- `Remote with provider work`
- `Needs server-side deployment`
- `Portal-only or operator-led for now`

This document answers a narrower question than the broader Defender enablement map:

> Can we turn this on remotely from Securityzator or an adjacent automation service, or does it still need portal work or infrastructure deployment?

## Classification rules

### Remote now

- Microsoft documents a supported remote/API or app-only control surface
- the task is tenant-side and does not require logging into a server
- the remaining work is mostly product wiring and validation

### Remote with provider work

- Microsoft supports the feature remotely or semi-remotely
- but Securityzator does not yet have the provider, token model, or state tracking needed to do it well

### Needs server-side deployment

- a server, sensor, package, installer, or local service must be deployed
- tenant-only Graph or portal automation is not enough to complete the task

### Portal-only or operator-led for now

- Microsoft’s documented path is primarily portal-driven
- a public automation surface is unclear, incomplete, or too weak to trust yet

## Executive summary

Best current read:

- strongest remotely reachable next Defender lane: `Defender for Cloud Apps SaaS discovery via Defender for Endpoint integration`
- strongest portal-led next lane: `Microsoft 365 app connector for Defender for Cloud Apps`
- strongest identity/machine-identity maturity lane: `service principal protection via Conditional Access for workload identities`
- clear non-remote boundary: `Defender for Identity onboarding`

## Matrix

| Task | Microsoft product lane | Remote classification | Securityzator read | Current blockers |
| --- | --- | --- | --- | --- |
| Enable service principals protection | Microsoft Entra workload identities / Conditional Access | `Remote with provider work` | Worth building once workload identity inventory and licensing checks exist | Needs Workload Identities Premium, direct service-principal assignment model, inventory, and risk telemetry |
| Connect M365 connector for enhanced detections | Defender for Cloud Apps app connector | `Portal-only or operator-led for now` | High-value onboarding target, but not yet a trusted worker lane | Microsoft documents portal/app-connector flow; no clean Securityzator provider yet |
| Enable on-premises discovery using Defender for Identity | Defender for Identity sensors | `Needs server-side deployment` | Important once AD exists, but not a tenant-only control | Requires sensor package download, access key, server install/activation, and sensor health validation |
| Enable SaaS applications discovery using Defender for Cloud Apps | Defender for Cloud Apps + Defender for Endpoint or log collector | `Remote with provider work` | Best next remote Defender onboarding lane | Needs MDCA provider work and discovery-state tracking in product |

## Per-task notes

### 1. Enable service principals protection

Microsoft-supported path:

- use `Conditional Access for workload identities`
- scope the policy directly to service principals
- optionally use service-principal risk as a condition

Important limits:

- requires `Workload Identities Premium`
- only applies to `single-tenant service principals`
- `managed identities` are out of scope for this policy model
- group assignment does not enforce workload-identity CA; the service principal must be assigned directly

Securityzator implication:

- this is a real remote lane, but not a quick toggle
- before automating it we need:
  - service principal inventory
  - licensing detection or declared capability
  - workload identity risk/readback visibility
  - safe exclusion/rollback decisions for business-critical apps

Recommended product path:

1. add workload identity inventory and posture discovery
2. add read-only visibility into risky service principals
3. add report-only or narrow pilot workload-identity CA
4. promote to enforced protection after validation

### 2. Connect M365 connector for enhanced detections

Microsoft-supported path:

- Defender portal
- `Settings > Cloud Apps > App Connectors > Connect Microsoft 365`

Why it matters:

- improves Defender for Cloud Apps visibility into Microsoft 365 activity
- unlocks SSPM/security recommendations reflected in Secure Score
- supports deeper detections and governance

Securityzator implication:

- high-value, but still onboarding-led
- current product does not have a Defender for Cloud Apps provider
- current Microsoft documentation is portal-centered for this exact connector path

Recommended product path:

1. add MDCA tenant-state detection
2. track whether Microsoft 365 app connector exists and is healthy
3. if Microsoft exposes a stable automation path we trust, add worker execution
4. until then, keep it as a guided onboarding step with readback

### 3. Enable on-premises discovery using Defender for Identity

Microsoft-supported path:

- download sensor package and access key from Defender
- install sensors on domain controllers and other eligible servers
- Microsoft documents silent installation for software deployment systems

Why it matters:

- this is the hard boundary where AD and hybrid telemetry become real
- it unlocks the higher-value AD and AD CS hardening families later

Securityzator implication:

- this is not a tenant-only remote toggle
- we can assist with planning, inventory, readiness checks, and later deployment orchestration
- but the actual onboarding still needs server reach and sensor deployment logic

Recommended product path:

1. keep the current guided onboarding model
2. add AD server inventory and eligibility tracking
3. add sensor deployment-state readback
4. only then decide whether to automate silent installation

### 4. Enable SaaS applications discovery using Defender for Cloud Apps

Microsoft-supported paths:

- integrate `Defender for Endpoint` with `Defender for Cloud Apps`
- deploy a `log collector` on firewalls/proxies
- use the `Cloud Discovery API` to upload traffic logs

Best practical lane:

- `Defender for Endpoint integration`
- Microsoft explicitly describes this as native, low-friction, and “no configuration required” once the integration toggle is available

Securityzator implication:

- this is the best next remote-ish Defender onboarding lane after the current core stack
- it still needs a provider and state tracking in product
- but unlike Defender for Identity, it does not inherently need us to install code on a domain controller first

Recommended product path:

1. detect MDCA licensing and portal/API reachability
2. detect MDE readiness in the tenant
3. add discovery-integration status tracking
4. then add guided enablement or worker-backed automation where the surface is stable

## Securityzator current status

Today the product still treats these as non-runnable or guided lanes:

- `defender-cloud-apps-foundation`
- `defender-identity-foundation`
- `workload-identity-review`

Current catalog read:

- Cloud Apps foundation is still guided onboarding because the platform has no MDCA provider yet
- Defender for Identity foundation is still guided onboarding because sensor deployment is infrastructure work
- workload identity protection is still discovery-first because we do not yet inventory or validate service-principal risk posture

## Recommended execution order

If the goal is maximum remote value before heavy hybrid/server work:

1. `Defender for Cloud Apps SaaS discovery via Defender for Endpoint integration`
2. `Defender for Cloud Apps Microsoft 365 connector`
3. `workload identity / service principal protection`
4. `Defender for Identity sensor rollout` once AD is alive

## Sources

- Microsoft Entra Conditional Access for workload identities:
  - https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity
- Risky service principals API:
  - https://learn.microsoft.com/en-us/graph/api/identityprotectionroot-list-riskyserviceprincipals?view=graph-rest-1.0
- Securing workload identities:
  - https://learn.microsoft.com/en-us/entra/id-protection/concept-workload-identity-risk
- Connect Microsoft 365 to Defender for Cloud Apps:
  - https://learn.microsoft.com/en-us/defender-cloud-apps/protect-office-365
- Connect apps to get visibility and control:
  - https://learn.microsoft.com/en-us/defender-cloud-apps/enable-instant-visibility-protection-and-governance-actions-for-your-apps
- Cloud discovery overview:
  - https://learn.microsoft.com/en-us/defender-cloud-apps/set-up-cloud-discovery
- Cloud discovery API:
  - https://learn.microsoft.com/en-us/defender-cloud-apps/api-discovery
- Defender for Endpoint and Defender for Cloud Apps integration:
  - https://learn.microsoft.com/en-us/defender-endpoint/microsoft-cloud-app-security-integration
- Pilot and deploy Defender for Cloud Apps:
  - https://learn.microsoft.com/en-us/defender-xdr/pilot-deploy-defender-cloud-apps
- Defender for Identity deployment overview:
  - https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-defender-identity
- Download Defender for Identity sensor:
  - https://learn.microsoft.com/en-us/defender-for-identity/deploy/download-sensor
- Install Defender for Identity sensor:
  - https://learn.microsoft.com/en-us/defender-for-identity/deploy/install-sensor
