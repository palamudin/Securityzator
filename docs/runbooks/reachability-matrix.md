# Reachability Matrix

Last reviewed: `2026-04-23`

## Executive summary

This matrix answers the practical question:

> How many mapped controls can Securityzator actually reach now on the current tenant, after the latest fixes and live retests?

Current answer:

- `440` total mapped controls
- `215` catalog-runnable controls
- `202` live-reachable controls on the current tenant
- `13` catalog-runnable controls still blocked live on the current tenant
- `225` broader-family mapped controls that are still not in a real execution lane

## Definitions

- `Catalog runnable`
  - the control family is wired into a queueable template and counts toward the current `215 / 440` runnable figure
- `Live reachable`
  - the family has been executed or revalidated successfully on the current tenant, or is a working assessment slice
- `Operationally improved`
  - the change set did not increase the formal runnable count, but it made the lane materially more usable or more resilient in real execution
- `Live blocked`
  - the family is still queueable in code, but the current tenant or provider surface still stops it from completing reliably

## Top-level matrix

| Area | Template / family | Mapped controls | Catalog runnable | Current tenant status | Claude-change impact | Notes |
| --- | --- | ---: | --- | --- | --- | --- |
| Identity | `block-legacy-auth` | 1 | Yes | Live reachable | None material | Already enabled and live-validated. Secure Score still lags. |
| Identity | `entra-risk-policies` | 2 | Yes | Live reachable | None material | Package already enabled. Microsoft score feed still stale. |
| Identity | `entra-daily-use-hardening` | 1 | Yes | Live reachable | None material | Strict no-user-consent posture now working app-only. |
| Identity | `entra-identity-hygiene-baseline` | 13 | Yes | Live reachable | None material | Working tenant-wide assessment slice. |
| Identity | `entra-low-impact-app-consent` | 0 direct mapped | Extra template | Live reachable | Material | Useful operator lane, but not counted as extra mapped reach. |
| Endpoint | Intune all-devices-capable baselines | 129 | Yes | Live reachable | Major | Biggest practical win in this change set. Removes the pilot-group prerequisite for the 10 endpoint families below. |
| Endpoint | `defender-endpoint-browser-and-adobe-policy-surface-readiness` | 6 | Yes | Live reachable | None material | Honest assessment slice, still not a full enforcement lane. |
| Apps / Exchange | `mdo-anti-phishing-and-impersonation` | 17 | Yes | Live reachable with follow-up | Major | Session handling is much more durable now. Protected-user seed list still needs operator follow-up in trimmed Exchange sessions. |
| Apps / Exchange | `mdo-anti-malware-baseline` | 2 | Yes | Live reachable | Major | Now a first-class executable lane instead of a stub. |
| Apps / Exchange | `mdo-spam-and-forwarding-baseline` | 16 | Yes | Live reachable | Minor | Still working; not the main beneficiary of this patch set. |
| Apps / Exchange | `exchange-online-collaboration-and-mailbox` | 9 | Yes | Live reachable | Minor | Still working; more stable with full Exchange module load. |
| Apps / Exchange | `mdo-safe-links-and-attachments` | 6 | Yes | Live blocked | Partial only | Still fails on missing `Get-AtpPolicyForO365` in the current Exchange session surface. |
| Apps / Teams | `teams-meeting-hardening` | 7 | Yes | Live blocked | None material | Still blocked by tenant-side authorization error `40301`. |
| Backlog | Broader-family mapped only | 225 | No | Not yet reachable | None | Still mapped for routing/reporting, but not in a real execution lane yet. |

## The 10 Intune families that gained all-devices reach

These were already in the runnable catalog, but the latest change set makes them materially easier to deploy because they no longer require a pre-created include group.

| Template | Mapped controls | Status now |
| --- | ---: | --- |
| `defender-endpoint-core-protection` | 15 | Live reachable, now all-devices-capable |
| `defender-endpoint-firewall-and-smartscreen` | 11 | Live reachable, now all-devices-capable |
| `defender-endpoint-exploit-protection` | 2 | Live reachable, now all-devices-capable |
| `defender-endpoint-bitlocker-baseline` | 5 | Live reachable, now all-devices-capable |
| `defender-endpoint-credential-and-elevation-hardening` | 11 | Live reachable, now all-devices-capable |
| `defender-endpoint-remote-access-and-network-hardening` | 15 | Live reachable, now all-devices-capable |
| `defender-endpoint-browser-hardening` | 4 | Live reachable, now all-devices-capable |
| `defender-endpoint-attack-surface-reduction` | 26 | Live reachable, now all-devices-capable |
| `defender-endpoint-os-security-baseline` | 35 | Live reachable, now all-devices-capable |
| `defender-endpoint-sensor-and-agent-health` | 5 | Live reachable assessment, now all-devices-capable |

Subtotal improved by all-devices support: `129`

## Practical reach delta from this change set

The latest patch set does **not** change the official coverage number from `215`.

What it does change in practice:

- `129` endpoint controls now have a no-group deployment path
- `17` anti-phish controls now sit on a much sturdier live Exchange lane
- `2` anti-malware controls now have a real first-class execution lane

That gives `148` mapped controls whose **operational reach improved materially**, even though the formal catalog count stayed flat.

## Current live blockers inside the runnable set

These are the `13` mapped controls that still count as runnable in the catalog, but are not cleanly reachable on the current tenant today:

- `mdo-safe-links-and-attachments` = `6`
  - blocker: Exchange session surface still does not expose `Get-AtpPolicyForO365`
- `teams-meeting-hardening` = `7`
  - blocker: Teams automation still fails with tenant-side authorization error `40301`

## Evidence anchors

- Anti-phish retest:
  - `artifacts/runlogs/claude-review-20260423/mdo-anti-phishing-and-impersonation.json`
- Safe Links / Safe Attachments retest:
  - `artifacts/runlogs/claude-review-20260423/mdo-safe-links-and-attachments.json`
- Anti-malware retest:
  - `artifacts/runlogs/claude-review-20260423/mdo-anti-malware-baseline.json`
- Teams blocker:
  - `artifacts/runlogs/manifest-push-20260423/teams-meeting-hardening.json`
- Coverage baseline:
  - `tools/Validate-SecureScoreCoverage.ps1`

## Bottom line

If the question is:

> how many controls can we really reach now, after these fixes?

The best practical answer is:

- `202` mapped controls are currently reachable on this tenant
- `148` of those benefited materially from the latest change set
- `13` are still queueable on paper but blocked live
- `225` are still mapped-only backlog
