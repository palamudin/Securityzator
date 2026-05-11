# Securityzator Defender Enablement Map

Last reviewed: `2026-04-23`

## Goal

Map Microsoft Defender security features that are worth enabling next, using Microsoft’s current documentation as the source of truth, and separate them into:

- `Ready now`
- `Ready with portal-driven onboarding`
- `Session-surface blocked`
- `Onboarding-dependent`

This document is intentionally broader than the current Securityzator automation surface. The point is to keep a top-down Defender map of what we can still turn on for security value, even when a specific lane is not yet fully automated in product.

Related remote-execution reference:

- `docs/runbooks/remote-defender-enablement-roadmap.md`

## Scope

This map focuses on:

- Microsoft Defender for Office 365
- Microsoft Defender for Cloud Apps
- Microsoft Defender for Endpoint
- Microsoft Defender for Identity

It does not try to cover every Microsoft 365 compliance feature. It is a practical security-first map.

## Best current read

The strongest immediate Defender value is still in `Defender for Office 365`, especially:

- preset security policies
- anti-phishing
- anti-spam / outbound spam
- Safe Links
- Safe Attachments
- collaboration protection for SharePoint / OneDrive / Teams
- user reporting and quarantine experience

After that, the next biggest security-value lanes are:

- Defender for Cloud Apps app governance
- Defender for Endpoint onboarding / expanded endpoint coverage
- Defender for Identity sensor rollout once AD exists

## Licensing read

Important licensing checkpoints from Microsoft’s documentation:

- Defender for Office 365 Plan 1 or Plan 2 unlocks the advanced mail, link, attachment, and collaboration protections discussed here.
- Attack simulation training and some priority-account features are Plan 2 / E5 class features.
- Defender for Cloud Apps app governance needs Defender for Cloud Apps.
- Defender for Identity obviously needs Defender for Identity plus sensor deployment.

## Ready now: high-value Defender for Office 365 items

### 1. Preset security policies

Why it matters:

- Microsoft repeatedly recommends `Standard` or `Strict` preset security policies as the fastest best-practice baseline.
- Presets pull together anti-spam, anti-malware, anti-phishing, Safe Links, and Safe Attachments with Microsoft-recommended values.

Securityzator read:

- This is one of the highest-leverage portal-native enablement paths.
- It is especially attractive for a fresh E5 tenant because it can close a lot of mail-security distance quickly without lots of custom-policy drift.

Notes:

- Built-in protection already provides some Safe Links and Safe Attachments coverage by default for uncovered recipients.
- Preset policy precedence matters when mixing presets and custom policies.

### 2. Anti-phishing policy

Why it matters:

- Anti-phishing is one of the strongest next lifts for both protection and likely score movement.
- Microsoft’s docs make it clear that the default anti-phishing policy does not expose all impersonation and threshold protections by default.

Important targeting model:

- recipient targeting can use users, groups, and domains
- impersonation protection can target protected users and protected domains
- exceptions are first-class and matter for usability

Securityzator read:

- Our current product model should treat anti-phish as a first-class wizard surface, not a single toggle.
- The model needs:
  - recipient scope
  - protected users
  - protected domains
  - trusted senders / domains exceptions
  - action settings

Current blocker:

- the current delegated Exchange session on this tenant still exposes a reduced anti-phish cmdlet surface
- recent failures:
  - `MailboxIntelligenceProtectionAction`
  - `EnableTargetedDomainsProtection`

Interpretation:

- this is still an `Exchange Online PowerShell session-surface` issue, not a Graph problem
- Microsoft’s docs still point to Defender portal and Exchange Online PowerShell, not Graph, for this area

### 3. Anti-spam and outbound spam

Why it matters:

- this is a real tenant-wide mail protection lane
- it is broad, understandable, and likely to produce meaningful posture improvement quickly

Securityzator read:

- this lane is working again
- the delegated helper is currently the dependable path
- Securityzator found and fixed the Exchange rule-update bug on `2026-04-23`

Current status:

- `Workable now`

### 4. Safe Links

Why it matters:

- protects email clicks
- protects Teams links
- protects Office app links
- can track clicks and block click-through to malicious URLs

Recommended practical settings:

- enable Safe Links for email
- enable Safe Links for Teams
- enable Safe Links for Office apps
- keep click tracking on
- do not allow click-through to malicious URLs unless there is a specific business reason

Securityzator read:

- high-value next Defender lane
- still blocked in current automation because the Exchange session surface is inconsistent

Current blocker:

- our delegated Safe Links / Safe Attachments helper still fails when `Set-AtpPolicyForO365` is missing from the session

### 5. Safe Attachments

Why it matters:

- adds detonation/sandboxing against harmful attachments
- supports email plus separate collaboration coverage

High-value companion setting:

- turn on Safe Attachments for SharePoint, OneDrive, and Microsoft Teams

Securityzator read:

- worth prioritizing on fresh E5 tenants
- currently grouped with the same session-surface problem as Safe Links

### 6. Microsoft Teams protection

Why it matters:

- Defender for Office 365 now covers Teams more broadly
- ZAP for Teams is a real protection layer
- user reporting in Teams is now part of the Defender story

Securityzator read:

- this is a meaningful next portal/Defender surface even if Teams PowerShell policy automation already exists elsewhere in the product
- mail-only thinking is too narrow now; Defender for Office 365 is increasingly a collaboration-protection surface

### 7. User reported settings

Why it matters:

- makes phishing/junk reporting part of the defense loop
- feeds Microsoft and tenant-side triage
- works for Outlook and now also Teams

High-value settings:

- route reported items to Microsoft
- optionally also route to a reporting mailbox
- decide whether to ask users for confirmation before reporting

Securityzator read:

- this is a very practical security feature to expose in product
- it improves response quality, not just prevention

### 8. Quarantine policies and notifications

Why it matters:

- determines whether users can preview/release messages
- controls quarantine notifications
- supports the operational side of ZAP and policy verdicts

Securityzator read:

- not glamorous, but this matters a lot for production acceptance
- strong candidate for a wizard step after mail protections are enabled

### 9. ZAP

Why it matters:

- post-delivery automated cleanup
- applies to email and Teams

Securityzator read:

- good “defense depth” win
- not always the flashiest score item, but strong practical protection

## Ready with Defender portal or product onboarding

### 10. Priority account protection

Why it matters:

- gives differentiated protection to tagged executive/high-risk accounts

Securityzator read:

- especially useful if we are already protecting admins and executives through CA
- this should become a simple “tag priority users” step in the future wizard

Licensing note:

- this is a Plan 2 / E5 class feature

### 11. Attack simulation training

Why it matters:

- useful for resilience and user hardening
- not a direct prevention toggle, but still security-value dense

Securityzator read:

- worth exposing eventually
- not the fastest road-to-70 control, but excellent for post-baseline maturity

Licensing note:

- Plan 2 / E5 class feature

## Onboarding-dependent Defender items

### 12. Defender for Cloud Apps

Why it matters:

- gets us into OAuth app governance, cloud discovery, governance actions, and broader SaaS security

High-value first actions:

- turn on app governance
- connect Microsoft 365 connector
- review/create app governance policies
- integrate cloud discovery with Defender for Endpoint where possible

Securityzator read:

- this is likely one of the strongest medium-term `Apps` category plays
- it is not just a toggle; it needs onboarding, connectors, and policy decisions

### 13. Defender for Endpoint onboarding

Why it matters:

- the endpoint baselines are strongest when the devices are actually onboarded to Defender for Endpoint

Securityzator read:

- we already have a lot of Intune baseline coverage
- the next value is less about more settings and more about confirmed Defender onboarding + sensor health + policy coverage

### 14. Defender for Identity

Why it matters:

- high-value hybrid/on-prem identity protection once AD exists

Securityzator read:

- this remains blocked on having actual AD and servers to instrument
- once that exists, sensor deployment should become a major priority

## Current Securityzator implementation read

### Strong working lanes

- app-only Entra policy assessment and daily-use hardening
- app-only Conditional Access
- app-only Intune / Windows Defender baselines
- delegated Exchange spam / outbound forwarding

### Partially working or blocked Defender lanes

- anti-phish:
  - `Implemented`
  - blocked by reduced Exchange session parameter surface
- Safe Links / Safe Attachments:
  - `Implemented`
  - blocked by Exchange session shape, especially missing `Set-AtpPolicyForO365`
- Defender for Cloud Apps:
  - mapped conceptually
  - not yet a full provider/onboarding lane in product
- Defender for Identity:
  - mapped conceptually
  - blocked until AD exists

## Recommended next Defender execution order

### For immediate protection/value

1. Standard or Strict preset security policies
2. anti-phishing model redesign in Securityzator
3. Safe Links / Safe Attachments plus collaboration protection
4. Teams protection, user reported settings, and quarantine tuning

### For next-wave `Apps` and enterprise maturity

5. Defender for Cloud Apps app governance
6. Defender for Endpoint onboarding completion
7. priority account protection
8. attack simulation training
9. Defender for Identity once AD is present

## Product implication

Defender for Office 365 should not be modeled in Securityzator as a single “mail protection baseline” forever.

It wants to become a grouped wizard with at least these slices:

- Preset or custom strategy
- Anti-phish
- Spam / outbound
- Safe Links
- Safe Attachments
- Collaboration protection
- Teams protection
- User reporting and quarantine experience
- Priority accounts and training

That shape will be much closer to Microsoft’s real Defender operating model than the current narrower Exchange-baseline framing.

## Source anchors

- Recommended settings for EOP and Defender for Office 365:
  - https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365
- Preset security policies:
  - https://learn.microsoft.com/en-gb/defender-office-365/preset-security-policies
- Anti-phishing policies:
  - https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-mdo-configure
- Safe Links:
  - https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure
  - https://learn.microsoft.com/en-us/defender-office-365/safe-links-about
- Safe Attachments:
  - https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-policies-configure
  - https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-for-spo-odfb-teams-configure
- User reported settings:
  - https://learn.microsoft.com/en-us/defender-office-365/submissions-user-reported-messages-custom-mailbox
  - https://learn.microsoft.com/en-us/defender-office-365/submissions-teams
- Zero-hour auto purge:
  - https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-purge
- Microsoft Teams protection:
  - https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/mdo-support-teams-about?view=o365-worldwide
- Priority account protection:
  - https://learn.microsoft.com/en-us/defender-office-365/priority-accounts-turn-on-priority-account-protection
- Attack simulation training:
  - https://learn.microsoft.com/en-us/defender-office-365/attack-simulation-training-get-started
- Defender for Cloud Apps:
  - https://learn.microsoft.com/en-us/defender-cloud-apps/get-started
  - https://learn.microsoft.com/en-us/defender-cloud-apps/app-governance-get-started
  - https://learn.microsoft.com/en-us/defender-cloud-apps/app-governance-app-policies-get-started
- Defender for Endpoint onboarding:
  - https://learn.microsoft.com/en-us/defender-endpoint/onboarding
- Defender for Identity:
  - https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-3
  - https://learn.microsoft.com/en-us/defender-for-identity/deploy/install-sensor
