# Securityzator Road To 70

Last reviewed: `2026-04-23`

## Goal
Move the tenant from the current observed Microsoft Secure Score baseline of roughly `53.62%` (`37 / 69`) toward `70%`.

Practical math:
- `70%` of `69` points is about `48.3`
- the current gap is therefore about `11` to `12` more Secure Score points

This is a realistic lift, but it will not come from more random Windows hardening alone. The next score gain needs to focus on the categories that are still lagging, especially `Apps`, plus the remaining tenant-wide Microsoft 365 controls that we have already implemented or can unblock with a small permission change.

## Current proven baseline

The following lanes are already proven in the live tenant and should be treated as a stable base:

- Conditional Access enabled baseline
  - legacy auth block
  - MFA for admins
  - MFA for all users
  - MFA for guests
  - MFA for admin portals
  - MFA for Azure management
  - secure security info registration
  - phishing-resistant MFA for admins
  - MFA for risky sign-ins
  - password change for high-risk users
- Intune / Defender Windows baseline set
  - core protection
  - firewall and SmartScreen
  - browser hardening
  - exploit protection
  - attack surface reduction
  - credential and elevation hardening
  - remote access and network hardening
  - OS security baseline
  - BitLocker startup baseline
- Assessment slices already giving real signal
  - Entra identity hygiene
  - Defender sensor and agent health
  - browser and Adobe policy-surface readiness

Reference evidence:
- [tenant-shakedown-20260423-121921 summary](c:/temp/Securityzator/artifacts/runlogs/tenant-shakedown-20260423-121921/summary.md)
- [Conditional Access rescue summary](c:/temp/Securityzator/artifacts/runlogs/ca-exclusions-20260423-105719/summary.md)

## 2026-04-23 identity and ASR checkpoint

These were the next high-impact candidates reviewed live after the first shakedown push.

### Identity Protection top-three check

Status:
- `2 already banked`
- `1 hybrid/manual`

Live outcome:
- `Enable Microsoft Entra ID Identity Protection sign-in risk policies`
  - already enabled
  - mapped to `require-mfa-risky-sign-ins`
- `Enable Microsoft Entra ID Identity Protection user risk policies`
  - already enabled
  - mapped to `require-password-change-high-risk-users`
- `Ensure that password hash sync is enabled for hybrid deployments`
  - still manual review only
  - mapped to `entra-identity-hygiene-baseline`

What the live runs proved:
- the risk-policy package smoke returned `Skipped` with the package already in enabled state
- the hygiene assessment confirmed:
  - default user consent disabled
  - admin consent workflow enabled
  - SSPR for admins allowed
  - 2 active Global Administrators
  - default domain password-expiration aligned
- password hash sync remains a hybrid validation item because Microsoft Graph does not expose enough Entra Connect posture here to call it compliant automatically

Obstacle log:
- `PasswordHashSync` is not a cloud-only one-click lift in the current product shape
- the current evidence path can only say:
  - no synchronized Global Administrator accounts were returned
  - validate Entra Connect / Entra Connect Health separately

Reference evidence:
- [entra-risk-policies-enabled.json](c:/temp/Securityzator/artifacts/runlogs/identity-push-20260423/entra-risk-policies-enabled.json)
- [entra-identity-hygiene.json](c:/temp/Securityzator/artifacts/runlogs/identity-push-20260423/entra-identity-hygiene.json)

### ASR checkpoint

Status:
- `implemented`
- `live-validated`
- `mostly harvested already`

Live outcome:
- the `defender-endpoint-attack-surface-reduction` baseline reran successfully and came back `AlreadyCompliantWithResidualFollowUp`
- policy:
  - `SS-AUTO | Endpoint attack surface reduction baseline`
  - policy id `c7a83bdb-1770-4534-a4ac-89814e3bce87`

Core ASR coverage already in the pilot baseline:
- Office child-process blocking
- Office executable-content blocking
- Office injection blocking
- Outlook child-process control
- Win32 API macro blocking
- obfuscated script blocking
- downloaded payload blocking
- email-executable blocking
- LSASS credential-theft protection
- PSExec / WMI process creation blocking
- untrusted USB execution blocking
- prevalence / age / trusted-list executable blocking
- ransomware protection
- controlled folder access
- WMI persistence blocking
- vulnerable signed-driver blocking

ASR-adjacent items still not truly solved by the current baseline:
- Adobe JavaScript controls
- Adobe Flash controls
- legacy browser Flash / ActiveX items
- Safe Mode reboot blocking
- webshell protection for server-oriented scenarios
- some server-specific ASR paths that need a different endpoint or server-management surface

Obstacle log:
- some Secure Score controls are routed into the ASR family because they are attack-surface adjacent, but the live Intune baseline only closes the rules that have a durable Windows Defender / Intune management lane
- Microsoft’s current guidance still requires Defender AV as primary AV, real-time protection on, cloud-delivered protection on, and cloud connectivity for the full ASR feature set
- enterprise Intune deployment is the right management surface; not every ASR-adjacent Secure Score item belongs in the same Intune policy object

Reference evidence:
- [defender-endpoint-attack-surface-reduction.json](c:/temp/Securityzator/artifacts/runlogs/identity-push-20260423/defender-endpoint-attack-surface-reduction.json)

Implication for the road to 70:
- ASR is still valuable, but most of the easy score from the core Windows ASR lane is already captured
- the next score lift is more likely to come from Microsoft 365 / app-governance / Defender for Office controls than from squeezing harder on already-compliant ASR rules

## What the current signal says

High-level category pressure:
- `Identity` is already materially better after the CA wave
- `Apps` is still visibly lagging and is the cleanest next score-lift area
- `Device` has strong baseline coverage already, but the next meaningful lift there is more about actual rollout completion than more policy quantity

Known remaining group buckets from local mapping:
- `connected-saas-session-and-auth-hardening`: `43`
- `salesforce-security-posture`: `29`
- `servicenow-security-posture`: `22`
- `federated-identity-provider-hygiene`: `20`
- `entra-identity-hygiene-baseline`: `14`
- `defender-endpoint-security-posture`: `53` in the broad export, but only a much smaller Windows/no-AD residue remains practical for this tenant lane

Important note:
- the current exported control map does not carry trustworthy per-control Secure Score point weights, so this plan ranks work by execution readiness and likely category lift rather than fake exact point promises

## Highest-yield route from here

### 1. Unblock Entra daily-use hardening
Status:
- `Implemented`
- `High yield`
- `Completed on 2026-04-23`

Why it matters:
- directly targets tenant app-consent and admin-consent posture
- likely helps the weak `Apps` category faster than more endpoint work
- uses a live tenant-wide write lane that already exists in product

What it does:
- disables default user consent to apps
- enables the admin consent workflow
- keeps the default domain password-expiration posture aligned

What happened:
- the app initially failed on `2026-04-23` at:
  - `PATCH /policies/authorizationPolicy`
  - `403 Authorization_RequestDenied`
- the underlying blocker was tenant app-role issuance, not product code
- Securityzator then aligned the tenant app and granted:
  - `Policy.ReadWrite.Authorization`
  - `Policy.ReadWrite.ConsentRequest`
  - `Domain.ReadWrite.All`
- a fresh live smoke then succeeded and applied:
  - default user consent disablement
  - admin consent workflow enablement
  - reviewer seeding from active Global Administrators

Needed app permissions:
- `Policy.ReadWrite.Authorization`
- `Policy.ReadWrite.ConsentRequest`
- `Domain.ReadWrite.All`

Current live evidence:
- successful live smoke artifact:
  - [entra-daily-use-hardening-20260423.json](c:/temp/Securityzator/artifacts/runlogs/entra-daily-use-hardening-20260423.json)
- successful full tenant shakedown:
  - [tenant-shakedown-20260423-135820 summary](c:/temp/Securityzator/artifacts/runlogs/tenant-shakedown-20260423-135820/summary.md)

Recommended next action:
- keep this step in the standard tenant-alignment path
- use `.\tools\Grant-GraphTenantRequirements.ps1` as the current working fallback helper until the main bootstrap path is fully normalized

### 2. Defender for Office anti-phish and impersonation
Status:
- `Implemented`
- `Potentially high yield`
- `Session / provider sensitive`
- `Still blocked as of 2026-04-23`

Why it matters:
- this is one of the most plausible next lifts after the CA baseline
- improves mail threat posture, which often lands in score faster than edge-case endpoint polish

Current state:
- implementation exists
- Microsoft’s current documentation says anti-phishing policies are configured in the Microsoft Defender portal or in Exchange Online PowerShell
- the same documentation also shows the feature is recipient-scoped by specific users, groups, or domains, which matches the user/domain targeting concern
- Securityzator’s delegated anti-phish helper still hits a reduced Exchange session surface on this tenant:
  - `MailboxIntelligenceProtectionAction` missing in one token-backed session
  - `EnableTargetedDomainsProtection` missing in a later device-login session

Interpretation:
- this looks like a real session-surface/cmdlet-availability problem, not a missing local module
- there is still no documented Microsoft Graph anti-phish configuration surface in Securityzator’s Graph source map

Recommended next action:
- on the fresh E5 tenant, retry the anti-phish baseline first through the delegated helper
- if the cmdlet surface is still reduced, classify anti-phish as `Exchange PowerShell full session required` instead of pretending it is app-only or Graph-backed
- capture before/after Secure Score movement after propagation

### 2a. Defender for Office anti-malware hardening
Status:
- `Implemented`
- `Medium to high yield`
- `Live-validated on 2026-04-23`

Why it matters:
- directly targets two Microsoft 365 mail-protection controls that belong in Defender, not in the Safe Links slice
- gives Securityzator a clean inbound malware-hardening lane instead of burying malware ZAP and attachment filtering under a broader Safe Links package

What happened:
- Securityzator promoted a new dedicated `mdo-anti-malware-baseline` template
- the first live smoke found a real code-path issue:
  - the PowerShell payload was serializing `alreadyCompliant` incorrectly
- that bug was fixed in the automation client and the rerun succeeded
- the live tenant then returned:
  - `AlreadyCompliant`
  - `SS-AUTO | Anti-malware baseline`

What this slice now covers:
- malware ZAP
- common attachment types filter
- admin-only malware quarantine posture
- accepted-domain anti-malware rule coverage

Obstacle log:
- the first blocker here was product serialization, not Exchange provider behavior
- the recommendation alias map also needed cleanup so the malware controls stopped resolving into the Safe Links family
- cached recommendation mapping backfill updated `2` controls after the template split

Reference evidence:
- [mdo-anti-malware-baseline-debug.json](c:/temp/Securityzator/artifacts/runlogs/defender-office-20260423/mdo-anti-malware-baseline-debug.json)

### 3. Defender for Office spam and forwarding hardening
Status:
- `Implemented`
- `Medium to high yield`
- `Workable with delegated helper`
- `Revalidated on 2026-04-23`

Why it matters:
- tenant-wide mail-flow protections tend to move the score faster than niche endpoint refinements

Current state:
- the delegated Exchange helper path is workable
- Securityzator found and fixed a real implementation bug on `2026-04-23`:
  - our helper was calling `Set-HostedContentFilterRule -Enabled`, but Microsoft’s supported model uses `Set-*Rule` plus separate `Enable-*Rule` cmdlets
- after the fix, the delegated helper completed successfully and confirmed the tenant is aligned on:
  - inbound spam quarantine posture
  - outbound forwarding automatic mode
  - outbound rate limits and threshold action

Recommended next action:
- use the existing spam/forwarding baseline as part of the fresh-tenant “armor me up” wave
- record the resulting Secure Score delta after sync

### 4. Safe Links and Safe Attachments
Status:
- `Implemented`
- `Potentially high yield`
- `Provider surface inconsistent`
- `Still blocked as of 2026-04-23`

Why it matters:
- still one of the most likely remaining Microsoft 365 scoring lifts in an E5 tenant

Current blocker:
- Safe Links / Safe Attachments cmdlets have been inconsistent in the token-backed delegated session
- the product still does not have a Graph-native path for these policies
- the latest delegated helper run failed because `Set-AtpPolicyForO365` was not available in the session at all

Recommended next action:
- test the fresh E5 tenant again
- if the delegated helper exposes the right cmdlets, treat this as a score-lift wave
- otherwise record as `Defender portal / full Exchange admin session required`

## Obstacles found during the 2026-04-23 push

- bootstrap manifest drift:
  - `bootstrap.requirements.psd1` and `graph.source-map.psd1` were still missing the current Entra daily-use and Intune write roles, so the validator blocked the change until the canonical source map was updated
- bootstrap entrypoint bug:
  - `bootstrap.ps1` was depending on `$PSScriptRoot` inside parameter defaults, which broke on this host/session
  - Securityzator now resolves its script root after parameter binding instead
- Azure CLI bootstrap Graph-context bug:
  - the main bootstrap still fell through to `Invoke-MgGraphRequest` and demanded `Connect-MgGraph` even though the Azure CLI Graph token path had been selected
  - working fallback added:
    - `.\tools\Grant-GraphTenantRequirements.ps1`
- Exchange rule-update mismatch:
  - delegated spam/forwarding helper originally used unsupported `Set-*Rule -Enabled` patterns
  - fixed to use `Enable-HostedContentFilterRule` and `Enable-HostedOutboundSpamFilterRule`
- Exchange anti-phish / Safe Links session trimming:
  - anti-phish still loses impersonation parameters in the current delegated/token-backed sessions
  - Safe Links / Safe Attachments still lose `Set-AtpPolicyForO365`

## Second-wave route

### 5. App governance and user-owned apps
Status:
- `Mapped`
- `Not yet a true execution lane`
- `Promising for Apps category`

Why it matters:
- `Apps` is the visibly weaker category in the current tenant
- this area is a better likely score-lift target than more mature Windows baselines

What needs to happen:
- build a real provider lane around enterprise app consent posture, approved apps, and broader app governance
- this will likely overlap with Defender for Cloud Apps and Microsoft Entra enterprise app governance

### 6. Defender for Cloud Apps foundation
Status:
- `Mapped`
- `Onboarding-dependent`

Why it matters:
- probably the strongest medium-term route for lifting `Apps`
- the tenant licensing direction now supports it much better than the earlier Business Premium path

Current blocker:
- needs onboarding and connector decisions, not just a button press

Recommended next action:
- treat this as the first serious post-70 expansion lane, or a parallel lane if the fresh E5 tenant is being onboarded from zero

## Device follow-up route

These are useful, but they are less likely than Entra + Defender for Office to produce the next clean score jump.

### BitLocker rollout completion
Status:
- `Implemented`
- `Assessment-proven`
- `Needs device follow-up`

Current finding:
- the policy is in place, but the pilot device still needs actual encryption rollout

Why it matters:
- helps convert baseline assignment into real device compliance

### Defender EDR onboarding policy coverage
Status:
- `Assessment-proven`
- `Connector / onboarding dependent`

Current finding:
- telemetry can be healthy while the pilot scope still lacks a direct Intune EDR onboarding policy

Why it matters:
- more about posture completion than immediate score lift

## Not the fastest path to 70 right now

The following areas matter, but they should not be the next sprint if the goal is simply to reach `70%` quickly:

- AD-backed controls
- Defender for Identity sensor rollout
- macOS baselines
- Linux baselines
- Salesforce / ServiceNow / external SaaS connectors
- broader federated identity provider lanes

Those are real product surfaces, but they are not the most efficient “score from here” path on the current tenant.

## Recommended execution order

1. Grant the missing Entra daily-use write permissions and rerun `entra-daily-use-hardening`.
2. On the fresh E5 tenant, run the Defender for Office anti-phish baseline.
3. Run the Defender for Office spam and forwarding baseline.
4. Re-test Safe Links / Safe Attachments on the fresh E5 tenant.
5. Resync Secure Score and capture the delta.
6. If still below target, open the `Apps` lane next:
   - app governance and user-owned apps
   - Defender for Cloud Apps foundation

## Definition of success for the next pass

We should treat the next pass as successful if we achieve all of the following:

- Entra daily-use hardening is either:
  - executed successfully, or
  - blocked only by a clear tenant permission gap that is now documented and queued
- Defender for Office anti-phish and spam/forwarding have been attempted on the fresh E5 tenant
- Safe Links / Safe Attachments have been tested again on E5 and classified as either:
  - workable now
  - delegated-session blocked
  - portal-only fallback
- a new before/after Secure Score capture is stored with the shakedown evidence

## Short version

To get from `53.62%` to `70%`, the best next route is:
- `Entra daily-use hardening`
- then `Defender for Office`
- then `Apps / app-governance onboarding`

The main blocker we know for certain right now is not product code. It is tenant permission issuance for the Entra daily-use write lane.

## Current source anchors

- Anti-phishing policy configuration guidance:
  - https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-mdo-configure
- Anti-phishing cmdlet surface:
  - https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-antiphishpolicy?view=exchange-ps
  - https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-antiphishpolicy?view=exchange-ps
- Safe Links policy guidance:
  - https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure
- Spam/content filter rule cmdlet surface:
  - https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-hostedcontentfilterrule?view=exchange-ps
  - https://learn.microsoft.com/en-us/powershell/module/exchange/set-hostedcontentfilterrule?view=exchange-ps
  - https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/enable-hostedcontentfilterrule?view=exchange-ps
- Outbound spam rule cmdlet surface:
  - https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-hostedoutboundspamfilterrule?view=exchange-ps
  - https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/enable-hostedoutboundspamfilterrule?view=exchange-ps
