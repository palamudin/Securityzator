# Tenant Shakedown Golden Guide

Last reviewed: `2026-04-23`

## Goal

Use the successful tenant shakedown as the repeatable reference guide for:
- clean-VM deployment validation
- clean-tenant onboarding validation
- AI-agent functionality testing
- regression detection after code changes

This guide turns the `2026-04-23` successful live run into the current golden fixture for the confirmed-working app-only lane.

## Golden Fixture

Reference run:
- Output root: `artifacts/runlogs/tenant-shakedown-20260423-121921`
- Summary markdown: `artifacts/runlogs/tenant-shakedown-20260423-121921/summary.md`
- Summary JSON: `artifacts/runlogs/tenant-shakedown-20260423-121921/summary.json`

Reference inputs:
- Profile: `ArmorMeUpAppOnly`
- Conditional Access mode: `Enabled`
- Connection: `Strong MSP Smoke Tenant`
- Connection ID: `b663326b-f424-43b7-8f47-8ef0a007a9b5`
- Pilot include group: `Securityzator-Test-Group`
- Pilot include group ID: `e99ed4d0-13b0-4484-81f7-74c2284955e7`

Reference totals:
- `22` steps
- `21` `Succeeded`
- `1` `CompletedWithFollowUp`
- `0` `Failed`
- `0` `Skipped`

## What “Good” Looks Like

### Conditional Access

These controls should complete successfully and read back as `enabled` when the harness is run with `-ConditionalAccessMode Enabled`:
- `block-legacy-auth`
- `require-mfa-admins`
- `mfa-all-users`
- `require-mfa-guest-access`
- `require-mfa-admin-portals`
- `require-mfa-azure-management`
- `secure-security-info-registration`
- `require-phishing-resistant-mfa-admins`
- `require-mfa-risky-sign-ins`
- `require-password-change-high-risk-users`

Acceptance rule:
- treat any readback state other than `enabled` as a real product or tenant issue
- do not count “no exception but still report-only” as success

### Intune / Defender baselines

These should complete successfully and usually read back as either:
- `AlreadyCompliantWithResidualFollowUp`
- `UpdatedWithResidualFollowUp`

Expected baseline set:
- `defender-endpoint-core-protection`
- `defender-endpoint-firewall-and-smartscreen`
- `defender-endpoint-browser-hardening`
- `defender-endpoint-exploit-protection`
- `defender-endpoint-attack-surface-reduction`
- `defender-endpoint-credential-and-elevation-hardening`
- `defender-endpoint-remote-access-and-network-hardening`
- `defender-endpoint-os-security-baseline`
- `defender-endpoint-bitlocker-baseline`

Acceptance rule:
- if the run says the pilot assignment and Securityzator profile already match, count that as success
- residual follow-up notes are expected for unsupported adjacent controls and should not be scored as harness failure

### Assessment slices

These are expected to produce evidence, not necessarily “all green” posture:
- `entra-identity-hygiene-baseline`
- `defender-endpoint-sensor-and-agent-health`
- `defender-endpoint-browser-and-adobe-policy-surface-readiness`

Expected interpretation:
- Entra hygiene should often finish with `NeedsFollowUp`
- Defender sensor/agent health may finish with `NeedsFollowUp` if telemetry is stale or onboarding is incomplete
- browser/Adobe readiness is currently expected to finish with follow-up unless Chrome outdated-plugin policy and Adobe ADMX surfaces are present

Acceptance rule:
- successful evidence collection with actionable findings is a pass
- lack of readiness is not the same as harness failure

## Current Expected Follow-Up From The Golden Run

These findings are normal against the current reference tenant:
- Entra user consent still needs tightening
- Entra admin consent workflow is disabled
- the pilot Windows device still needs BitLocker rollout follow-up
- Defender sensor/agent health still needs follow-up because telemetry is stale and no Intune EDR onboarding policy covers the pilot scope
- Chrome outdated-plugin policy is not exposed as a durable Intune policy surface
- Adobe ADMX definitions are not uploaded in Intune

## AI-Agent Scoring Rules

Use these rules when judging an autonomous run:

### Count as pass
- the harness executes all manifest steps
- output artifacts are produced
- policy creation or promotion succeeds
- baseline readback matches the expected target state
- assessment flows return evidence and clear follow-up items

### Count as product failure
- a step returns `Failed`
- Conditional Access requested `Enabled` but readback is not `enabled`
- the harness cannot resolve the saved connection or pilot group
- the tool logs claim success without producing a run record or per-step JSON artifact

### Count as environment failure
- token acquisition fails because transport to Microsoft Entra is blocked
- sandbox or proxy restrictions prevent outbound HTTPS
- worker process or host prerequisites are missing

The `2026-04-23` in-sandbox run at `artifacts/runlogs/tenant-shakedown-20260423-121402` is a good example of an environment failure. It produced universal SSL transport errors before any tenant logic executed and should not be scored as a tenant-control failure.

## Recommended Execution Order

1. Run `AssessmentOnly` on a new tenant first.
2. Run `AppOnlyConfirmed` with `-ConditionalAccessMode ReportOnly`.
3. Review the generated summary and per-step JSON outputs.
4. Run `ArmorMeUpAppOnly` with `-ConditionalAccessMode Enabled`.
5. Compare the new run to the golden fixture.
6. Record any delta into docs before changing the manifest or expanding scope.

## Commands

Dry-run shape check:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\Invoke-TenantShakedown.ps1 -Profile AppOnlyConfirmed -PlanOnly -IncludeGroupId <pilot-group-object-id>
```

Reference-style live run:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\Invoke-TenantShakedown.ps1 -Profile ArmorMeUpAppOnly -ConnectionId <connection-id> -IncludeGroupId <pilot-group-object-id> -ConditionalAccessMode Enabled
```

## Artifact Checklist

Every valid shakedown folder should contain:
- `driver.log`
- `summary.md`
- `summary.json`
- one `*.json` report per step
- one `*.stdout.log` per step

If any of these are missing, do not treat the run as complete.

## Change Control

Update this guide whenever one of these changes:
- the manifest order
- the confirmed-working template set
- the expected pass/follow-up totals
- the accepted readback state for any template
- the default pilot-group strategy

This guide should stay stable enough that we can use it as a reliable AI-agent acceptance test instead of rewriting the scoring rules after every run.
