# Tenant Shakedown

Last reviewed: `2026-04-23`

## Goal

Run the currently confirmed-working Securityzator controls in a repeatable sequence against a clean tenant and capture a durable event log that an AI agent, operator, or reviewer can inspect afterward.

This runbook is meant for:
- clean-tenant onboarding rehearsals
- clean-VM deployment stress tests
- AI-agent functionality tests
- pilot-group validation before broader production rollout

For the current reference baseline and scoring rules, use:
- `docs/runbooks/tenant-shakedown-golden-guide.md`

## Main Harness

Use:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\Invoke-TenantShakedown.ps1 -Profile AppOnlyConfirmed -ConnectionId <connection-id> -IncludeGroupId <pilot-group-object-id>
```

The harness reads:
- `tools/tenant-shakedown.manifest.psd1`

It runs:
- the currently confirmed-working app-driven templates in manifest order
- the existing `Securityzator.SmokeRunner`
- a build pass first unless `-SkipBuild` is supplied

It writes:
- `summary.json`
- `summary.md`
- `driver.log`
- one stdout log and one JSON report per step

Default output root:

```text
.\artifacts\runlogs\tenant-shakedown-<timestamp>\
```

## Profiles

### `AssessmentOnly`
Use this when you want posture and readiness evidence without creating or promoting baselines.

### `AppOnlyConfirmed`
Use this when you want the currently confirmed-working app-driven surfaces only.

This is the best default for clean-tenant dry runs and first AI-agent test passes.

### `ArmorMeUpAppOnly`
Use this when you want the same confirmed-working app-driven sequence but with the intent to push harder on the tenant.

This profile still depends on the `-ConditionalAccessMode` flag to decide whether Conditional Access stays `ReportOnly` or is pushed to `Enabled`.

## Important Inputs

### `-ConnectionId`
Use the saved Securityzator connection for the tenant under test.

If omitted, the harness falls back to the most recently updated saved connection in `src\Securityzator.Web\App_Data\securityzator-state.json`.

### `-IncludeGroupId`
Required for the pilot-group Intune baselines and any group-scoped Conditional Access templates.

### `-ExcludeGroupId`
Optional exclusion group for breakglass or staged rollout safety.

### `-ConditionalAccessMode`
Supported values:
- `ReportOnly`
- `Enabled`

Recommended first pass:

```powershell
-ConditionalAccessMode ReportOnly
```

Use `Enabled` only when the clean tenant is explicitly being used as an enforcement rehearsal.

### `-PlanOnly`
Use this to generate the sequence and output structure without touching the tenant.

## What The Harness Logs

For each template it records:
- template key and display name
- launch mode
- script status
- message
- policy or target ID when present
- remediation job ID
- remediation run ID
- job logs
- run logs
- stdout transcript path
- JSON report path

This gives us both:
- a human-readable markdown narrative
- a machine-readable event log for AI-agent scoring and regression checks

## Recommended Clean-Tenant Sequence

1. Run `AssessmentOnly` first.
2. Run `AppOnlyConfirmed` with `-ConditionalAccessMode ReportOnly`.
3. Review `summary.md` and the per-step logs.
4. If the tenant is behaving as expected, rerun with `-ConditionalAccessMode Enabled`.
5. Record every blocker back into `requirements.txt` and the deployment docs.

The current successful reference run is:
- `artifacts/runlogs/tenant-shakedown-20260423-121921`

## Current Scope Boundary

This harness intentionally focuses on the currently confirmed-working app-driven surfaces.

It does not try to fake progress on:
- AD-backed controls
- Linux or macOS endpoint lanes
- external SaaS connectors
- delegated-only Exchange paths that are not yet part of the confirmed app-driven baseline

That keeps the shakedown honest and makes failures easier to reason about.
