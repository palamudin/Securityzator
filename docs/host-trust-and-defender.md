# Host Trust And Defender Posture

Last reviewed: April 12, 2026

## Goal

Securityzator should run as normal enterprise admin tooling, not as ad hoc script activity that looks suspicious to Microsoft Defender, Smart App Control, App Control for Business, or AppLocker.

## Operating rules

1. Prefer compiled .NET tooling for local helpers, validators, exporters, and smoke runners.
2. Use PowerShell only when Microsoft exposes the admin surface primarily through PowerShell modules, such as Exchange Online or Teams.
3. Keep PowerShell wrappers thin. Heavy business logic should live in the application or a compiled helper, not in large inline scripts.
4. Do not rely on blanket antivirus exclusions as the normal operating model.
5. Keep all local automation in stable, auditable paths, and avoid temp-folder execution for routine workflows.

## PowerShell posture

- Use PowerShell 7 (`pwsh`) as the standard shell for local admin automation.
- Prefer `RemoteSigned` for normal development and signed scripts for broader rollout.
- Long-term publishable scripts should be Authenticode signed.
- Avoid `Invoke-Expression`, encoded command launches, hidden windows, download-and-execute patterns, and other behaviors that commonly trigger inspection.
- Avoid `-ExecutionPolicy Bypass` as the normal operator path. Keep it limited to explicit local bootstrap or troubleshooting only.

## Trust model for Windows controls

- For Smart App Control and App Control for Business, favor signed binaries and signed scripts.
- For enterprise rollout, create publisher-based allow rules for Securityzator binaries and signed scripts.
- If AppLocker is used, define explicit script and executable allow rules for Securityzator's signed publisher or managed install path.
- Prefer deployment under a stable location such as `Program Files\Securityzator` for packaged tooling instead of arbitrary working folders.

## Defender posture

- Do not add broad folder or process exclusions unless there is no narrower safe option.
- If Microsoft Defender flags a legitimate Securityzator binary or script, treat it as a false-positive workflow: capture the detection, preserve the artifact, and submit it through Microsoft's software developer / false-positive channels.
- Consistent code signing should be treated as a core requirement because Microsoft explicitly notes it helps their researchers recognize software faster.

## Securityzator implementation direction

- Keep IIS web app and worker as compiled .NET services.
- Migrate PowerShell-heavy local helper utilities over time into compiled .NET tools wherever Microsoft does not require PowerShell.
- Keep Exchange and Teams automation behind small, reviewable wrappers that call official Microsoft modules.
- Maintain clear audit logs for every tenant-affecting action regardless of whether the provider path is Graph, PowerShell, or Intune.

## New-rig baseline

A new rig is considered host-trust ready when:

- PowerShell 7 is installed.
- Securityzator scripts are local, reviewed, and preferably signed.
- Required Microsoft admin modules are installed from official sources.
- Securityzator binaries and scripts can run under the tenant's App Control or AppLocker posture without ad hoc bypasses.
- Defender exceptions, if any, are narrow, documented, and temporary.
