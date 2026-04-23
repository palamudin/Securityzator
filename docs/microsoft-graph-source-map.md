# Microsoft Graph Source Map

`graph.source-map.psd1` is Securityzator's machine-readable anchor for Microsoft Graph guidance that we want to keep permanent instead of rediscovering on every mapping pass.

## Why this exists

Securityzator now spans three different kinds of Microsoft Graph truth:

- endpoint and permission guidance
- schema and path permanence
- SDK behavior and operator ergonomics

Those are not always best served by the same upstream repository. The local source map makes that explicit so our control mappings, bootstrap manifest, and remediation code do not drift.

## Canonical upstream sources

- `microsoft-graph-docs-contrib`
  Repository: `https://github.com/microsoftgraph/microsoft-graph-docs-contrib`
  Use for: endpoint permissions, documented request and response contracts, and operator-facing API behavior.
- `msgraph-metadata`
  Repository: `https://github.com/microsoftgraph/msgraph-metadata`
  Use for: schema permanence, path validation, and long-lived endpoint existence checks.
- `msgraph-sdk-powershell`
  Repository: `https://github.com/microsoftgraph/msgraph-sdk-powershell`
  Use for: examples, module packaging, and PowerShell ergonomics.
  Important: do not treat SDK behavior as bootstrap truth when it diverges from REST or documented contracts.

## How Securityzator uses the map

- `graph.source-map.psd1`
  Machine-readable source-of-truth pointers and local rules.
- `bootstrap.requirements.psd1`
  Curated operational subset derived from the source map for tenant bootstrap.
- `control-catalog.map.psd1`
  Machine-readable contract for the surfaced Business Premium recommendation cards and the extended remediation-template families that keep routing permanent.
- `requirements.txt`
  Human-readable zero-to-secured-tenant checklist.
- `bootstrap.ps1`
  Emits the active source-map anchors during bootstrap-critical runs so operators know which upstream references the repo is aligned to.
- `tools/Validate-GraphSourceMap.ps1`
  Local alignment check for the source map, bootstrap manifest, and human docs.
- `tools/Validate-ControlCatalog.ps1`
  Post-build validation for the current recommendation-to-template contract.
- `tools/Validate-SecureScoreCoverage.ps1`
  Snapshot-aware coverage report that recomputes current mapping against the latest cached Secure Score data for a tenant connection.

## Validation command

Run this after changing permissions, directory-role requirements, or source-map guidance:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\Validate-GraphSourceMap.ps1
```

This validator now runs automatically from:

- `.\build.ps1`
- `.\bootstrap.ps1`

If you deliberately need to work through known drift, both scripts support `-SkipGraphSourceMapValidation`.

The script fails fast if:

- `bootstrap.requirements.psd1` drifts from the permission profiles recorded in `graph.source-map.psd1`
- the manifest metadata points at the wrong canonical Microsoft Graph repositories
- `requirements.txt` or this document stop referencing the source-map workflow

## Permanent update workflow

When we add or change a permission, control family, or remediation surface:

1. Confirm the endpoint behavior and required permissions in `microsoft-graph-docs-contrib`.
2. Confirm the path and schema shape in `msgraph-metadata` when permanence matters.
3. Record the rule or anchor in `graph.source-map.psd1`.
4. Update `bootstrap.requirements.psd1` if bootstrap permissions, roles, or modules changed.
5. Update `requirements.txt` if operator or tenant prerequisites changed.
6. Only then update the code, control mappings, or playbook catalog.
7. If surfaced recommendation routing or template families changed, update `control-catalog.map.psd1`.
8. Run `tools/Validate-ControlCatalog.ps1` or let `.\build.ps1` do it automatically.
9. After a real tenant sync, run `tools/Validate-SecureScoreCoverage.ps1` to see how much of the snapshot is runnable now, mapped to broader families, or still unmapped.

## Current local rules worth keeping

- Bootstrap-critical app-role assignment validation should stay REST-first.
- Conditional Access create and update flows should keep a REST-capable path.
- Secure Score control mapping should stay anchored to docs-contrib for permissions and metadata for schema permanence.

## Useful anchored documents

- Secure Score control profiles:
  `https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/v1.0/api/security-list-securescorecontrolprofiles.md`
- Conditional Access policy create:
  `https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/v1.0/api/conditionalaccessroot-post-policies.md`
- Service principal app-role assignment create:
  `https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/api/serviceprincipal-post-approleassignments.md`
- Directory role assignments:
  `https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/v1.0/api/rbacapplication-list-roleassignments.md`

## Known SDK caveats already captured locally

- App-role assignment output can be incomplete in the PowerShell SDK compared with REST.
- Conditional Access create flows have had SDK schema mismatches.

Those caveats are already recorded in `graph.source-map.psd1` so the repo keeps the safer fallback behavior visible.
