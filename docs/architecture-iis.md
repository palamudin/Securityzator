# Securityzator IIS Architecture

## Decision

Securityzator is being refactored from a single-file browser prototype into an IIS-hosted ASP.NET Core application. The browser stops talking directly to Microsoft Graph. Instead, the product becomes a classic enterprise web application with a layered backend and a background execution host.

## Solution Shape

```text
src/
  Securityzator.Web           ASP.NET Core MVC web front end hosted behind IIS
  Securityzator.Domain        Core business records and rules
  Securityzator.Application   Use-case contracts and orchestration boundaries
  Securityzator.Infrastructure Implementations for Graph, persistence, secrets, and queues
  Securityzator.Worker        Background job host for remediation execution
```

## Hosting Model

- `Securityzator.Web` runs behind IIS using the ASP.NET Core Hosting Bundle.
- IIS terminates the public request and forwards traffic to Kestrel.
- `Securityzator.Worker` is the long-term home for remediation jobs and can run as a Windows service on the same host tier or a separate worker node.
- Worker heartbeats are persisted into shared state so the web console can expose current execution posture and stale-worker recovery signals.

## Why This Fits The POC

- The current prototype already assumes a central panel that operators use to pull recommendations and launch remediations.
- The quick win flow is operationally safer when the Graph call path lives on the server.
- A worker host preserves the existing sequential queue idea while making retries, audit, and approvals much easier to implement.

## Initial Product Modules

- Dashboard
- Azure Connections
- Recommendations
- Remediations
- Jobs and Audit

## Production Notes

- The local workspace is now pinned to `.NET SDK 10.0.201` so the web app and worker use the same toolchain during development.
- Before a real rollout, confirm the production hosting baseline you want to standardize on and install the matching IIS Hosting Bundle on the server tier.
- Secret storage should move behind a vault or protected server-side encryption boundary before milestone 2 is considered complete.
