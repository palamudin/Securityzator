using Securityzator.Application.Blueprints;
using Securityzator.Application.Portal;

namespace Securityzator.Infrastructure.Blueprints;

public sealed class StaticProductBlueprintService : IProductBlueprintService
{
    public Task<PortalBlueprint> GetPortalBlueprintAsync(CancellationToken cancellationToken = default)
    {
        var blueprint = new PortalBlueprint(
            PlatformSummary: "IIS-hosted Securityzator control plane with an ASP.NET Core web front end, layered application services, and a worker process for remediation jobs.",
            DeploymentSummary: "The web UI runs behind IIS, Graph and secret operations stay server-side, and long-running remediations move into a background worker or Windows service as the product hardens.",
            Modules: new[]
            {
                new ModuleCard("dashboard", "Dashboard", "Program overview, rollout status, and quick links into the tenant workflow.", "Milestone 2"),
                new ModuleCard("connections", "Azure Connections", "Capture tenant credentials, validate backend Graph reachability, and track certificate-backed automation readiness for the next Microsoft 365 admin providers.", "Milestone 6 hardening slice"),
                new ModuleCard("recommendations", "Recommendations", "Pull Secure Score controls, normalize them, and expose an operator-friendly remediation queue.", "Milestone 3 live slice"),
                new ModuleCard("remediations", "Remediations", "Turn the POC quick win into reusable remediation playbooks with auditable inputs.", "Milestone 4 live slice"),
                new ModuleCard("jobs", "Jobs and Audit", "Queue execution, retries, logs, approvals, and operator-visible outcomes.", "Milestone 5 live slice")
            },
            Milestones: new[]
            {
                new Milestone("M1", "Foundation", "Stand up the IIS-friendly solution, shell UI, and deployment shape.", "Web app, layered projects, worker host, and milestone docs are committed.", "Started"),
                new Milestone("M2", "Identity and Connections", "Add product login plus a connection workflow for customer Azure app credentials.", "Authenticated users can create, edit, and review connection profiles with server-side validation and protected secrets.", "Started"),
                new Milestone("M3", "Recommendation Sync", "Pull Secure Score data through the backend and persist recommendation snapshots.", "Operators can trigger a sync and browse recommendations without using the POC page.", "Started"),
                new Milestone("M4", "Quick Win Port", "Port the Conditional Access quick wins into reusable remediation templates.", "Operators can launch the block-legacy-auth, require-mfa-admins, mfa-all-users, require-mfa-guest-access, require-mfa-admin-portals, require-mfa-azure-management, secure-security-info-registration, require-mfa-risky-sign-ins, require-password-change-high-risk-users, require-phishing-resistant-mfa-admins, mdo-safe-links-and-attachments, and teams-meeting-hardening playbooks from the new app with auditable inputs.", "Started"),
                new Milestone("M5", "Queue and Audit", "Move execution into background jobs with retries, status pages, and audit trails.", "Every remediation run has queue status, logs, result state, and who-triggered metadata.", "Started"),
                new Milestone("M6", "Hardening", "Add RBAC, secret rotation posture, approval gates, and production deployment polish.", "Admin-only remediation gates, approval capture, health endpoints, and connection validation posture are in place for controlled rollout.", "Started")
            },
            ConnectionFields: new[]
            {
                new AzureConnectionField("tenantId", "Tenant ID", "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", true, false, "Customer Microsoft Entra tenant identifier."),
                new AzureConnectionField("clientId", "Application ID", "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", true, false, "The App Registration client ID used for Microsoft Graph access."),
                new AzureConnectionField("clientSecret", "Client Secret", "Stored server-side only", true, true, "Required today for Secure Score sync and Graph-driven remediations. Will never be sent back to the browser once saved."),
                new AzureConnectionField("automationCertificateThumbprint", "Automation Certificate Thumbprint", "LocalMachine\\My thumbprint", false, false, "Optional for Exchange, SharePoint, Purview, and future PowerShell-backed providers on IIS or Windows service hosts."),
                new AzureConnectionField("automationCertificateStoreLocation", "Certificate Store Location", "LocalMachine", false, false, "Usually LocalMachine for IIS app pools and Windows services."),
                new AzureConnectionField("automationCertificateStoreName", "Certificate Store Name", "My", false, false, "Usually My unless the certificate is installed into a different Windows certificate store."),
                new AzureConnectionField("redirectUri", "Redirect URI", "https://securityzator.example.com/signin-oidc", true, false, "Needed when delegated flows or interactive admin consent are used.")
            },
            RecommendationCatalog: BusinessPremiumBlueprintCatalog.GetRecommendationCatalog(),
            RemediationTemplates: BusinessPremiumBlueprintCatalog.GetRemediationTemplates(),
            JobCapabilities: new[]
            {
                new JobCapability("Sequential execution", "Start with one remediation step at a time so we preserve the safe behavior proven in the POC."),
                new JobCapability("Retry-aware Graph calls", "Honor Retry-After headers and surface throttling to the operator instead of hiding it."),
                new JobCapability("Operator-visible logs", "Every run writes structured activity so the UI can explain what happened."),
                new JobCapability("Promotion path", "The same worker can later run as a Windows service or containerized background process.")
            });

        return Task.FromResult(blueprint);
    }
}
