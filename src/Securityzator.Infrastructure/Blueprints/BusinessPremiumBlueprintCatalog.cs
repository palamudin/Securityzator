using Securityzator.Application.Portal;
using Securityzator.Application.Connections;
using Securityzator.Application.Remediations;

namespace Securityzator.Infrastructure.Blueprints;

internal static class BusinessPremiumBlueprintCatalog
{
    internal static IReadOnlyList<SecurityRecommendationPreview> GetRecommendationCatalog()
    {
        return
        [
            new SecurityRecommendationPreview(
                1,
                "Block legacy authentication",
                "Identity",
                "Conditional Access",
                "Runnable now",
                "High",
                "block-legacy-auth",
                ["Enable Conditional Access policies to block legacy authentication"]),
            new SecurityRecommendationPreview(
                2,
                "Require MFA for privileged administrators",
                "Identity",
                "Microsoft Entra ID",
                "Runnable now",
                "High",
                "require-mfa-admins",
                ["Ensure multifactor authentication is enabled for all users in administrative roles"]),
            new SecurityRecommendationPreview(
                3,
                "Require MFA for all users",
                "Identity",
                "Microsoft Entra ID",
                "Runnable now",
                "High",
                "mfa-all-users",
                ["Ensure multifactor authentication is enabled for all users"]),
            new SecurityRecommendationPreview(
                4,
                "Risk-based identity protection",
                "Identity",
                "Microsoft Entra ID",
                "Runnable now",
                "High",
                "entra-risk-policies",
                Array.Empty<string>()),
            new SecurityRecommendationPreview(
                5,
                "Entra admin and consent hygiene",
                "Identity",
                "Microsoft Entra ID",
                "Runnable now",
                "High",
                "entra-identity-hygiene-baseline",
                [
                    "Ensure that password hash sync is enabled for hybrid deployments",
                    "Ensure user consent to apps accessing company data on their behalf is not allowed",
                    "Use least privileged administrative roles",
                    "Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (recommended)'",
                    "Ensure 'Self service password reset enabled' is set to 'All'",
                    "Designate more than one global admin"
                ]),
            new SecurityRecommendationPreview(
                6,
                "Require phishing-resistant MFA for privileged administrators",
                "Identity",
                "Conditional Access",
                "Runnable now",
                "High",
                "require-phishing-resistant-mfa-admins",
                ["Ensure 'Phishing-resistant MFA strength' is required for Administrators"]),
            new SecurityRecommendationPreview(
                7,
                "Defender for Office anti-phishing and impersonation",
                "Apps",
                "Defender for Office",
                "Runnable now",
                "High",
                "mdo-anti-phishing-and-impersonation",
                [
                    "Ensure that intelligence for impersonation protection is enabled",
                    "Move messages that are detected as impersonated users by mailbox intelligence",
                    "Enable impersonated domain protection",
                    "Enable impersonated user protection",
                    "Quarantine messages that are detected from impersonated domains",
                    "Quarantine messages that are detected from impersonated users",
                    "Enable the domain impersonation safety tip",
                    "Enable the user impersonation safety tip",
                    "Enable the user impersonation unusual characters safety tip",
                    "Ensure that an anti-phishing policy has been created",
                    "Set the phishing email level threshold at 2 or higher",
                    "Set action to take on phishing detection",
                    "Set action to take on high confidence phishing detection",
                    "Ensure that mailbox intelligence is enabled",
                    "Create zero-hour auto purge policies for phishing messages"
                ]),
            new SecurityRecommendationPreview(
                8,
                "Defender for Office Safe Links and attachments",
                "Apps",
                "Defender for Office",
                "Runnable now",
                "High",
                "mdo-safe-links-and-attachments",
                [
                    "Turn on Microsoft Defender for Office 365 in SharePoint, OneDrive, and Microsoft Teams",
                    "Turn on Safe Documents for Office Clients",
                    "Ensure Safe Links for Office Applications is Enabled",
                    "Create Safe Links policies for email messages",
                    "Turn on Safe Attachments in block mode",
                    "Ensure Safe Attachments policy is enabled",
                    "Create zero-hour auto purge policies for malware",
                    "Ensure the Common Attachment Types Filter is enabled"
                ]),
            new SecurityRecommendationPreview(
                9,
                "Defender for Office spam and forwarding hardening",
                "Apps",
                "Defender for Office",
                "Runnable now",
                "High",
                "mdo-spam-and-forwarding-baseline",
                [
                    "Set action to take on high confidence spam detection",
                    "Set action to take on spam detection",
                    "Set action to take on bulk spam detection",
                    "Retain spam in quarantine for 30 days",
                    "Set the email bulk complaint level (BCL) threshold to be 6 or lower",
                    "Block users who reached the message limit",
                    "Ensure all forms of mail forwarding are blocked and/or disabled",
                    "Ensure Exchange Online Spam Policies are set to notify administrators",
                    "Ensure that no sender domains are allowed for anti-spam policies",
                    "Don't add allowed IP addresses in the connection filter policy",
                    "Create zero-hour auto purge policies for spam messages",
                    "Set automatic email forwarding rules to be system controlled",
                    "Set maximum number of external recipients that a user can email per hour",
                    "Set maximum number of internal recipients that a user can send to within an hour",
                    "Set a daily message limit",
                    "Ensure Spam confidence level (SCL) is configured in mail transport rules with specific domains"
                ]),
            new SecurityRecommendationPreview(
                10,
                "Exchange Online collaboration and mailbox hardening",
                "Apps",
                "Exchange Online",
                "Runnable now",
                "Medium",
                "exchange-online-collaboration-and-mailbox",
                [
                    "Ensure 'External sharing' of calendars is not available",
                    "Ensure additional storage providers are restricted in Outlook on the web",
                    "Ensure MailTips are enabled for end users",
                    "Ensure mailbox auditing for all users is Enabled",
                    "Ensure users installing Outlook add-ins is not allowed",
                    "Ensure the customer lockbox feature is enabled",
                    "Ensure modern authentication for Exchange Online is enabled"
                ]),
            new SecurityRecommendationPreview(
                11,
                "Purview data protection baseline",
                "Data",
                "Microsoft Information Protection",
                "Control set draft",
                "High",
                "purview-data-protection-baseline",
                [
                    "Ensure DLP policies are enabled",
                    "Ensure Microsoft 365 audit log search is Enabled",
                    "Publish M365 sensitivity label data classification policies",
                    "Extend M365 sensitivity labeling to assets in Microsoft Purview data map",
                    "Ensure that Auto-labeling data classification policies are set up and used"
                ]),
            new SecurityRecommendationPreview(
                12,
                "Teams meeting hardening baseline",
                "Apps",
                "Microsoft Teams",
                "Runnable now",
                "Medium",
                "teams-meeting-hardening",
                [
                    "Only invited users should be automatically admitted to Teams meetings",
                    "Configure which users are allowed to present in Teams meetings",
                    "Restrict anonymous users from joining meetings",
                    "Restrict dial-in users from bypassing a meeting lobby",
                    "Limit external participants from having control in a Teams meeting",
                    "Restrict anonymous users from starting Teams meetings"
                ]),
            new SecurityRecommendationPreview(
                13,
                "SharePoint session and authentication hardening",
                "Apps",
                "SharePoint Online",
                "Control set draft",
                "Medium",
                "sharepoint-online-session-hardening",
                [
                    "Sign out inactive users in SharePoint Online",
                    "Ensure modern authentication for SharePoint applications is required"
                ]),
            new SecurityRecommendationPreview(
                14,
                "Defender for Cloud Apps discovery",
                "Apps",
                "Microsoft Defender for Cloud Apps",
                "Guided enablement",
                "Medium",
                "defender-cloud-apps-foundation",
                [
                    "Ensure Microsoft Defender for Cloud Apps is enabled and configured",
                    "Deploy a log collector to discover shadow IT activity"
                ]),
            new SecurityRecommendationPreview(
                15,
                "Defender for Identity foundation",
                "Identity",
                "Defender for Identity",
                "Guided enablement",
                "Medium",
                "defender-identity-foundation",
                ["Start your Defender for Identity deployment, installing Sensors on Domain Controllers and other eligible servers."]),
            new SecurityRecommendationPreview(
                16,
                "Protect breakglass accounts with exclusions and monitoring",
                "Identity",
                "Conditional Access",
                "Discovery",
                "Medium",
                "protect-breakglass",
                Array.Empty<string>()),
            new SecurityRecommendationPreview(
                17,
                "Review risky sign-in coverage for workload identities",
                "Threat protection",
                "Microsoft Defender",
                "Discovery",
                "Medium",
                "workload-identity-review",
                Array.Empty<string>()),
            new SecurityRecommendationPreview(
                18,
                "Require MFA when risky sign-ins are detected",
                "Identity",
                "Microsoft Entra ID",
                "Runnable now",
                "High",
                "require-mfa-risky-sign-ins",
                ["Enable Microsoft Entra ID Identity Protection sign-in risk policies"]),
            new SecurityRecommendationPreview(
                19,
                "Require password change for high-risk users",
                "Identity",
                "Microsoft Entra ID",
                "Runnable now",
                "High",
                "require-password-change-high-risk-users",
                ["Enable Microsoft Entra ID Identity Protection user risk policies"]),
            new SecurityRecommendationPreview(
                20,
                "Require MFA for guest access",
                "Identity",
                "Conditional Access",
                "Runnable now",
                "High",
                "require-mfa-guest-access",
                Array.Empty<string>()),
            new SecurityRecommendationPreview(
                21,
                "Require MFA for Microsoft admin portals",
                "Identity",
                "Conditional Access",
                "Runnable now",
                "High",
                "require-mfa-admin-portals",
                Array.Empty<string>()),
            new SecurityRecommendationPreview(
                22,
                "Require MFA for Azure management",
                "Identity",
                "Conditional Access",
                "Runnable now",
                "High",
                "require-mfa-azure-management",
                Array.Empty<string>()),
            new SecurityRecommendationPreview(
                23,
                "Secure security info registration",
                "Identity",
                "Conditional Access",
                "Runnable now",
                "High",
                "secure-security-info-registration",
                Array.Empty<string>())
        ];
    }

    internal static IReadOnlyList<RemediationTemplate> GetRemediationTemplates()
    {
        return
        [
            new RemediationTemplate(
                "block-legacy-auth",
                "Block legacy authentication",
                "Ports the proven POC quick win into a reusable playbook that creates a Conditional Access policy in report-only mode first.",
                "Backend validates inputs, checks for an existing policy, creates the policy through Microsoft Graph, then writes a durable audit entry.",
                "Automated quick win",
                true,
                [
                    "Include group Object ID",
                    "Optional breakglass exclusion group Object ID",
                    "Connection profile with Policy.ReadWrite.ConditionalAccess capability"
                ],
                [
                    "Resolve the target tenant connection from the signed-in workspace.",
                    "Validate required Graph permissions and operator authorization.",
                    "Look up an existing policy by display name before creating anything.",
                    "Create the policy in report-only mode and store the response payload for traceability."
                ])
            {
                ExecutionSurface = "Microsoft Graph Conditional Access policy API with app-only access.",
                NextStage = "Keep this policy report-only until the operator reviews sign-in impact and is ready to promote it into enforcement.",
                Targeting = new RemediationTemplateTargeting(
                    "Users and groups",
                    "Targets a specific Microsoft Entra group, with an optional exclusion group for breakglass or staged rollout.",
                    true,
                    true),
                SupportsLaunchModeSelection = true,
                DefaultLaunchMode = RemediationLaunchMode.ReportOnly,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.EntraIdP1]
            },
            new RemediationTemplate(
                "require-mfa-admins",
                "Require MFA for privileged admins",
                "Creates a report-only Conditional Access policy that requires MFA for a chosen privileged admin group.",
                "Reuses the same queue, worker, approval, and audit infrastructure as the block-legacy-auth quick win, but switches the grant control to MFA.",
                "Automated quick win",
                true,
                [
                    "Privileged admin group Object ID",
                    "Optional trusted location exclusions",
                    "MFA registration readiness review"
                ],
                [
                    "Validate which privileged admin group belongs in scope.",
                    "Review MFA registration readiness before enforcement.",
                    "Create the policy in report-only mode first and store the Graph response for traceability."
                ])
            {
                ExecutionSurface = "Microsoft Graph Conditional Access policy API with app-only access.",
                NextStage = "Review report-only outcomes, then decide whether the tenant is ready to enforce the policy.",
                Targeting = new RemediationTemplateTargeting(
                    "Users and groups",
                    "Targets the chosen privileged-admin group, with an optional exclusion group for breakglass or staged rollout.",
                    true,
                    true),
                SupportsLaunchModeSelection = true,
                DefaultLaunchMode = RemediationLaunchMode.ReportOnly,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.EntraIdP1]
            },
            new RemediationTemplate(
                "mfa-all-users",
                "Require MFA for all users",
                "Creates a report-only Conditional Access policy that requires multifactor authentication for all users, with optional exclusion groups for breakglass or staged rollout safety.",
                "Uses the built-in Multifactor authentication strength in report-only mode so the tenant can validate coverage before any enforcement decision.",
                "Automated quick win",
                true,
                [
                    "Optional breakglass exclusion group Object ID",
                    "Authentication method readiness",
                    "Operator approval for a report-only tenant-wide policy"
                ],
                [
                    "Confirm the tenant's MFA registration readiness and target population.",
                    "Exclude the right breakglass or pilot groups before queueing the policy.",
                    "Create the policy in report-only mode and store the Graph response for traceability."
                ])
            {
                ExecutionSurface = "Microsoft Graph Conditional Access policy API with built-in authentication strengths.",
                NextStage = "Use report-only sign-in data to confirm exclusion safety before any enforced tenant-wide MFA rollout.",
                Targeting = new RemediationTemplateTargeting(
                    "Users",
                    "Targets all users, with an optional exclusion group for breakglass or staged rollout.",
                    false,
                    true),
                SupportsLaunchModeSelection = true,
                DefaultLaunchMode = RemediationLaunchMode.ReportOnly,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.EntraIdP1]
            },
            new RemediationTemplate(
                "require-mfa-guest-access",
                "Require MFA for guest access",
                "Creates a report-only Conditional Access policy that requires MFA for guest and external users across all resources.",
                "Follows Microsoft's guest-access baseline by targeting guest and external identities directly while preserving the same queue, approval, and audit path used by the existing quick wins.",
                "Automated quick win",
                true,
                [
                    "Optional guest exclusion group Object ID",
                    "Guest and partner access review",
                    "Operator approval for a report-only guest-access policy"
                ],
                [
                    "Confirm the tenant wants a dedicated guest-access MFA policy rather than relying only on broader all-user coverage.",
                    "Exclude any emergency or staged-rollout guest population before queueing the policy.",
                    "Create the policy in report-only mode and store the Graph response for traceability."
                ])
            {
                ExecutionSurface = "Microsoft Graph Conditional Access policy API using the GuestsOrExternalUsers scope.",
                NextStage = "Review guest sign-in impact, then decide whether the tenant is ready to enforce the guest-access policy.",
                Targeting = new RemediationTemplateTargeting(
                    "Users",
                    "Targets all guest and external users, with an optional exclusion group for emergency access or phased rollout.",
                    false,
                    true),
                SupportsLaunchModeSelection = true,
                DefaultLaunchMode = RemediationLaunchMode.ReportOnly,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.EntraIdP1]
            },
            new RemediationTemplate(
                "require-mfa-admin-portals",
                "Require MFA for Microsoft admin portals",
                "Creates a report-only Conditional Access policy that targets protected built-in administrator roles when they access Microsoft admin portals.",
                "Matches Microsoft's admin-portal baseline without requiring the operator to maintain a custom admin group, because the policy scopes directly to built-in roles.",
                "Automated quick win",
                true,
                [
                    "Optional breakglass exclusion group Object ID",
                    "Administrator registration readiness",
                    "Operator approval for a report-only admin-portal policy"
                ],
                [
                    "Review administrator MFA readiness before queueing the policy.",
                    "Exclude the correct breakglass group for recovery safety.",
                    "Create the policy in report-only mode and store the Graph response for traceability."
                ])
            {
                ExecutionSurface = "Microsoft Graph Conditional Access policy API using built-in role scopes and the MicrosoftAdminPortals target resource.",
                NextStage = "Use report-only outcomes to validate administrator coverage before any enforced rollout.",
                Targeting = new RemediationTemplateTargeting(
                    "Administrator roles",
                    "Targets protected built-in administrator roles directly, with an optional exclusion group for breakglass or phased rollout.",
                    false,
                    true),
                SupportsLaunchModeSelection = true,
                DefaultLaunchMode = RemediationLaunchMode.ReportOnly,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.EntraIdP1]
            },
            new RemediationTemplate(
                "require-mfa-azure-management",
                "Require MFA for Azure management",
                "Creates a report-only Conditional Access policy that requires MFA for Azure Resource Manager access.",
                "This aligns the app with Microsoft's Azure-management baseline by protecting interactive Azure resource management without changing the broader user MFA policy.",
                "Automated quick win",
                true,
                [
                    "Optional breakglass exclusion group Object ID",
                    "Administrator and engineer readiness review",
                    "Operator approval for a report-only Azure management policy"
                ],
                [
                    "Confirm the tenant is ready to monitor Azure-management sign-ins in report-only mode.",
                    "Exclude any emergency access or staged-rollout group before queueing the policy.",
                    "Create the policy in report-only mode and store the Graph response for traceability."
                ])
            {
                ExecutionSurface = "Microsoft Graph Conditional Access policy API targeting the Azure Resource Manager application.",
                NextStage = "Review Azure-management sign-in impact before enforcing the policy.",
                Targeting = new RemediationTemplateTargeting(
                    "Users",
                    "Targets all users for Azure Resource Manager access, with an optional exclusion group for breakglass or phased rollout.",
                    false,
                    true),
                SupportsLaunchModeSelection = true,
                DefaultLaunchMode = RemediationLaunchMode.ReportOnly,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.EntraIdP1]
            },
            new RemediationTemplate(
                "require-mfa-risky-sign-ins",
                "Require MFA when risky sign-ins are detected",
                "Creates a report-only Conditional Access policy for medium and high sign-in risk events.",
                "Promotes the sign-in-risk recommendation into a real queue-backed control so Identity Protection can move from a mapped backlog item into runnable tenant posture.",
                "Automated quick win",
                true,
                [
                    "Optional breakglass exclusion group Object ID",
                    "Identity Protection licensing review",
                    "Operator approval for a report-only risk policy"
                ],
                [
                    "Confirm the tenant can use Microsoft Entra risk detections and understands the report-only scope.",
                    "Exclude the right breakglass group before queueing the policy.",
                    "Create the policy in report-only mode and store the Graph response for traceability."
                ])
            {
                ExecutionSurface = "Microsoft Graph Conditional Access policy API with sign-in risk conditions.",
                NextStage = "Validate report-only outcomes, then decide whether the tenant is ready to enforce the risky sign-in policy.",
                Targeting = new RemediationTemplateTargeting(
                    "Users",
                    "Targets all users for medium and high sign-in risk events, excluding guests and protected admin roles by design, with an optional exclusion group for breakglass.",
                    false,
                    true),
                SupportsLaunchModeSelection = true,
                DefaultLaunchMode = RemediationLaunchMode.ReportOnly,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.EntraIdP2]
            },
            new RemediationTemplate(
                "require-password-change-high-risk-users",
                "Require password change for high-risk users",
                "Creates a report-only Conditional Access policy that requires MFA and password change for high user-risk accounts.",
                "Moves the high-risk user recommendation into the same queue-backed workflow as the other identity quick wins, while keeping the policy safely in report-only mode first.",
                "Automated quick win",
                true,
                [
                    "Optional breakglass exclusion group Object ID",
                    "Identity Protection licensing review",
                    "Operator approval for a report-only high-risk-user policy"
                ],
                [
                    "Confirm the tenant can use Microsoft Entra user risk detections and understands the remediation scope.",
                    "Exclude the right breakglass group before queueing the policy.",
                    "Create the policy in report-only mode and store the Graph response for traceability."
                ])
            {
                ExecutionSurface = "Microsoft Graph Conditional Access policy API with user risk conditions and password-change grant controls.",
                NextStage = "Use report-only outcomes to confirm remediation impact before deciding on enforcement.",
                Targeting = new RemediationTemplateTargeting(
                    "Users",
                    "Targets all users for high user-risk events, excluding guests and protected admin roles by design, with an optional exclusion group for breakglass.",
                    false,
                    true),
                SupportsLaunchModeSelection = true,
                DefaultLaunchMode = RemediationLaunchMode.ReportOnly,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.EntraIdP2]
            },
            new RemediationTemplate(
                "secure-security-info-registration",
                "Secure security info registration",
                "Creates a report-only Conditional Access policy that requires MFA for security info registration outside trusted locations.",
                "Implements Microsoft's registration-protection baseline with the built-in register-security-info user action, automatic guest exclusion, and trusted-location exclusion through AllTrusted.",
                "Automated quick win",
                true,
                [
                    "Breakglass exclusion strategy",
                    "Authentication method registration safety review",
                    "Operator approval for a report-only registration policy"
                ],
                [
                    "Confirm the tenant is ready to protect security info registration outside trusted locations.",
                    "Exclude the correct breakglass group before queueing the policy.",
                    "Create the policy in report-only mode and store the Graph response for traceability."
                ])
            {
                ExecutionSurface = "Microsoft Graph Conditional Access policy API using the register-security-info user action with AllTrusted location exclusion.",
                NextStage = "Review report-only registration events before enforcing the policy.",
                Targeting = new RemediationTemplateTargeting(
                    "Users and user actions",
                    "Targets the register-security-info user action for all users outside trusted locations, with guests excluded by design and an optional exclusion group for breakglass.",
                    false,
                    true),
                SupportsLaunchModeSelection = true,
                DefaultLaunchMode = RemediationLaunchMode.ReportOnly,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.EntraIdP1]
            },
            new RemediationTemplate(
                "entra-risk-policies",
                "Enable Entra risk policies",
                "Packages the risky sign-in and high-risk user Conditional Access controls into one operator workflow for Identity Protection rollout.",
                "Securityzator executes the two existing risk-policy quick wins as one queue-backed package so the tenant can move from mapped guidance into a staged risk-policy rollout.",
                "Automated policy package",
                true,
                [
                    "Optional breakglass exclusion group Object ID",
                    "Eligible Entra licensing",
                    "Breakglass exclusion strategy",
                    "Operator approval for a staged risk-policy rollout"
                ],
                [
                    "Validate licensing and confirm the tenant can use Microsoft Entra Identity Protection risk policies.",
                    "Optionally exclude a breakglass group for staged rollout safety.",
                    "Create or promote the risky sign-in and high-risk-user Conditional Access controls together through one queued package."
                ])
            {
                ExecutionSurface = "Microsoft Graph Conditional Access policy API, plus later program-level packaging across the specific risky-sign-in and high-risk-user quick wins.",
                NextStage = "Add richer threshold, pilot targeting, and readiness modeling so the package can evolve beyond the current medium/high-risk baseline pair.",
                Targeting = new RemediationTemplateTargeting(
                    "Users",
                    "Targets all users for Microsoft Entra risk-based controls, with an optional exclusion group for breakglass or staged rollout.",
                    false,
                    true),
                SupportsLaunchModeSelection = true,
                DefaultLaunchMode = RemediationLaunchMode.ReportOnly,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.EntraIdP2]
            },
            new RemediationTemplate(
                "entra-daily-use-hardening",
                "Entra daily-use consent and password hardening",
                "Applies the lowest-risk tenant-wide Entra daily-use settings by disabling default user consent, enabling the admin consent workflow, and keeping the default domain password-expiration posture aligned to never expire.",
                "This slice promotes the most supportable cloud-only Entra hygiene settings into direct-apply automation without pretending that broader role or hybrid posture is a one-click change.",
                "Automated baseline",
                true,
                [
                    "Azure connection with a stored client secret",
                    "Microsoft Graph Policy.ReadWrite.Authorization application permission",
                    "Microsoft Graph Policy.ReadWrite.ConsentRequest application permission",
                    "Microsoft Graph Domain.ReadWrite.All application permission",
                    "At least one active Global Administrator account for admin consent workflow reviewers if no reviewers are already configured"
                ],
                [
                    "Acquire a Microsoft Graph application token for Microsoft Entra tenant-setting automation.",
                    "Disable default user consent to apps and keep risky-app user consent disabled.",
                    "Enable the admin consent workflow with existing reviewers or active Global Administrators as the reviewer seed.",
                    "Set the default domain password-validity period to never expire when the tenant is not already aligned."
                ])
            {
                ExecutionSurface = "Microsoft Graph authorizationPolicy, adminConsentRequestPolicy, and domain update APIs.",
                NextStage = "Split out additional cloud-only Entra tenant settings once their write paths and rollback posture are validated.",
                CurrentBlockers =
                [
                    "This slice intentionally avoids broader role-design, separate-admin-identity, and hybrid-password controls because they still need governance review or hybrid visibility.",
                    "Admin consent workflow enablement needs reviewer coverage, so Securityzator seeds existing Global Administrators only when the tenant has no reviewer list yet.",
                    "If the app lacks the required write permissions, the run should fail clearly and leave the broader assessment path available."
                ],
                Targeting = new RemediationTemplateTargeting(
                    "Tenant-wide Microsoft Entra settings",
                    "Applies tenant-wide Microsoft Entra directory settings. No pilot group is used in this slice.",
                    false,
                    false),
                DefaultLaunchMode = RemediationLaunchMode.DirectApply,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.EntraIdP1]
            },
            new RemediationTemplate(
                "entra-identity-hygiene-baseline",
                "Entra admin and consent hygiene",
                "Runs a Microsoft Graph assessment for Entra app consent posture, admin consent workflow, self-service password reset, password-expiration posture, and active Global Administrator hygiene, while surfacing the remaining hybrid and governance items as explicit follow-up.",
                "The worker reads Microsoft Graph authorization policy, admin consent request policy, default domain settings, and Global Administrator membership so the Entra hygiene family can move out of draft status without pretending every item is a one-click tenant setting.",
                "Automated assessment",
                true,
                [
                    "Azure connection with a stored client secret",
                    "Microsoft Graph Policy.Read.All application permission",
                    "Microsoft Graph Directory.Read.All application permission"
                ],
                [
                    "Acquire a Microsoft Graph application token for Entra identity policy assessment.",
                    "Read the authorization policy, admin consent workflow, default domain password policy, and active Global Administrator membership.",
                    "Record which identity-hygiene controls are satisfied, which need tenant follow-up, and which still require manual or hybrid review."
                ])
            {
                ExecutionSurface = "Microsoft Graph authorizationPolicy, adminConsentRequestPolicy, domain, and directoryRoles assessment workflow.",
                NextStage = "Promote the cloud-only tenant settings that prove stable in assessment into direct-apply Entra administration helpers, while keeping hybrid and governance-heavy items as guided follow-up.",
                CurrentBlockers =
                [
                    "Several identity-hygiene controls are governance-heavy or hybrid-dependent, so this slice assesses them honestly instead of forcing direct-apply changes.",
                    "Password hash sync, on-prem password protection, custom banned-password lists, and broader sign-in frequency posture still need hybrid or Conditional Access-specific validation outside this first assessment.",
                    "Separate admin identities, least-privilege role design, and third-party app restrictions still need human review even when Graph exposes related posture signals."
                ],
                Targeting = new RemediationTemplateTargeting(
                    "Tenant-wide Microsoft Entra policy assessment",
                    "Runs tenant-wide against Microsoft Entra directory and policy settings. No pilot group is required for this report-only assessment.",
                    false,
                    false),
                DefaultLaunchMode = RemediationLaunchMode.ReportOnly,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.EntraIdP1]
            },
            new RemediationTemplate(
                "require-phishing-resistant-mfa-admins",
                "Require phishing-resistant MFA for privileged admins",
                "Creates a report-only Conditional Access policy that requires the built-in Phishing resistant MFA authentication strength for a chosen privileged-admin group.",
                "Extends the existing Conditional Access automation path so administrator sign-ins can move from baseline MFA into a stronger report-only control with the same audit trail.",
                "Automated quick win",
                true,
                [
                    "Privileged admin group Object ID",
                    "Breakglass exclusion strategy"
                ],
                [
                    "Confirm the privileged admin group that belongs in scope.",
                    "Review phishing-resistant method readiness before broad enforcement.",
                    "Create the policy in report-only mode first and store the Graph response for traceability."
                ])
            {
                ExecutionSurface = "Microsoft Graph Conditional Access policy API with built-in authentication strengths.",
                NextStage = "Keep the policy in report-only mode until the tenant confirms phishing-resistant method readiness for the targeted admins.",
                Targeting = new RemediationTemplateTargeting(
                    "Users and groups",
                    "Targets the chosen privileged-admin group, with an optional exclusion group for breakglass or staged rollout.",
                    true,
                    true),
                SupportsLaunchModeSelection = true,
                DefaultLaunchMode = RemediationLaunchMode.ReportOnly,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.EntraIdP1]
            },
            new RemediationTemplate(
                "mdo-anti-phishing-and-impersonation",
                "Defender for Office anti-phishing and impersonation",
                "Applies a managed Defender for Office anti-phish baseline across mailbox intelligence, impersonated-domain protection, privileged-user impersonation seeding, and safety tips using certificate-backed Exchange Online automation.",
                "The worker uses Microsoft Graph to seed a protected-user list from privileged role members, then connects to Exchange Online PowerShell with the saved automation certificate and creates or updates the Securityzator anti-phish policy and rule.",
                "Automated baseline",
                true,
                [
                    "Azure connection with a usable automation certificate",
                    "Office 365 Exchange Online application permission Exchange.ManageAsApp",
                    "Microsoft Entra admin role assignment such as Exchange Administrator",
                    "Directory read permission for privileged-user discovery",
                    "ExchangeOnlineManagement PowerShell module on the worker host"
                ],
                [
                    "Acquire a Microsoft Graph application token and derive a protected-user seed list from activated privileged roles.",
                    "Connect to Exchange Online PowerShell with the saved certificate-backed app identity.",
                    "Create or update the Securityzator anti-phish policy with mailbox intelligence, impersonated-domain protection, safety tips, and phish threshold tuning.",
                    "Create or update the Securityzator anti-phish rule for all accepted domains.",
                    "Capture readback state and preserve a note when protected-user follow-up still needs an operator decision."
                ])
            {
                ExecutionSurface = "Exchange Online PowerShell app-only automation with Microsoft Graph privileged-user discovery.",
                NextStage = "Expand the baseline into spoof-protection, explicit allowlist review, and safer protected-user scoping once tenant-specific exception handling matures.",
                Targeting = new RemediationTemplateTargeting(
                    "Tenant-wide anti-phish protection",
                    "Applies tenant-wide mailbox-intelligence and impersonated-domain protections while seeding targeted user protection from discovered privileged accounts.",
                    false,
                    false),
                DefaultLaunchMode = RemediationLaunchMode.DirectApply,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.DefenderForOfficePlan1]
            },
            new RemediationTemplate(
                "mdo-safe-links-and-attachments",
                "Defender for Office Safe Links and attachments",
                "Applies a Business Premium-friendly Defender for Office baseline across Safe Links, Safe Attachments, and the SharePoint/OneDrive/Teams protection switch using certificate-backed Exchange Online automation.",
                "The worker connects to Exchange Online PowerShell with the saved automation certificate, enables Defender for Office scanning for SharePoint/OneDrive/Teams, creates or updates the Securityzator Safe Links and Safe Attachments policies, and records readback state for the resulting baseline.",
                "Automated baseline",
                true,
                [
                    "Azure connection with a usable automation certificate",
                    "Office 365 Exchange Online application permission Exchange.ManageAsApp",
                    "Microsoft Entra admin role assignment such as Exchange Administrator",
                    "ExchangeOnlineManagement PowerShell module on the worker host"
                ],
                [
                    "Connect to Exchange Online PowerShell with the saved certificate-backed app identity.",
                    "Enable Defender for Office protection for SharePoint, OneDrive, and Teams.",
                    "Create or update the Securityzator Safe Links policy and rule for all accepted domains.",
                    "Create or update the Securityzator Safe Attachments policy and rule in block mode for all accepted domains.",
                    "Capture readback state and preserve a note that Safe Documents remains licensing-dependent."
                ])
            {
                ExecutionSurface = "Exchange Online PowerShell app-only automation using a Windows certificate-backed service principal.",
                NextStage = "Expand this first Defender slice into anti-phishing, ZAP, and spam or forwarding controls once Exchange readiness and rollback handling mature.",
                Targeting = new RemediationTemplateTargeting(
                    "Tenant-wide mail protection",
                    "Applies tenant-wide Defender for Office Safe Links, Safe Attachments, and SharePoint/OneDrive/Teams protection settings.",
                    false,
                    false),
                DefaultLaunchMode = RemediationLaunchMode.DirectApply,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.DefenderForOfficePlan1]
            },
            new RemediationTemplate(
                "mdo-spam-and-forwarding-baseline",
                "Defender for Office spam and forwarding hardening",
                "Applies a managed Defender for Office baseline across inbound spam filtering, outbound forwarding posture, and recipient throttling using certificate-backed Exchange Online automation.",
                "The worker connects to Exchange Online PowerShell with the saved automation certificate, creates or updates Securityzator inbound spam and outbound forwarding policies, records readback state, and preserves follow-up notes for connection-filter or mail-flow items that still need operator review.",
                "Automated baseline",
                true,
                [
                    "Azure connection with a usable automation certificate",
                    "Office 365 Exchange Online application permission Exchange.ManageAsApp",
                    "Microsoft Entra admin role assignment such as Exchange Administrator",
                    "ExchangeOnlineManagement PowerShell module on the worker host"
                ],
                [
                    "Connect to Exchange Online PowerShell with the saved certificate-backed app identity.",
                    "Create or update the Securityzator inbound spam policy and rule for all accepted domains, with quarantine actions, ZAP, and an empty sender allowlist.",
                    "Create or update the Securityzator outbound spam or forwarding policy and rule with Automatic external forwarding, recipient limits, and threshold blocking.",
                    "Capture readback state and preserve notes for any connection-filter allowlist entries or remaining mail-flow follow-up items."
                ])
            {
                ExecutionSurface = "Exchange Online Protection and outbound spam PowerShell automation using a Windows certificate-backed service principal.",
                NextStage = "Expand this slice into transport-rule, connection-filter, and more tenant-specific mail-flow exception handling once rollback and staged rollout are mature.",
                Targeting = new RemediationTemplateTargeting(
                    "Tenant-wide mail flow and spam protection",
                    "Applies tenant-wide inbound spam filtering and outbound forwarding safeguards across all accepted domains.",
                    false,
                    false),
                DefaultLaunchMode = RemediationLaunchMode.DirectApply,
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.DefenderForOfficePlan1]
            },
            new RemediationTemplate(
                "exchange-online-collaboration-and-mailbox",
                "Exchange Online collaboration and mailbox hardening",
                "Applies a managed Exchange Online baseline across mailbox auditing, MailTips, Outlook add-in restriction, modern authentication, and Outlook on the web storage-provider hardening.",
                "The worker connects to Exchange Online PowerShell with the saved automation certificate, updates low-risk organization and OWA policy settings, and captures follow-up notes for sharing-policy review and licensing-dependent items.",
                "Automated baseline",
                true,
                [
                    "Azure connection with a usable automation certificate",
                    "Office 365 Exchange Online application permission Exchange.ManageAsApp",
                    "Microsoft Entra admin role assignment such as Exchange Administrator",
                    "ExchangeOnlineManagement PowerShell module on the worker host"
                ],
                [
                    "Connect to Exchange Online PowerShell with the saved certificate-backed app identity.",
                    "Enable mailbox auditing, MailTips, and modern authentication at the organization level.",
                    "Disable Outlook add-ins at the organization level and restrict additional storage providers on the default Outlook on the web mailbox policy.",
                    "Capture the default sharing-policy state and preserve follow-up notes for external calendar sharing and Customer Lockbox."
                ])
            {
                ExecutionSurface = "Exchange Online PowerShell app-only automation using a Windows certificate-backed service principal.",
                NextStage = "Split sharing-policy enforcement, customer lockbox posture, and any tenant-specific add-in exceptions into their own rollout-safe follow-up jobs.",
                Targeting = new RemediationTemplateTargeting(
                    "Tenant-wide Exchange collaboration settings",
                    "Applies low-risk organization and default OWA policy settings across the tenant, while keeping sharing-policy review as explicit operator follow-up.",
                    false,
                    false),
                DefaultLaunchMode = RemediationLaunchMode.DirectApply
            },
            new RemediationTemplate(
                "purview-data-protection-baseline",
                "Purview data protection baseline",
                "Groups DLP, audit log visibility, sensitivity labeling, and auto-labeling work into one Purview-oriented playbook.",
                "This gives the Business Premium data-protection controls a clear home in the portal even before each compliance action is automated.",
                "Control set draft",
                false,
                [
                    "Purview ownership",
                    "Azure Information Protection Premium P2 or equivalent Purview licensing confirmation",
                    "Classification policy scope",
                    "Audit and retention requirements"
                ],
                [
                    "Review the tenant's data protection recommendations as one baseline.",
                    "Choose which labeling and DLP steps are ready for deeper productization.",
                    "Promote the lowest-risk compliance tasks into guided workflows or later queue automation."
                ])
            {
                ExecutionSurface = "Planned Purview and compliance administration provider.",
                NextStage = "Use EMS E5 or equivalent Purview licensing to clear the advanced-labeling blocker, then break the baseline into audit-log, DLP, and labeling slices so each can get its own validation and rollout model.",
                CurrentBlockers =
                [
                    "This baseline depends on Purview and compliance administration surfaces that the current app does not yet manage.",
                    "DLP, labeling, and auto-labeling controls need classification-scope and business-owner decisions before automation is safe.",
                    "Advanced auto-labeling and recommended-classification work still needs Azure Information Protection Premium P2 or equivalent Purview licensing."
                ],
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.InformationProtectionPlan2]
            },
            new RemediationTemplate(
                "teams-meeting-hardening",
                "Teams meeting hardening baseline",
                "Applies the Securityzator Teams meeting baseline directly to the Global Teams meeting policy for admission, presenter, anonymous-access, and external-control settings.",
                "The worker connects through Teams PowerShell app-based authentication, captures the current Global policy state, applies the baseline, and stores before and after posture details in the remediation run log.",
                "Automated baseline",
                true,
                [
                    "Connection profile with a stored client secret",
                    "Microsoft Graph Organization.Read.All and Teams Administrator role assignment for the app",
                    "MicrosoftTeams PowerShell module on the worker host"
                ],
                [
                    "Read the current Global Teams meeting policy before any change is made.",
                    "Apply the Securityzator baseline to invited-user admission, presenter defaults, anonymous access, PSTN lobby bypass, and external control.",
                    "Read the Global policy again and store the before and after posture in the run history."
                ])
            {
                ExecutionSurface = "MicrosoftTeams PowerShell module using app-based authentication and Global meeting policy readback.",
                NextStage = "Add named policy creation and scoped assignment so the Teams baseline can move beyond the Global policy when the product is ready.",
                Targeting = new RemediationTemplateTargeting(
                    "Tenant-wide collaboration policy",
                    "Applies the baseline directly to the tenant's Global Teams meeting policy.",
                    false,
                    false),
                DefaultLaunchMode = RemediationLaunchMode.DirectApply
            },
            new RemediationTemplate(
                "sharepoint-online-session-hardening",
                "SharePoint session and authentication hardening",
                "Covers the low-friction SharePoint Online session timeout and modern-auth requirements that fit the current license tier.",
                "This keeps the SharePoint surface visible in the portal while we design the safer automation path for collaboration controls.",
                "Control set draft",
                false,
                [
                    "SharePoint admin ownership",
                    "Session timeout decision",
                    "App authentication review"
                ],
                [
                    "Review the mapped SharePoint hardening controls.",
                    "Decide whether they belong in a broader collaboration baseline or a standalone automation slice.",
                    "Promote them into worker automation once the payload is locked."
                ])
            {
                ExecutionSurface = "Planned SharePoint Online administration provider.",
                NextStage = "Add SharePoint admin configuration support, then promote session timeout and modern-auth checks into runnable controls.",
                CurrentBlockers =
                [
                    "The current app does not manage SharePoint Online tenant settings.",
                    "Session timeout and app-authentication changes can disrupt user workflows and need a clearer exception model.",
                    "We do not yet have readback verification or rollback support for SharePoint settings."
                ]
            },
            new RemediationTemplate(
                "defender-cloud-apps-foundation",
                "Defender for Cloud Apps discovery",
                "Tracks the tenant onboarding and shadow IT discovery work needed before deeper SaaS hardening can move into automation.",
                "Keeps the recommendation-to-playbook path intact even when the first implementation step is still guided onboarding instead of a worker action.",
                "Guided enablement",
                false,
                [
                    "EMS E5, standalone Defender for Cloud Apps, or equivalent licensing confirmation",
                    "Defender portal onboarding plan",
                    "Cloud app discovery scope"
                ],
                [
                    "Validate licensing and confirm the onboarding path for Defender for Cloud Apps.",
                    "Enable discovery and collect the first shadow IT signals.",
                    "Use the resulting posture to unlock deeper app-governance playbooks."
                ])
            {
                ExecutionSurface = "Defender for Cloud Apps onboarding and discovery workflow.",
                NextStage = "Use EMS E5 or equivalent Defender for Cloud Apps licensing to clear the product blocker, then add discovery-state tracking before deeper control automation.",
                CurrentBlockers =
                [
                    "The tenant still needs Defender for Cloud Apps licensing and product onboarding before discovery or governance automation can start.",
                    "Discovery depends on log-source and integration decisions that the current app does not capture.",
                    "There is no Defender for Cloud Apps provider in the platform yet."
                ],
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.DefenderForCloudApps]
            },
            new RemediationTemplate(
                "defender-identity-foundation",
                "Defender for Identity foundation",
                "Tracks the sensor deployment and onboarding work needed before Defender for Identity detections and controls become operational.",
                "This keeps the recommendation visible as an onboarding playbook rather than an unmapped row while the product matures.",
                "Guided enablement",
                false,
                [
                    "Directory admin ownership",
                    "EMS E5, standalone Defender for Identity, or equivalent licensing confirmation",
                    "Eligible server inventory",
                    "Sensor deployment plan"
                ],
                [
                    "Validate the domain controller and eligible server scope.",
                    "Plan and execute sensor deployment in a controlled rollout.",
                    "Use the resulting telemetry to inform later identity-detection playbooks."
                ])
            {
                ExecutionSurface = "Defender for Identity sensor deployment and workspace onboarding.",
                NextStage = "Use EMS E5 or equivalent Defender for Identity licensing to clear the product blocker, then add discovery of eligible servers and deployment-state tracking before attempting any guided automation.",
                CurrentBlockers =
                [
                    "Defender for Identity still needs product licensing plus server-side sensor deployment outside the current tenant-only app model.",
                    "The platform has no server inventory, installation workflow, or deployment health validation for sensors.",
                    "This is an onboarding and infrastructure task, not a simple Graph setting."
                ],
                RequiredLicenseCapabilities = [TenantLicenseCapabilityCatalog.DefenderForIdentity]
            },
            new RemediationTemplate(
                "protect-breakglass",
                "Protect breakglass accounts with exclusions and monitoring",
                "Tracks the tenant-specific discovery needed before breakglass accounts can be consistently excluded from automated controls and monitored safely.",
                "This keeps the identity resiliency work visible in the product instead of burying it in side notes outside the recommendation flow.",
                "Discovery playbook",
                false,
                [
                    "Breakglass account inventory",
                    "Exclusion group design",
                    "Monitoring and alerting owner"
                ],
                [
                    "Identify the tenant's approved breakglass accounts and how they are maintained.",
                    "Decide which policies and automations must exclude them by default.",
                    "Define the monitoring path so emergency accounts stay visible and controlled."
                ])
            {
                ExecutionSurface = "Tenant-specific identity discovery and monitoring workflow.",
                NextStage = "Create a reusable breakglass inventory model in the app so later automations can consume it safely.",
                CurrentBlockers =
                [
                    "Breakglass account inventory is tenant-specific and not stored in the app yet.",
                    "There is no shared exclusion model that other playbooks can reuse automatically.",
                    "Monitoring and alerting for emergency account usage are not wired into the platform."
                ]
            },
            new RemediationTemplate(
                "workload-identity-review",
                "Review risky sign-in coverage for workload identities",
                "Keeps workload identity discovery and coverage analysis visible before the app starts automating service principal protection decisions.",
                "This is a discovery playbook because the right control path depends on tenant app inventory, telemetry, and licensing rather than a single toggle.",
                "Discovery playbook",
                false,
                [
                    "Application and service principal inventory",
                    "Available workload identity telemetry",
                    "Owner for remediation decisions"
                ],
                [
                    "Identify the workload identities that matter in the tenant.",
                    "Review what telemetry and protections are already available for those identities.",
                    "Choose whether later automation belongs in Conditional Access, app governance, or manual operations."
                ])
            {
                ExecutionSurface = "Discovery workflow across service principals, workload identity telemetry, and app governance.",
                NextStage = "Add workload identity inventory and telemetry visibility before defining any runnable remediation path.",
                CurrentBlockers =
                [
                    "The platform does not yet inventory service principals or workload identity posture.",
                    "Licensing and telemetry prerequisites need to be confirmed before we can automate coverage decisions.",
                    "There is no chosen execution surface yet for these protections."
                ]
            },
            new RemediationTemplate(
                "defender-endpoint-attack-surface-reduction",
                "Defender for Endpoint attack surface reduction",
                "Applies the first Intune-backed Securityzator ASR baseline for Office or script abuse, ransomware protection, WMI persistence, LSASS credential-theft protection, and related executable control rules to a pilot Microsoft Entra group.",
                "The worker uses Microsoft Graph Intune device-configuration APIs to create or update a managed windows10EndpointProtectionConfiguration profile, assigns it to the selected pilot group, records readback state, and preserves notes for the remaining ASR-adjacent items that still need browser, Adobe, or server-specific management surfaces.",
                "Automated baseline",
                true,
                [
                    "Azure connection with a stored client secret",
                    "Microsoft Graph DeviceManagementConfiguration.ReadWrite.All application permission",
                    "Pilot Microsoft Entra group for device or user assignment",
                    "Optional exclusion group for staged rollout safety",
                    "Active Intune licensing and enrolled pilot devices"
                ],
                [
                    "Acquire a Microsoft Graph application token for Intune endpoint protection automation.",
                    "Create or update the Securityzator managed Windows attack surface reduction profile.",
                    "Assign the profile to the selected pilot group with an optional exclusion group for staged rollout safety.",
                    "Capture configuration and assignment readback for audit and drift tracking.",
                    "Preserve follow-up notes for Flash, Adobe JavaScript, webshell, Safe Mode, and other residual ASR-related controls that still need another execution surface."
                ])
            {
                ExecutionSurface = "Microsoft Graph Intune deviceManagement or deviceConfigurations API with Windows 10 endpoint protection configuration profiles.",
                NextStage = "Extend this ASR slice into browser or Adobe or server-specific protections, then layer in device validation and narrower exclusion handling for higher-impact rules.",
                CurrentBlockers =
                [
                    "Browser, Adobe JavaScript, Flash, webshell, Safe Mode, and some server-specific ASR controls still need a different endpoint or application-management surface than this first Intune baseline.",
                    "Device-level validation still depends on enrolled pilot devices and later readback enhancements beyond configuration creation.",
                    "This slice assumes pilot-group rollout rather than broad tenant-wide device enforcement."
                ],
                Targeting = new RemediationTemplateTargeting(
                    "Pilot devices or users via Microsoft Entra groups",
                    "Assigns the ASR baseline to a chosen Microsoft Entra pilot group, with an optional exclusion group for staged rollout or breakglass safety.",
                    true,
                    true),
                DefaultLaunchMode = RemediationLaunchMode.DirectApply,
                RequiredLicenseCapabilities =
                [
                    TenantLicenseCapabilityCatalog.IntunePlan1,
                    TenantLicenseCapabilityCatalog.DefenderForBusiness
                ]
            },
            new RemediationTemplate(
                "defender-endpoint-firewall-and-smartscreen",
                "Defender Firewall and SmartScreen baseline",
                "Applies a managed Intune package for Microsoft Defender Firewall posture, Windows SmartScreen app/file checking, and Microsoft Edge SmartScreen site/download protections to a pilot Microsoft Entra group.",
                "The worker uses Microsoft Graph Intune endpoint-protection and group policy configuration APIs to create or update a managed windows10EndpointProtectionConfiguration profile plus a companion Edge group policy profile, assigns both to the selected pilot group, records readback state, and preserves notes for broader browser controls that still need another surface.",
                "Automated baseline",
                true,
                [
                    "Azure connection with a stored client secret",
                    "Microsoft Graph DeviceManagementConfiguration.ReadWrite.All application permission",
                    "Pilot Microsoft Entra group for device or user assignment",
                    "Optional exclusion group for staged rollout safety",
                    "Active Intune licensing and enrolled pilot devices"
                ],
                [
                    "Acquire a Microsoft Graph application token for Intune configuration automation.",
                    "Create or update the Securityzator managed firewall endpoint-protection profile and the companion Edge SmartScreen group policy profile.",
                    "Assign both profiles to the selected pilot group with an optional exclusion group for staged rollout safety.",
                    "Capture configuration and assignment readback for both profiles for audit and drift tracking.",
                    "Preserve follow-up notes for broader browser controls that still need another management surface."
                ])
            {
                ExecutionSurface = "Microsoft Graph Intune deviceManagement or deviceConfigurations API with Windows 10 endpoint-protection configuration profiles plus groupPolicyConfigurations for Microsoft Edge settings.",
                NextStage = "Keep layering narrower browser and application-hardening slices on top of this package, then add deeper firewall merge and notification posture once the broader endpoint provider matures.",
                CurrentBlockers =
                [
                    "Residual browser and host-hardening controls still belong in narrower follow-on families.",
                    "Adobe-specific browser or reader controls still need a different management surface on this tenant.",
                    "This slice assumes pilot-group rollout rather than broad tenant-wide device enforcement."
                ],
                Targeting = new RemediationTemplateTargeting(
                    "Pilot devices or users via Microsoft Entra groups",
                    "Assigns the baseline to a chosen Microsoft Entra pilot group, with an optional exclusion group for staged rollout or breakglass safety.",
                    true,
                    true),
                DefaultLaunchMode = RemediationLaunchMode.DirectApply,
                RequiredLicenseCapabilities =
                [
                    TenantLicenseCapabilityCatalog.IntunePlan1,
                    TenantLicenseCapabilityCatalog.DefenderForBusiness
                ]
            },
            new RemediationTemplate(
                "defender-endpoint-bitlocker-baseline",
                "Defender BitLocker startup baseline",
                "Applies a managed Intune endpoint-protection baseline for Windows device encryption and BitLocker startup authentication to a pilot Microsoft Entra group.",
                "The worker uses Microsoft Graph Intune endpoint-protection configuration APIs to create or update a managed windows10EndpointProtectionConfiguration profile, assigns it to the selected pilot group, records readback state, and follows the rollout with managed-device encryption telemetry so BitLocker assignment, readiness, and encryption state are visible in the run history.",
                "Automated baseline",
                true,
                [
                    "Azure connection with a stored client secret",
                    "Microsoft Graph DeviceManagementConfiguration.ReadWrite.All application permission",
                    "Pilot Microsoft Entra group for device or user assignment",
                    "Optional exclusion group for staged rollout safety",
                    "Active Intune licensing and enrolled pilot devices"
                ],
                [
                    "Acquire a Microsoft Graph application token for Intune configuration automation.",
                    "Create or update the Securityzator managed BitLocker startup and device-encryption profile.",
                    "Assign the profile to the selected pilot group with an optional exclusion group for staged rollout safety.",
                    "Capture configuration and assignment readback for audit and drift tracking.",
                    "Assess managed-device encryption telemetry so BitLocker encryption state, readiness, and reported policy assignment are visible for the pilot scope."
                ])
            {
                ExecutionSurface = "Microsoft Graph Intune deviceManagement or deviceConfigurations API with Windows 10 endpoint-protection configuration profiles plus beta managedDeviceEncryptionStates telemetry for rollout-health validation.",
                NextStage = "Extend this slice into recovery escrow validation and broader drive-state verification once richer escrow and recovery telemetry is available.",
                CurrentBlockers =
                [
                    "Recovery escrow confirmation and hands-on remediation for TPM, firmware, or readiness blockers still need device-level follow-up beyond this first rollout-health slice.",
                    "BitLocker rollout-health validation depends on Microsoft Graph beta managedDeviceEncryptionStates telemetry, so the assessment path needs watching as that endpoint evolves.",
                    "This slice assumes pilot-group rollout rather than broad tenant-wide device enforcement."
                ],
                Targeting = new RemediationTemplateTargeting(
                    "Pilot devices or users via Microsoft Entra groups",
                    "Assigns the baseline to a chosen Microsoft Entra pilot group, with an optional exclusion group for staged rollout or breakglass safety.",
                    true,
                    true),
                DefaultLaunchMode = RemediationLaunchMode.DirectApply,
                RequiredLicenseCapabilities =
                [
                    TenantLicenseCapabilityCatalog.IntunePlan1,
                    TenantLicenseCapabilityCatalog.DefenderForBusiness
                ]
            },
            new RemediationTemplate(
                "defender-endpoint-credential-and-elevation-hardening",
                "Defender credential and elevation hardening",
                "Applies a managed Intune custom-configuration baseline for Windows credential protection, credential storage restrictions, and UAC elevation hardening to a pilot Microsoft Entra group.",
                "The worker uses Microsoft Graph Intune device-configuration APIs to create or update a managed windows10CustomConfiguration profile backed by Policy CSP OMA settings, assigns it to the selected pilot group, records readback state, and preserves notes for adjacent credential and remote-management items that still need another surface.",
                "Automated baseline",
                true,
                [
                    "Azure connection with a stored client secret",
                    "Microsoft Graph DeviceManagementConfiguration.ReadWrite.All application permission",
                    "Pilot Microsoft Entra group for device or user assignment",
                    "Optional exclusion group for staged rollout safety",
                    "Active Intune licensing and enrolled pilot devices"
                ],
                [
                    "Acquire a Microsoft Graph application token for Intune configuration automation.",
                    "Create or update the Securityzator managed Windows credential and elevation hardening profile.",
                    "Assign the profile to the selected pilot group with an optional exclusion group for staged rollout safety.",
                    "Capture configuration and assignment readback for audit and drift tracking.",
                    "Preserve follow-up notes for WinRM Basic authentication, Remote Assistance, and other adjacent hardening items that still need another management surface."
                ])
            {
                ExecutionSurface = "Microsoft Graph Intune deviceManagement or deviceConfigurations API with Windows 10 custom configuration profiles using Policy CSP OMA settings.",
                NextStage = "Extend this slice into deeper WinRM, Remote Assistance, and broader credential-isolation controls once the custom OMA lane is proven more deeply.",
                CurrentBlockers =
                [
                    "WinRM Basic authentication, Remote Assistance, and some adjacent controls still need additional CSP coverage or ADMX-backed handling beyond this custom OMA slice.",
                    "Credential Guard and related virtualization-based protections still need device-edition and reboot validation beyond configuration creation.",
                    "This slice assumes pilot-group rollout rather than broad tenant-wide device enforcement."
                ],
                Targeting = new RemediationTemplateTargeting(
                    "Pilot devices or users via Microsoft Entra groups",
                    "Assigns the baseline to a chosen Microsoft Entra pilot group, with an optional exclusion group for staged rollout or breakglass safety.",
                    true,
                    true),
                DefaultLaunchMode = RemediationLaunchMode.DirectApply,
                RequiredLicenseCapabilities =
                [
                    TenantLicenseCapabilityCatalog.IntunePlan1,
                    TenantLicenseCapabilityCatalog.DefenderForBusiness
                ]
            },
            new RemediationTemplate(
                "defender-endpoint-remote-access-and-network-hardening",
                "Defender remote access and network hardening",
                "Applies a managed Intune custom-configuration baseline for WinRM Basic authentication, Remote Assistance, network bridge, Internet Connection Sharing, network location elevation, and non-volume AutoPlay hardening to a pilot Microsoft Entra group.",
                "The worker uses Microsoft Graph Intune device-configuration APIs to create or update a managed windows10CustomConfiguration profile backed by Policy CSP OMA settings, assigns it to the selected pilot group, records readback state, and preserves notes for adjacent remote-desktop, Autorun, SMBv1, and other network-surface items that still need another surface.",
                "Automated baseline",
                true,
                [
                    "Azure connection with a stored client secret",
                    "Microsoft Graph DeviceManagementConfiguration.ReadWrite.All application permission",
                    "Pilot Microsoft Entra group for device or user assignment",
                    "Optional exclusion group for staged rollout safety",
                    "Active Intune licensing and enrolled pilot devices"
                ],
                [
                    "Acquire a Microsoft Graph application token for Intune configuration automation.",
                    "Create or update the Securityzator managed Windows remote access and network hardening profile.",
                    "Assign the profile to the selected pilot group with an optional exclusion group for staged rollout safety.",
                    "Capture configuration and assignment readback for audit and drift tracking.",
                    "Preserve follow-up notes for broader browser-adjacent and compatibility-sensitive host-hardening controls that still need another management surface."
                ])
            {
                ExecutionSurface = "Microsoft Graph Intune deviceManagement or deviceConfigurations API with Windows 10 custom configuration profiles using Policy CSP OMA settings.",
                NextStage = "Extend this slice into broader browser-adjacent and deeper network-surface controls once the custom OMA lane is proven more broadly.",
                CurrentBlockers =
                [
                    "Several adjacent browser, Adobe, and compatibility-sensitive host-hardening controls still need additional CSP coverage, application-specific policy surfaces, or another management surface.",
                    "Several controls in this area can affect compatibility and should stay staged behind pilot-group validation.",
                    "This slice assumes pilot-group rollout rather than broad tenant-wide device enforcement."
                ],
                Targeting = new RemediationTemplateTargeting(
                    "Pilot devices or users via Microsoft Entra groups",
                    "Assigns the baseline to a chosen Microsoft Entra pilot group, with an optional exclusion group for staged rollout or breakglass safety.",
                    true,
                    true),
                DefaultLaunchMode = RemediationLaunchMode.DirectApply,
                RequiredLicenseCapabilities =
                [
                    TenantLicenseCapabilityCatalog.IntunePlan1,
                    TenantLicenseCapabilityCatalog.DefenderForBusiness
                ]
            },
            new RemediationTemplate(
                "defender-endpoint-browser-hardening",
                "Defender browser hardening baseline",
                "Applies a managed Intune browser-hardening baseline for Google Chrome background apps, AutoFill, password manager, and third-party cookie posture to a pilot Microsoft Entra group.",
                "The worker uses Microsoft Graph Intune group-policy configuration APIs to create or update a managed browser baseline, assigns it to the selected pilot group, records readback state, and preserves notes for removed Chrome policies and Adobe controls that still need another surface.",
                "Automated baseline",
                true,
                [
                    "Azure connection with a stored client secret",
                    "Microsoft Graph DeviceManagementConfiguration.ReadWrite.All application permission",
                    "Pilot Microsoft Entra group for device or user assignment",
                    "Optional exclusion group for staged rollout safety",
                    "Active Intune licensing and enrolled pilot devices"
                ],
                [
                    "Acquire a Microsoft Graph application token for Intune configuration automation.",
                    "Create or update the Securityzator managed browser hardening group policy configuration.",
                    "Apply the Chrome background-app, AutoFill, password-manager, and third-party cookie controls.",
                    "Assign the browser baseline to the selected pilot group with an optional exclusion group for staged rollout safety.",
                    "Capture configuration and assignment readback for audit and drift tracking."
                ])
            {
                ExecutionSurface = "Microsoft Graph Intune deviceManagement or groupPolicyConfigurations API with Chrome ADMX-backed group policy definitions.",
                NextStage = "Extend this slice into Microsoft Edge, Adobe, and other browser-aware policy families once the first Chrome lane is proven more deeply.",
                CurrentBlockers =
                [
                    "The outdated Chrome plugins Secure Score control currently lands only on removed Chrome policies in Intune, so Securityzator keeps it as residual follow-up instead of durable automation coverage.",
                    "Adobe JavaScript and Flash controls still need a different software-aware policy surface.",
                    "This slice assumes pilot-group rollout rather than broad tenant-wide device enforcement."
                ],
                Targeting = new RemediationTemplateTargeting(
                    "Pilot devices or users via Microsoft Entra groups",
                    "Assigns the baseline to a chosen Microsoft Entra pilot group, with an optional exclusion group for staged rollout or breakglass safety.",
                    true,
                    true),
                DefaultLaunchMode = RemediationLaunchMode.DirectApply,
                RequiredLicenseCapabilities =
                [
                    TenantLicenseCapabilityCatalog.IntunePlan1,
                    TenantLicenseCapabilityCatalog.DefenderForBusiness
                ]
            },
            new RemediationTemplate(
                "defender-endpoint-browser-and-adobe-policy-surface-readiness",
                "Defender browser and Adobe policy-surface readiness",
                "Assesses whether Intune exposes the durable Chrome and Adobe policy surfaces Securityzator would need before the remaining browser-app controls can become real automation.",
                "The worker uses Microsoft Graph Intune groupPolicyDefinitions and groupPolicyUploadedDefinitionFiles to check whether the outdated Chrome plug-in policy is still exposed and whether Adobe Acrobat or Reader ADMX-backed definitions are available for JavaScript and Flash controls.",
                "Automated assessment",
                true,
                [
                    "Azure connection with a stored client secret",
                    "Microsoft Graph DeviceManagementConfiguration.Read.All or DeviceManagementConfiguration.ReadWrite.All application permission",
                    "Active Intune licensing"
                ],
                [
                    "Acquire a Microsoft Graph application token for Intune policy-surface assessment.",
                    "Enumerate Intune group policy definitions for the remaining Chrome outdated plug-in control.",
                    "Enumerate uploaded ADMX definition files and Adobe policy definitions for Acrobat or Reader JavaScript and Flash controls.",
                    "Record tenant findings so the remaining browser-app controls stop living as generic backlog."
                ])
            {
                ExecutionSurface = "Microsoft Graph Intune beta groupPolicyDefinitions and groupPolicyUploadedDefinitionFiles assessment workflow.",
                NextStage = "If the tenant exposes the Adobe and Chrome policy surfaces cleanly, port those controls into a dedicated browser-app baseline instead of leaving them as readiness findings.",
                CurrentBlockers =
                [
                    "The outdated Chrome plug-in control does not currently show up as a durable Intune definition on this tenant.",
                    "Adobe JavaScript and Flash controls depend on Adobe ADMX import and surfaced definitions, which are not present in the current app-only path.",
                    "This slice is tenant-readiness assessment, not a live device configuration change."
                ],
                Targeting = new RemediationTemplateTargeting(
                    "Tenant-wide Intune policy surface",
                    "Assesses whether the tenant exposes the Intune policy definitions needed before the remaining Chrome and Adobe controls can become durable automation.",
                    false,
                    false),
                DefaultLaunchMode = RemediationLaunchMode.ReportOnly,
                RequiredLicenseCapabilities =
                [
                    TenantLicenseCapabilityCatalog.IntunePlan1,
                    TenantLicenseCapabilityCatalog.DefenderForBusiness
                ]
            },
            new RemediationTemplate(
                "defender-endpoint-core-protection",
                "Defender for Endpoint core protection baseline",
                "Applies Securityzator's first Intune-backed endpoint protection package for Defender Antivirus, cloud protection, PUA blocking, network protection, and tamper protection to a pilot Microsoft Entra group.",
                "The worker uses Microsoft Graph Intune device-configuration APIs to create or update a managed windows10GeneralConfiguration profile plus a companion windows10EndpointProtectionConfiguration profile, assigns both to the selected pilot group, records readback state, and preserves notes for the remaining core-protection items that still need a different endpoint surface.",
                "Automated baseline",
                true,
                [
                    "Azure connection with a stored client secret",
                    "Microsoft Graph DeviceManagementConfiguration.ReadWrite.All application permission",
                    "Pilot Microsoft Entra group for device or user assignment",
                    "Optional exclusion group for staged rollout safety",
                    "Active Intune licensing and enrolled pilot devices"
                ],
                [
                    "Acquire a Microsoft Graph application token for Intune configuration automation.",
                    "Create or update the Securityzator managed Windows core protection and endpoint hardening profiles.",
                    "Assign both profiles to the selected pilot group with an optional exclusion group for staged rollout safety.",
                    "Capture configuration and assignment readback for audit and drift tracking.",
                    "Preserve follow-up notes for EDR in block mode, Defender cloud connectivity, and update-governance items that still need another endpoint surface."
                ])
            {
                ExecutionSurface = "Microsoft Graph Intune deviceManagement or deviceConfigurations API with Windows 10 general and endpoint-protection configuration profiles.",
                NextStage = "Extend this endpoint slice into EDR in block mode, richer Defender connectivity validation, and update-governance controls once the broader endpoint provider and smoke path mature.",
                CurrentBlockers =
                [
                    "EDR in block mode and update-governance items still need a different Intune, Defender, or rollout surface than this first endpoint package.",
                    "Defender cloud-service connectivity still depends on endpoint onboarding health outside the Intune configuration path.",
                    "Device-level validation still depends on enrolled pilot devices and later readback enhancements beyond configuration creation.",
                    "This slice assumes pilot-group rollout rather than broad tenant-wide device enforcement."
                ],
                Targeting = new RemediationTemplateTargeting(
                    "Pilot devices or users via Microsoft Entra groups",
                    "Assigns the baseline to a chosen Microsoft Entra pilot group, with an optional exclusion group for staged rollout or breakglass safety.",
                    true,
                    true),
                DefaultLaunchMode = RemediationLaunchMode.DirectApply,
                RequiredLicenseCapabilities =
                [
                    TenantLicenseCapabilityCatalog.IntunePlan1,
                    TenantLicenseCapabilityCatalog.DefenderForBusiness
                ]
            },
            new RemediationTemplate(
                "defender-endpoint-exploit-protection",
                "Defender exploit protection baseline",
                "Applies a managed Intune endpoint-protection baseline for Windows system-level exploit protection settings to a pilot Microsoft Entra group.",
                "The worker uses Microsoft Graph Intune endpoint-protection configuration APIs to create or update a managed windows10EndpointProtectionConfiguration profile that carries a Securityzator exploit-protection XML, assigns it to the selected pilot group, records readback state, and preserves notes for reboot-sensitive rollout and app-specific exploit mitigations that still need broader validation.",
                "Automated baseline",
                true,
                [
                    "Azure connection with a stored client secret",
                    "Microsoft Graph DeviceManagementConfiguration.ReadWrite.All application permission",
                    "Pilot Microsoft Entra group for device or user assignment",
                    "Optional exclusion group for staged rollout safety",
                    "Active Intune licensing and enrolled pilot devices"
                ],
                [
                    "Acquire a Microsoft Graph application token for Intune configuration automation.",
                    "Create or update the Securityzator managed endpoint exploit protection profile.",
                    "Assign the profile to the selected pilot group with an optional exclusion group for staged rollout safety.",
                    "Capture configuration and assignment readback for audit and drift tracking.",
                    "Preserve follow-up notes for reboot-sensitive rollout checks and application-specific exploit mitigations."
                ])
            {
                ExecutionSurface = "Microsoft Graph Intune deviceManagement or deviceConfigurations API with Windows 10 endpoint-protection configuration profiles carrying exploit-protection XML.",
                NextStage = "Extend this exploit-protection slice into application-specific exploit mitigations and broader runtime validation once the pilot path matures.",
                CurrentBlockers =
                [
                    "Application-specific exploit mitigations for Adobe and browser controls still need software-aware rollout and validation beyond this first system-level XML baseline.",
                    "System-level exploit protection requires device reboot before every mitigation is fully active, so pilot validation remains necessary after profile deployment.",
                    "This slice assumes pilot-group rollout rather than broad tenant-wide device enforcement."
                ],
                Targeting = new RemediationTemplateTargeting(
                    "Pilot devices or users via Microsoft Entra groups",
                    "Assigns the baseline to a chosen Microsoft Entra pilot group, with an optional exclusion group for staged rollout or breakglass safety.",
                    true,
                    true),
                DefaultLaunchMode = RemediationLaunchMode.DirectApply,
                RequiredLicenseCapabilities =
                [
                    TenantLicenseCapabilityCatalog.IntunePlan1,
                    TenantLicenseCapabilityCatalog.DefenderForBusiness
                ]
            },
            new RemediationTemplate(
                "defender-endpoint-os-security-baseline",
                "Endpoint OS and platform security baseline",
                "Applies Securityzator's first Intune-backed OS hardening slice for workstation-safe Windows local security and SMB protections to a pilot Microsoft Entra group.",
                "The worker uses Microsoft Graph Intune endpoint-protection configuration APIs to create or update a managed windows10EndpointProtectionConfiguration profile, assigns it to the selected pilot group, records readback state, and preserves notes for the remaining server-sensitive or infrastructure-sensitive controls that still need a broader rollout model.",
                "Automated baseline",
                true,
                [
                    "Azure connection with a stored client secret",
                    "Microsoft Graph DeviceManagementConfiguration.ReadWrite.All application permission",
                    "Pilot Microsoft Entra group for device or user assignment",
                    "Optional exclusion group for staged rollout safety",
                    "Active Intune licensing and enrolled pilot devices"
                ],
                [
                    "Acquire a Microsoft Graph application token for Intune configuration automation.",
                    "Create or update the Securityzator managed endpoint OS security profile.",
                    "Assign the profile to the selected pilot group with an optional exclusion group for staged rollout safety.",
                    "Capture configuration and assignment readback for audit and drift tracking.",
                    "Preserve follow-up notes for password-age, account-lockout, LDAP, NTLM disablement, share-governance, and Secure Boot items that still need a broader rollout model."
                ])
            {
                ExecutionSurface = "Microsoft Graph Intune deviceManagement or deviceConfigurations API with Windows 10 endpoint-protection configuration profiles.",
                NextStage = "Extend this first OS baseline into password or account-lockout controls, SMBv1 or WDigest hardening, firewall or BitLocker slices, and broader server-safe rollout patterns once device validation matures.",
                CurrentBlockers =
                [
                    "Password-age, account-lockout, LDAP, NTLM disablement, share-governance, and Secure Boot controls still need a broader endpoint or server configuration rollout model than this first slice.",
                    "Several related controls affect infrastructure compatibility and should stay staged behind pilot-group validation.",
                    "This slice assumes pilot-group rollout rather than broad tenant-wide device enforcement."
                ],
                Targeting = new RemediationTemplateTargeting(
                    "Pilot devices or users via Microsoft Entra groups",
                    "Assigns the baseline to a chosen Microsoft Entra pilot group, with an optional exclusion group for staged rollout or breakglass safety.",
                    true,
                    true),
                DefaultLaunchMode = RemediationLaunchMode.DirectApply,
                RequiredLicenseCapabilities =
                [
                    TenantLicenseCapabilityCatalog.IntunePlan1,
                    TenantLicenseCapabilityCatalog.DefenderForBusiness
                ]
            },
            new RemediationTemplate(
                "defender-endpoint-sensor-and-agent-health",
                "Defender for Endpoint sensor and agent health",
                "Runs a scoped Intune-backed assessment for Defender for Endpoint onboarding coverage, Windows Defender telemetry freshness, overdue signature state, core component health, and WSL plug-in readiness follow-up across the selected pilot group.",
                "The worker uses Microsoft Graph managed device inventory, Windows protection-state readback, and Intune endpoint detection and response policy readback to assess sensor or agent health for the selected pilot scope, record per-device findings, and flag follow-up where Defender onboarding or reporting is incomplete.",
                "Automated assessment",
                true,
                [
                    "Azure connection with a stored client secret",
                    "Microsoft Graph DeviceManagementManagedDevices.Read.All application permission",
                    "Microsoft Graph DeviceManagementConfiguration.Read.All or DeviceManagementConfiguration.ReadWrite.All application permission",
                    "Pilot Microsoft Entra group for user or device scope",
                    "Optional exclusion group for staged rollout safety",
                    "Active Intune licensing and enrolled Windows devices in scope"
                ],
                [
                    "Acquire a Microsoft Graph application token for Intune managed device assessment.",
                    "Resolve the selected pilot group into user or device scope.",
                    "Read Windows managed device inventory and Defender protection-state telemetry for the scoped devices.",
                    "Read Intune endpoint detection and response policy assignments to understand whether the pilot scope is covered by a current onboarding policy.",
                    "Record healthy devices and devices needing follow-up for stale telemetry, overdue signatures, missing core component health data, onboarding gaps, or WSL plug-in prerequisite follow-up."
                ])
            {
                ExecutionSurface = "Microsoft Graph Intune managedDevices, windowsProtectionState, and configurationPolicies assessment workflow.",
                NextStage = "Add connector-readiness validation and later promote the supported onboarding path into a separate Defender for Endpoint onboarding baseline once the tenant connector state is confirmed.",
                CurrentBlockers =
                [
                    "This slice assesses Windows onboarding coverage and health but does not yet repair connector-based onboarding or platform-specific agent issues.",
                    "The WSL plug-in still needs host-side validation for WSL 2.0.7.0 or newer, an active distro, and local plug-in installation because Microsoft Graph does not expose those runtime details directly.",
                    "macOS and Linux sensor-health tasks still need platform-specific inventory and remediation surfaces.",
                    "Some impaired-communications fixes remain device-side actions outside Microsoft Graph."
                ],
                Targeting = new RemediationTemplateTargeting(
                    "Pilot devices or users via Microsoft Entra groups",
                    "Scopes the assessment to the selected Microsoft Entra pilot group, with an optional exclusion group for staged rollout or breakglass safety.",
                    true,
                    true),
                DefaultLaunchMode = RemediationLaunchMode.ReportOnly,
                RequiredLicenseCapabilities =
                [
                    TenantLicenseCapabilityCatalog.IntunePlan1,
                    TenantLicenseCapabilityCatalog.DefenderForBusiness
                ]
            },
            CreateBlockedTemplate(
                "defender-endpoint-macos-hardening",
                "Defender for Endpoint macOS hardening",
                "Groups the macOS-specific endpoint security, Defender Antivirus, firewall, FileVault, and platform integrity recommendations.",
                "These controls need a macOS-capable endpoint management provider and platform-aware validation before they can be executed safely.",
                "Control set draft",
                "macOS endpoint management and Defender for Endpoint administration.",
                "Build a platform-aware macOS provider before promoting any of these controls into worker automation.",
                [
                    "macOS device inventory",
                    "Policy deployment method",
                    "Platform verification steps"
                ],
                [
                    "Review the macOS hardening items as one platform family.",
                    "Separate sensor-health tasks from configuration tasks.",
                    "Promote the safest settings once a macOS policy path exists."
                ],
                [
                    "The platform cannot currently manage macOS endpoint settings.",
                    "These controls require device-level validation and rollout tracking.",
                    "The worker has no platform-specific macOS execution path."
                ],
                [
                    TenantLicenseCapabilityCatalog.IntunePlan1,
                    TenantLicenseCapabilityCatalog.DefenderForBusiness
                ]),
            CreateBlockedTemplate(
                "defender-endpoint-linux-hardening",
                "Defender for Endpoint Linux hardening",
                "Groups the Linux-specific Defender Antivirus, tamper, behavior monitoring, and sensor-health controls.",
                "These Linux tasks need platform-aware tooling and validation that the current app does not yet own.",
                "Control set draft",
                "Linux endpoint management and Defender for Endpoint administration.",
                "Add Linux inventory and supported configuration channels before promoting these recommendations into automation.",
                [
                    "Linux host inventory",
                    "Supported configuration channel",
                    "Health verification path"
                ],
                [
                    "Review the Linux-specific hardening items together.",
                    "Separate agent-health from configuration controls.",
                    "Promote the safest Linux settings after a supported provider is added."
                ],
                [
                    "The platform does not manage Linux endpoint settings today.",
                    "These controls depend on host-level remediation outside the current app model.",
                    "We need device inventory and validation before automation is safe."
                ],
                [
                    TenantLicenseCapabilityCatalog.IntunePlan1,
                    TenantLicenseCapabilityCatalog.DefenderForBusiness
                ]),
            CreateBlockedTemplate(
                "defender-endpoint-security-posture",
                "Defender for Endpoint security posture",
                "Catches the remaining Defender for Endpoint recommendations that still belong in endpoint policy and posture management.",
                "This keeps every Endpoint recommendation routed even before the family is fully split into runnable control sets.",
                "Discovery playbook",
                "Endpoint policy and device posture management.",
                "Use this as the residual bucket until every Endpoint family has its own safer execution path.",
                [
                    "Endpoint ownership",
                    "Platform inventory",
                    "Execution provider choice"
                ],
                [
                    "Identify which residual endpoint controls still need a dedicated family.",
                    "Assign them to the correct endpoint execution surface.",
                    "Promote them into narrower playbooks over time."
                ],
                [
                    "The app still lacks a general endpoint management provider.",
                    "Residual controls need clearer ownership before automation.",
                    "This bucket exists to avoid leaving Endpoint controls unmapped in the portal."
                ],
                [
                    TenantLicenseCapabilityCatalog.IntunePlan1,
                    TenantLicenseCapabilityCatalog.DefenderForBusiness
                ]),
            CreateBlockedTemplate(
                "active-directory-certificate-services-hardening",
                "Active Directory Certificate Services hardening",
                "Tracks AD CS misconfigurations, ESC findings, enrollment issues, and certificate authority exposure detected through Defender for Identity.",
                "These certificate-based identity exposures need directory and PKI-aware remediation workflows beyond the current Graph-only path.",
                "Control set draft",
                "Active Directory Certificate Services and PKI administration.",
                "Add AD CS discovery and rollback-aware PKI workflows before promoting certificate exposure fixes into jobs.",
                [
                    "AD CS inventory",
                    "PKI owner approval",
                    "Certificate-service rollback plan"
                ],
                [
                    "Review the AD CS findings as one privilege-escalation family.",
                    "Separate template, CA ACL, and enrollment-endpoint issues.",
                    "Promote the safest PKI changes only after readback and rollback are defined."
                ],
                [
                    "The current platform does not manage AD CS or enterprise PKI settings.",
                    "Certificate misconfiguration fixes can have broad infrastructure impact and need strong rollback planning.",
                    "Readback validation for PKI changes is not implemented."
                ]),
            CreateBlockedTemplate(
                "defender-identity-sensor-coverage",
                "Defender for Identity sensor coverage",
                "Tracks Defender for Identity sensor deployment, coverage gaps, honeytoken setup, and related onboarding tasks.",
                "This playbook keeps the sensor-coverage side of Defender for Identity visible separately from the deeper Active Directory hardening work.",
                "Guided enablement",
                "Defender for Identity deployment and sensor coverage workflow.",
                "Add infrastructure inventory and deployment-state tracking before automating any sensor rollout or coverage remediation.",
                [
                    "Eligible server inventory",
                    "Sensor deployment ownership",
                    "Onboarding validation path"
                ],
                [
                    "Identify the servers that should carry Defender for Identity sensors.",
                    "Confirm deployment ownership and rollout order.",
                    "Track coverage and onboarding state before deeper automation."
                ],
                [
                    "The platform has no server deployment or sensor-health workflow.",
                    "These tasks depend on infrastructure changes outside the current web-plus-worker model.",
                    "We need deployment-state visibility before automation is safe."
                ]),
            CreateBlockedTemplate(
                "active-directory-privileged-account-hygiene",
                "Active Directory privileged account hygiene",
                "Groups leaked credentials, stale privileged accounts, password rotation, DCSync, LAPS, and other account hygiene findings from Defender for Identity.",
                "These are some of the highest-value identity recommendations, but they need stronger ownership, verification, and rollback than the current app offers.",
                "Control set draft",
                "Active Directory administration and identity hygiene workflows.",
                "Split this family into password rotation, privileged exposure, and stale-account slices before automation.",
                [
                    "Directory owner approval",
                    "Account inventory",
                    "Password rotation and rollback plan"
                ],
                [
                    "Review privileged account exposures as one identity hygiene family.",
                    "Separate credential-rotation tasks from privilege-removal tasks.",
                    "Promote the safest slices into guided or automated workflows later."
                ],
                [
                    "The platform does not yet own on-prem Active Directory account operations.",
                    "Many controls require coordinated password rotation and privileged-access review.",
                    "Rollback and post-change verification are not modeled yet."
                ]),
            CreateBlockedTemplate(
                "active-directory-domain-security-hardening",
                "Active Directory domain security hardening",
                "Covers domain configuration, delegation, protocol, group policy, and lateral-movement exposure findings from Defender for Identity.",
                "This playbook keeps domain and infrastructure-level identity findings visible while we separate them from account-hygiene and sensor-coverage tasks.",
                "Control set draft",
                "Active Directory and domain-controller security administration.",
                "Break this family into smaller domain-security slices after infrastructure ownership and rollback models are defined.",
                [
                    "Domain security owner",
                    "Infrastructure inventory",
                    "Service-impact review"
                ],
                [
                    "Review domain posture findings as one infrastructure-hardening family.",
                    "Separate protocol, delegation, GPO, and lateral-movement issues.",
                    "Promote the safest infrastructure changes only after validation and rollback are ready."
                ],
                [
                    "These findings sit outside the current cloud-only execution model.",
                    "Several controls affect authentication, delegation, or infrastructure services and need careful change management.",
                    "The platform has no domain readback or rollback workflow yet."
                ]),
            CreateBlockedTemplate(
                "federated-identity-provider-hygiene",
                "Federated identity provider hygiene",
                "Groups privileged-account, MFA, password, and role-hygiene findings for external identity providers and connected admin platforms such as Okta, PingOne, SailPoint, and CyberArk Identity.",
                "These recommendations require either product-native APIs or a stronger Defender for Cloud Apps or App Governance execution path than the app currently has.",
                "Guided hardening",
                "Third-party identity provider administration or app-governance provider.",
                "Add tenant connector posture and product-specific execution choices before automating federated IdP hardening.",
                [
                    "Connected IdP inventory",
                    "Product owner approval",
                    "Supported execution path"
                ],
                [
                    "Review the external identity-provider findings together.",
                    "Confirm which platforms are actually in scope for the tenant.",
                    "Choose whether future execution belongs in native APIs or a broader app-governance provider."
                ],
                [
                    "The platform does not yet integrate with external identity-provider admin APIs.",
                    "These products require connector-specific ownership and rollout planning.",
                    "We need inventory and scope confirmation before automation."
                ]),
            CreateBlockedTemplate(
                "salesforce-security-posture",
                "Salesforce security posture",
                "Tracks the Salesforce-specific login, session, clickjack, CSP, CSRF, password, and remote-site hardening controls surfaced through connected-app visibility.",
                "These controls are product-specific enough that they deserve their own playbook instead of being hidden inside a generic SaaS bucket.",
                "Control set draft",
                "Salesforce administration or connected-app governance provider.",
                "Add Salesforce-specific posture readback before promoting any of these controls into runnable jobs.",
                [
                    "Salesforce owner approval",
                    "Connected org inventory",
                    "Product-specific rollback plan"
                ],
                [
                    "Review the Salesforce findings as one product family.",
                    "Separate session and auth controls from page and app-surface controls.",
                    "Promote the safest product-specific changes after a provider exists."
                ],
                [
                    "The app has no Salesforce configuration provider.",
                    "Many settings affect admin workflows or custom pages and need safer rollback.",
                    "We do not yet have Salesforce readback validation."
                ]),
            CreateBlockedTemplate(
                "servicenow-security-posture",
                "ServiceNow security posture",
                "Tracks the ServiceNow ACL, session, script, authorization, and high-security recommendations surfaced through connected-app visibility.",
                "These controls belong in a ServiceNow-aware provider because the risks and rollback paths are app-specific.",
                "Control set draft",
                "ServiceNow administration or connected-app governance provider.",
                "Add ServiceNow-specific posture readback before attempting automation.",
                [
                    "ServiceNow owner approval",
                    "Instance inventory",
                    "Validation and rollback model"
                ],
                [
                    "Review the ServiceNow findings as one product family.",
                    "Separate script, ACL, authentication, and session settings.",
                    "Promote the safest changes after provider support exists."
                ],
                [
                    "The app does not manage ServiceNow settings today.",
                    "Several settings can affect app behavior and integrations and need product-aware rollback.",
                    "Readback validation for ServiceNow posture is not available."
                ]),
            CreateBlockedTemplate(
                "github-enterprise-hardening",
                "GitHub enterprise hardening",
                "Tracks enterprise GitHub organization restrictions around visibility, collaborators, SSO, notifications, IP allow lists, and repository governance.",
                "GitHub is distinct enough from the other connected SaaS apps that it deserves a dedicated playbook.",
                "Control set draft",
                "GitHub enterprise administration or app-governance provider.",
                "Add GitHub posture readback and organization scoping before promoting these controls into automation.",
                [
                    "GitHub org ownership",
                    "Enterprise scope review",
                    "Rollback plan for org restrictions"
                ],
                [
                    "Review the GitHub findings as one product family.",
                    "Separate org governance controls from access and SSO settings.",
                    "Promote the safest restrictions after provider support exists."
                ],
                [
                    "The app has no GitHub administration provider.",
                    "These controls need org-aware rollback and verification.",
                    "We do not yet track tenant-to-connector scope for GitHub organizations."
                ]),
            CreateBlockedTemplate(
                "connected-saas-session-and-auth-hardening",
                "Connected SaaS session and authentication hardening",
                "Groups the MFA, SSO, password, timeout, encryption, and mobile-app posture recommendations for the remaining connected SaaS products.",
                "This playbook closes the current mapping gap for the long tail of connected apps while we decide which products deserve their own dedicated providers next.",
                "Guided hardening",
                "Connected-app governance or product-native administration providers.",
                "Use this as the long-tail SaaS bucket until tenant usage shows which products should get dedicated playbooks next.",
                [
                    "Connected app inventory",
                    "Product ownership",
                    "Execution surface decision"
                ],
                [
                    "Review the remaining SaaS identity and session findings together.",
                    "Identify which products matter enough to deserve dedicated automation.",
                    "Promote those products into narrower playbooks over time."
                ],
                [
                    "The platform does not yet have product-native providers for the long-tail connected SaaS apps.",
                    "Connector scope, ownership, and licensing vary by tenant and need to be confirmed.",
                    "Current execution is limited to mapping and operator guidance, not direct SaaS configuration."
                ]),
            CreateBlockedTemplate(
                "sharepoint-collaboration-and-device-access",
                "SharePoint collaboration and device access",
                "Tracks SharePoint Online and OneDrive controls for external sharing, guest sharing, unmanaged-device sync, and collaboration boundaries.",
                "These settings belong in a broader collaboration-control family than the narrower session and modern-auth playbook already in the app.",
                "Control set draft",
                "SharePoint Online administration provider.",
                "Add SharePoint tenant-setting support, then promote device-access and sharing restrictions into separate jobs.",
                [
                    "SharePoint owner approval",
                    "Collaboration exception model",
                    "Tenant-setting validation path"
                ],
                [
                    "Review collaboration and unmanaged-device controls together.",
                    "Separate external sharing from device-access restrictions.",
                    "Promote the lowest-risk settings after provider support exists."
                ],
                [
                    "The app does not yet manage SharePoint Online tenant collaboration settings.",
                    "These controls can disrupt business sharing and need exception handling.",
                    "Readback validation and rollback are not implemented."
                ]),
            CreateBlockedTemplate(
                "app-governance-and-user-owned-apps",
                "App governance and user-owned app controls",
                "Groups app-governance findings such as sensitive-data access, consent posture, and user-owned app restrictions that sit outside the current Conditional Access and Secure Score execution path.",
                "This gives the app-governance surface a visible home while we decide between App Governance, Defender for Cloud Apps, and product-native providers.",
                "Discovery playbook",
                "App governance, consent governance, and Microsoft 365 admin controls.",
                "Add app inventory and governance-state visibility before choosing the execution surface for these controls.",
                [
                    "Application inventory",
                    "Consent governance owner",
                    "Execution-surface decision"
                ],
                [
                    "Review the app-governance findings together.",
                    "Identify which controls belong in Entra, App Governance, or Microsoft 365 admin settings.",
                    "Promote the clearest slice into a dedicated provider."
                ],
                [
                    "The platform does not yet inventory application governance posture deeply enough.",
                    "These controls span multiple admin surfaces and need clearer ownership.",
                    "There is no chosen execution provider yet."
                ]),
            CreateBlockedTemplate(
                "microsoft-365-collaboration-sharing-governance",
                "Microsoft 365 collaboration and sharing governance",
                "Captures the remaining Sway and Forms collaboration controls that do not belong in the bigger SharePoint or Teams playbooks.",
                "This keeps the collaboration long tail visible while we focus implementation on the higher-volume providers first.",
                "Guided hardening",
                "Microsoft 365 collaboration administration surfaces.",
                "Keep these controls mapped while we decide whether they should live with SharePoint, Teams, or a broader Microsoft 365 collaboration provider.",
                [
                    "Collaboration workload ownership",
                    "Sharing policy decision",
                    "Validation path"
                ],
                [
                    "Review the remaining collaboration-sharing findings together.",
                    "Decide whether they belong with SharePoint, Teams, or a future collaboration provider.",
                    "Promote them into a narrower playbook when the owner and provider are clear."
                ],
                [
                    "The current platform does not yet manage these collaboration settings directly.",
                    "These controls are lower-volume than the main SharePoint and Teams families, so they are intentionally staged behind them.",
                    "We still need a clearer execution surface for these workloads."
                ])
        ];
    }

    private static RemediationTemplate CreateBlockedTemplate(
        string key,
        string name,
        string summary,
        string methodology,
        string deliveryMode,
        string executionSurface,
        string nextStage,
        IReadOnlyList<string> requiredInputs,
        IReadOnlyList<string> steps,
        IReadOnlyList<string> blockers,
        IReadOnlyList<string>? requiredLicenseCapabilities = null)
    {
        return new RemediationTemplate(
            key,
            name,
            summary,
            methodology,
            deliveryMode,
            false,
            requiredInputs,
            steps)
        {
            ExecutionSurface = executionSurface,
            NextStage = nextStage,
            CurrentBlockers = blockers,
            RequiredLicenseCapabilities = requiredLicenseCapabilities ?? Array.Empty<string>()
        };
    }
}
