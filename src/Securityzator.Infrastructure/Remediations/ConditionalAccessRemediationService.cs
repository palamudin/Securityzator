using Securityzator.Application.Remediations;
using Securityzator.Infrastructure.Exchange;
using Securityzator.Infrastructure.Graph;
using Securityzator.Infrastructure.Intune;
using Securityzator.Infrastructure.Security;
using Securityzator.Infrastructure.Storage;
using Securityzator.Infrastructure.Teams;

namespace Securityzator.Infrastructure.Remediations;

public sealed class ConditionalAccessRemediationService : IRemediationService
{
    private const string BlockLegacyAuthTemplateKey = "block-legacy-auth";
    private const string BlockLegacyAuthTemplateName = "Block legacy authentication";
    private const string BlockLegacyAuthPolicyDisplayName = "SS-AUTO | Block legacy authentication";
    private const string RequireMfaAdminsTemplateKey = "require-mfa-admins";
    private const string RequireMfaAdminsTemplateName = "Require MFA for privileged admins";
    private const string RequireMfaAdminsPolicyDisplayName = "SS-AUTO | Require MFA for privileged admins";
    private const string RequireMfaAllUsersTemplateKey = "mfa-all-users";
    private const string RequireMfaAllUsersTemplateName = "Require MFA for all users";
    private const string RequireMfaAllUsersPolicyDisplayName = "SS-AUTO | Require MFA for all users";
    private const string EntraRiskPoliciesTemplateKey = "entra-risk-policies";
    private const string EntraRiskPoliciesTemplateName = "Enable Entra risk policies";
    private const string EntraIdentityHygieneTemplateKey = "entra-identity-hygiene-baseline";
    private const string EntraIdentityHygieneTemplateName = "Entra admin and consent hygiene";
    private const string EntraIdentityHygieneTargetName = "Entra identity hygiene assessment";
    private const string EntraDailyUseHardeningTemplateKey = "entra-daily-use-hardening";
    private const string EntraDailyUseHardeningTemplateName = "Entra daily-use consent and password hardening";
    private const string EntraDailyUseHardeningTargetName = "Entra daily-use hardening";
    private const string EntraLowImpactAppConsentTemplateKey = "entra-low-impact-app-consent";
    private const string EntraLowImpactAppConsentTemplateName = "Entra low-impact app consent";
    private const string EntraLowImpactAppConsentTargetName = "Entra low-impact app consent";
    private const string EntraDailyUsePermissionsHint =
        "Grant Graph Policy.ReadWrite.Authorization, Policy.ReadWrite.ConsentRequest, and Domain.ReadWrite.All with admin consent, then validate the connection again.";
    private const string EntraLowImpactAppConsentPermissionsHint =
        "Grant Graph Policy.ReadWrite.Authorization with admin consent, then validate the connection again.";
    private const string RequireMfaGuestAccessTemplateKey = "require-mfa-guest-access";
    private const string RequireMfaGuestAccessTemplateName = "Require MFA for guest access";
    private const string RequireMfaGuestAccessPolicyDisplayName = "SS-AUTO | Require MFA for guest access";
    private const string RequireMfaAdminPortalsTemplateKey = "require-mfa-admin-portals";
    private const string RequireMfaAdminPortalsTemplateName = "Require MFA for Microsoft admin portals";
    private const string RequireMfaAdminPortalsPolicyDisplayName = "SS-AUTO | Require MFA for Microsoft admin portals";
    private const string RequireMfaAzureManagementTemplateKey = "require-mfa-azure-management";
    private const string RequireMfaAzureManagementTemplateName = "Require MFA for Azure management";
    private const string RequireMfaAzureManagementPolicyDisplayName = "SS-AUTO | Require MFA for Azure management";
    private const string SecureSecurityInfoRegistrationTemplateKey = "secure-security-info-registration";
    private const string SecureSecurityInfoRegistrationTemplateName = "Secure security info registration";
    private const string SecureSecurityInfoRegistrationPolicyDisplayName = "SS-AUTO | Secure security info registration";
    private const string RequireMfaRiskySignInsTemplateKey = "require-mfa-risky-sign-ins";
    private const string RequireMfaRiskySignInsTemplateName = "Require MFA when risky sign-ins are detected";
    private const string RequireMfaRiskySignInsPolicyDisplayName = "SS-AUTO | Require MFA when risky sign-ins are detected";
    private const string RequirePasswordChangeHighRiskUsersTemplateKey = "require-password-change-high-risk-users";
    private const string RequirePasswordChangeHighRiskUsersTemplateName = "Require password change for high-risk users";
    private const string RequirePasswordChangeHighRiskUsersPolicyDisplayName = "SS-AUTO | Require password change for high-risk users";
    private const string RequirePhishingResistantMfaAdminsTemplateKey = "require-phishing-resistant-mfa-admins";
    private const string RequirePhishingResistantMfaAdminsTemplateName = "Require phishing-resistant MFA for privileged admins";
    private const string RequirePhishingResistantMfaAdminsPolicyDisplayName = "SS-AUTO | Require phishing-resistant MFA for privileged admins";
    private const string MdoAntiPhishingAndImpersonationTemplateKey = "mdo-anti-phishing-and-impersonation";
    private const string MdoAntiPhishingAndImpersonationTemplateName = "Defender for Office anti-phishing and impersonation";
    private const string MdoAntiPhishingAndImpersonationTargetName = "SS-AUTO | Anti-phish baseline";
    private const string MdoAntiMalwareTemplateKey = "mdo-anti-malware-baseline";
    private const string MdoAntiMalwareTemplateName = "Defender for Office anti-malware hardening";
    private const string MdoAntiMalwareTargetName = "SS-AUTO | Anti-malware baseline";
    private const string MdoSafeLinksAndAttachmentsTemplateKey = "mdo-safe-links-and-attachments";
    private const string MdoSafeLinksAndAttachmentsTemplateName = "Defender for Office Safe Links and attachments";
    private const string MdoSafeLinksAndAttachmentsTargetName = "SS-AUTO | Safe Links baseline + SS-AUTO | Safe Attachments baseline";
    private const string MdoSpamAndForwardingTemplateKey = "mdo-spam-and-forwarding-baseline";
    private const string MdoSpamAndForwardingTemplateName = "Defender for Office spam and forwarding hardening";
    private const string MdoSpamAndForwardingTargetName = "SS-AUTO | Spam baseline + SS-AUTO | Outbound forwarding baseline";
    private const string ExchangeOnlineCollaborationMailboxTemplateKey = "exchange-online-collaboration-and-mailbox";
    private const string ExchangeOnlineCollaborationMailboxTemplateName = "Exchange Online collaboration and mailbox hardening";
    private const string ExchangeOnlineCollaborationMailboxTargetName = "SS-AUTO | Exchange collaboration baseline";
    private const string TeamsMeetingHardeningTemplateKey = "teams-meeting-hardening";
    private const string TeamsMeetingHardeningTemplateName = "Teams meeting hardening baseline";
    private const string TeamsMeetingHardeningPolicyIdentity = "Global";
    private const string DefenderEndpointBitLockerTemplateKey = "defender-endpoint-bitlocker-baseline";
    private const string DefenderEndpointBitLockerTemplateName = "Defender BitLocker startup baseline";
    private const string DefenderEndpointBitLockerTargetName = "SS-AUTO | Endpoint BitLocker baseline";
    private const string DefenderEndpointCredentialAndElevationHardeningTemplateKey = "defender-endpoint-credential-and-elevation-hardening";
    private const string DefenderEndpointCredentialAndElevationHardeningTemplateName = "Defender credential and elevation hardening";
    private const string DefenderEndpointCredentialAndElevationHardeningTargetName = "SS-AUTO | Endpoint credential and elevation hardening";
    private const string DefenderEndpointRemoteAccessAndNetworkHardeningTemplateKey = "defender-endpoint-remote-access-and-network-hardening";
    private const string DefenderEndpointRemoteAccessAndNetworkHardeningTemplateName = "Defender remote access and network hardening";
    private const string DefenderEndpointRemoteAccessAndNetworkHardeningTargetName = "SS-AUTO | Endpoint remote access and network hardening";
    private const string DefenderEndpointCoreProtectionTemplateKey = "defender-endpoint-core-protection";
    private const string DefenderEndpointCoreProtectionTemplateName = "Defender for Endpoint core protection baseline";
    private const string DefenderEndpointCoreProtectionTargetName = "SS-AUTO | Endpoint core protection baseline + SS-AUTO | Endpoint core protection hardening";
    private const string DefenderEndpointFirewallAndSmartScreenTemplateKey = "defender-endpoint-firewall-and-smartscreen";
    private const string DefenderEndpointFirewallAndSmartScreenTemplateName = "Defender Firewall and SmartScreen baseline";
    private const string DefenderEndpointFirewallAndSmartScreenTargetName = "SS-AUTO | Endpoint firewall and SmartScreen baseline + SS-AUTO | Endpoint Edge SmartScreen baseline";
    private const string DefenderEndpointBrowserHardeningTemplateKey = "defender-endpoint-browser-hardening";
    private const string DefenderEndpointBrowserHardeningTemplateName = "Defender browser hardening baseline";
    private const string DefenderEndpointBrowserHardeningTargetName = "SS-AUTO | Endpoint browser hardening baseline";
    private const string DefenderEndpointBrowserAndAdobePolicySurfaceTemplateKey = "defender-endpoint-browser-and-adobe-policy-surface-readiness";
    private const string DefenderEndpointBrowserAndAdobePolicySurfaceTemplateName = "Defender browser and Adobe policy-surface readiness";
    private const string DefenderEndpointBrowserAndAdobePolicySurfaceTargetName = "Defender browser and Adobe policy-surface readiness assessment";
    private const string DefenderEndpointExploitProtectionTemplateKey = "defender-endpoint-exploit-protection";
    private const string DefenderEndpointExploitProtectionTemplateName = "Defender exploit protection baseline";
    private const string DefenderEndpointExploitProtectionTargetName = "SS-AUTO | Endpoint exploit protection baseline";
    private const string DefenderEndpointSensorAndAgentHealthTemplateKey = "defender-endpoint-sensor-and-agent-health";
    private const string DefenderEndpointSensorAndAgentHealthTemplateName = "Defender for Endpoint sensor and agent health";
    private const string DefenderEndpointSensorAndAgentHealthTargetName = "Defender for Endpoint sensor and agent health assessment";
    private const string DefenderEndpointOsSecurityBaselineTemplateKey = "defender-endpoint-os-security-baseline";
    private const string DefenderEndpointOsSecurityBaselineTemplateName = "Endpoint OS and platform security baseline";
    private const string DefenderEndpointOsSecurityBaselineTargetName = "SS-AUTO | Endpoint OS security baseline";
    private const string DefenderEndpointAttackSurfaceReductionTemplateKey = "defender-endpoint-attack-surface-reduction";
    private const string DefenderEndpointAttackSurfaceReductionTemplateName = "Defender for Endpoint attack surface reduction";
    private const string DefenderEndpointAttackSurfaceReductionTargetName = "SS-AUTO | Endpoint attack surface reduction baseline";
    private const string ExchangeDelegatedBootstrapHint =
        "Exchange Online custom protection policies currently need a delegated bootstrap helper on this tenant. For anti-phish run '.\\tools\\Apply-ExchangeAntiPhishBaseline.ps1 -UseAuthTxt -UseAzureCliDeviceCode' or the PowerShell 7 device-login variant if the token-backed session hides anti-phish parameters. For Safe Links and Safe Attachments run '.\\tools\\Apply-ExchangeSafeLinksAndAttachmentsBaseline.ps1 -UseAuthTxt -UseAzureCliDeviceCode'. If the delegated Exchange session still does not expose the Safe Links cmdlets, complete that baseline in the Microsoft Defender portal or a full Exchange Online admin PowerShell session. For spam and forwarding run '.\\tools\\Apply-ExchangeSpamAndForwardingBaseline.ps1 -UseAuthTxt -UseAzureCliDeviceCode'. For Exchange collaboration and mailbox settings run '.\\tools\\Apply-ExchangeCollaborationMailboxBaseline.ps1 -UseAuthTxt -UseAzureCliDeviceCode'. Use a Global Administrator Azure CLI session.";

    private readonly JsonFileSecurityzatorStateStore _stateStore;
    private readonly ClientSecretProtector _secretProtector;
    private readonly GraphAccessTokenService _tokenService;
    private readonly DirectoryGraphClient _directoryClient;
    private readonly ConditionalAccessGraphClient _conditionalAccessClient;
    private readonly DefenderForOfficeAutomationClient _defenderForOfficeAutomationClient;
    private readonly IntuneEndpointAutomationClient _intuneEndpointAutomationClient;
    private readonly TeamsMeetingPolicyAutomationClient _teamsMeetingPolicyAutomationClient;

    public ConditionalAccessRemediationService(
        JsonFileSecurityzatorStateStore stateStore,
        ClientSecretProtector secretProtector,
        GraphAccessTokenService tokenService,
        DirectoryGraphClient directoryClient,
        ConditionalAccessGraphClient conditionalAccessClient,
        DefenderForOfficeAutomationClient defenderForOfficeAutomationClient,
        IntuneEndpointAutomationClient intuneEndpointAutomationClient,
        TeamsMeetingPolicyAutomationClient teamsMeetingPolicyAutomationClient)
    {
        _stateStore = stateStore;
        _secretProtector = secretProtector;
        _tokenService = tokenService;
        _directoryClient = directoryClient;
        _conditionalAccessClient = conditionalAccessClient;
        _defenderForOfficeAutomationClient = defenderForOfficeAutomationClient;
        _intuneEndpointAutomationClient = intuneEndpointAutomationClient;
        _teamsMeetingPolicyAutomationClient = teamsMeetingPolicyAutomationClient;
    }

    public Task<RemediationExecutionOutcome> ExecuteQueueableTemplateAsync(
        QueueableRemediationTemplateRequest request,
        CancellationToken cancellationToken = default)
    {
        return request.TemplateKey.Trim() switch
        {
            BlockLegacyAuthTemplateKey => ExecuteBlockLegacyAuthenticationAsync(
                new BlockLegacyAuthenticationRequest(
                    request.ConnectionId,
                    request.OwnerOperatorId,
                    request.LaunchedByOperatorId,
                    request.LaunchedByOperatorName,
                    request.ApprovalJustification,
                    request.LaunchMode,
                    request.IncludeGroupId,
                    request.ExcludeGroupId),
                cancellationToken),
            RequireMfaAdminsTemplateKey => ExecuteRequireMfaAdminsAsync(
                new RequireMfaAdminsRequest(
                    request.ConnectionId,
                    request.OwnerOperatorId,
                    request.LaunchedByOperatorId,
                    request.LaunchedByOperatorName,
                    request.ApprovalJustification,
                    request.LaunchMode,
                    request.IncludeGroupId,
                    request.ExcludeGroupId),
                cancellationToken),
            RequireMfaAllUsersTemplateKey => ExecuteRequireMfaAllUsersAsync(
                new RequireMfaAllUsersRequest(
                    request.ConnectionId,
                    request.OwnerOperatorId,
                    request.LaunchedByOperatorId,
                    request.LaunchedByOperatorName,
                    request.ApprovalJustification,
                    request.LaunchMode,
                    request.ExcludeGroupId),
                cancellationToken),
            EntraRiskPoliciesTemplateKey => ExecuteEntraRiskPoliciesPackageAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.ExcludeGroupId,
                cancellationToken),
            EntraIdentityHygieneTemplateKey => ExecuteEntraIdentityHygieneAssessmentAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                cancellationToken),
            EntraDailyUseHardeningTemplateKey => ExecuteEntraDailyUseHardeningAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                cancellationToken),
            EntraLowImpactAppConsentTemplateKey => ExecuteEntraLowImpactAppConsentAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                cancellationToken),
            RequireMfaGuestAccessTemplateKey => ExecuteRequireMfaGuestAccessAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.ExcludeGroupId,
                cancellationToken),
            RequireMfaAdminPortalsTemplateKey => ExecuteRequireMfaAdminPortalsAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.ExcludeGroupId,
                cancellationToken),
            RequireMfaAzureManagementTemplateKey => ExecuteRequireMfaAzureManagementAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.ExcludeGroupId,
                cancellationToken),
            SecureSecurityInfoRegistrationTemplateKey => ExecuteSecureSecurityInfoRegistrationAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.ExcludeGroupId,
                cancellationToken),
            RequireMfaRiskySignInsTemplateKey => ExecuteRequireMfaRiskySignInsAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.ExcludeGroupId,
                cancellationToken),
            RequirePasswordChangeHighRiskUsersTemplateKey => ExecuteRequirePasswordChangeHighRiskUsersAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.ExcludeGroupId,
                cancellationToken),
            RequirePhishingResistantMfaAdminsTemplateKey => ExecuteRequirePhishingResistantMfaAdminsAsync(
                new RequirePhishingResistantMfaAdminsRequest(
                    request.ConnectionId,
                    request.OwnerOperatorId,
                    request.LaunchedByOperatorId,
                    request.LaunchedByOperatorName,
                    request.ApprovalJustification,
                    request.LaunchMode,
                    request.IncludeGroupId,
                    request.ExcludeGroupId),
                cancellationToken),
            MdoAntiPhishingAndImpersonationTemplateKey => ExecuteDefenderForOfficeAntiPhishBaselineAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                cancellationToken),
            MdoAntiMalwareTemplateKey => ExecuteDefenderForOfficeAntiMalwareBaselineAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                cancellationToken),
            MdoSafeLinksAndAttachmentsTemplateKey => ExecuteDefenderForOfficeSafeLinksAndAttachmentsAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                cancellationToken),
            MdoSpamAndForwardingTemplateKey => ExecuteDefenderForOfficeSpamAndForwardingBaselineAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                cancellationToken),
            ExchangeOnlineCollaborationMailboxTemplateKey => ExecuteExchangeOnlineCollaborationMailboxBaselineAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                cancellationToken),
            TeamsMeetingHardeningTemplateKey => ExecuteTeamsMeetingHardeningBaselineAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                cancellationToken),
            DefenderEndpointCredentialAndElevationHardeningTemplateKey => ExecuteDefenderEndpointCredentialAndElevationHardeningBaselineAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.IncludeGroupId,
                request.ExcludeGroupId,
                request.AllUsersAssignment,
                cancellationToken),
            DefenderEndpointRemoteAccessAndNetworkHardeningTemplateKey => ExecuteDefenderEndpointRemoteAccessAndNetworkHardeningBaselineAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.IncludeGroupId,
                request.ExcludeGroupId,
                request.AllUsersAssignment,
                cancellationToken),
            DefenderEndpointBitLockerTemplateKey => ExecuteDefenderEndpointBitLockerBaselineAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.IncludeGroupId,
                request.ExcludeGroupId,
                request.AllUsersAssignment,
                cancellationToken),
            DefenderEndpointFirewallAndSmartScreenTemplateKey => ExecuteDefenderEndpointFirewallAndSmartScreenBaselineAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.IncludeGroupId,
                request.ExcludeGroupId,
                request.AllUsersAssignment,
                cancellationToken),
            DefenderEndpointBrowserHardeningTemplateKey => ExecuteDefenderEndpointBrowserHardeningBaselineAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.IncludeGroupId,
                request.ExcludeGroupId,
                request.AllUsersAssignment,
                cancellationToken),
            DefenderEndpointBrowserAndAdobePolicySurfaceTemplateKey => ExecuteDefenderEndpointBrowserAndAdobePolicySurfaceAssessmentAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                cancellationToken),
            DefenderEndpointExploitProtectionTemplateKey => ExecuteDefenderEndpointExploitProtectionBaselineAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.IncludeGroupId,
                request.ExcludeGroupId,
                request.AllUsersAssignment,
                cancellationToken),
            DefenderEndpointSensorAndAgentHealthTemplateKey => ExecuteDefenderEndpointSensorAndAgentHealthAssessmentAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.IncludeGroupId,
                request.ExcludeGroupId,
                request.AllUsersAssignment,
                cancellationToken),
            DefenderEndpointCoreProtectionTemplateKey => ExecuteDefenderEndpointCoreProtectionBaselineAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.IncludeGroupId,
                request.ExcludeGroupId,
                request.AllUsersAssignment,
                cancellationToken),
            DefenderEndpointOsSecurityBaselineTemplateKey => ExecuteDefenderEndpointOsSecurityBaselineAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.IncludeGroupId,
                request.ExcludeGroupId,
                request.AllUsersAssignment,
                cancellationToken),
            DefenderEndpointAttackSurfaceReductionTemplateKey => ExecuteDefenderEndpointAttackSurfaceReductionBaselineAsync(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.IncludeGroupId,
                request.ExcludeGroupId,
                request.AllUsersAssignment,
                cancellationToken),
            _ => throw new InvalidOperationException($"Unsupported template key '{request.TemplateKey}'.")
        };
    }

    public async Task<IReadOnlyList<DirectoryGroupEntry>> ListGroupsAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default)
    {
        var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
        var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
        var groups = await _directoryClient.ListGroupsAsync(accessToken, cancellationToken);

        return groups
            .Where(group => !string.IsNullOrWhiteSpace(group.Id))
            .OrderBy(group => group.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(group => group.Id, StringComparer.OrdinalIgnoreCase)
            .Select(group => new DirectoryGroupEntry(
                group.Id,
                string.IsNullOrWhiteSpace(group.DisplayName) ? group.Id : group.DisplayName))
            .ToArray();
    }

    public Task<IReadOnlyList<RemediationRunRecord>> ListRunsAsync(
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default)
    {
        return _stateStore.ReadAsync<IReadOnlyList<RemediationRunRecord>>(state =>
            state.RemediationRuns
                .Where(run => run.OwnerOperatorId == ownerOperatorId)
                .OrderByDescending(run => run.CompletedUtc)
                .Select(ToRecord)
                .ToArray(), cancellationToken);
    }

    public async Task<RemediationExecutionOutcome> ExecuteBlockLegacyAuthenticationAsync(
        BlockLegacyAuthenticationRequest request,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteGroupTargetedConditionalAccessAsync(
            new TemplateExecutionRequest(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.IncludeGroupId,
                request.ExcludeGroupId),
            BlockLegacyAuthTemplateKey,
            BlockLegacyAuthTemplateName,
            BlockLegacyAuthPolicyDisplayName,
            null,
            (token, launchMode, includeGroupId, excludeGroupId, tokenCancellation) =>
                _conditionalAccessClient.CreateBlockLegacyAuthenticationPolicyAsync(
                    token,
                    launchMode,
                    includeGroupId,
                    excludeGroupId,
                    tokenCancellation),
            cancellationToken);
    }

    public async Task<RemediationExecutionOutcome> ExecuteRequireMfaAdminsAsync(
        RequireMfaAdminsRequest request,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteGroupTargetedConditionalAccessAsync(
            new TemplateExecutionRequest(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.IncludeGroupId,
                request.ExcludeGroupId),
            RequireMfaAdminsTemplateKey,
            RequireMfaAdminsTemplateName,
            RequireMfaAdminsPolicyDisplayName,
            null,
            (token, launchMode, includeGroupId, excludeGroupId, tokenCancellation) =>
                _conditionalAccessClient.CreateRequireMfaForAdminsPolicyAsync(
                    token,
                    launchMode,
                    includeGroupId,
                    excludeGroupId,
                    tokenCancellation),
            cancellationToken);
    }

    public async Task<RemediationExecutionOutcome> ExecuteRequireMfaAllUsersAsync(
        RequireMfaAllUsersRequest request,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteGroupTargetedConditionalAccessAsync(
            new TemplateExecutionRequest(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                string.Empty,
                request.ExcludeGroupId),
            RequireMfaAllUsersTemplateKey,
            RequireMfaAllUsersTemplateName,
            RequireMfaAllUsersPolicyDisplayName,
            "All users",
            (token, launchMode, _, excludeGroupId, tokenCancellation) =>
                _conditionalAccessClient.CreateRequireMfaForAllUsersPolicyAsync(
                    token,
                    launchMode,
                    excludeGroupId,
                    tokenCancellation),
            cancellationToken);
    }

    private async Task<RemediationExecutionOutcome> ExecuteEntraRiskPoliciesPackageAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        CancellationToken cancellationToken)
    {
        if (launchMode == RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("The Entra risk policies package only supports report-only or enabled launch modes.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            string.Empty,
            excludeGroupId);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            $"Preparing the Entra risk policies package in {DescribeLaunchMode(launchMode)} mode.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            logs.Add($"Resolved connection '{connection.DisplayName}'.");

            logs.Add("Executing risky sign-in protection.");
            var riskySignInOutcome = await ExecuteRequireMfaRiskySignInsAsync(
                connectionId,
                ownerOperatorId,
                launchedByOperatorId,
                launchedByOperatorName,
                approvalJustification,
                launchMode,
                excludeGroupId,
                cancellationToken);
            logs.Add($"Risky sign-in result: {riskySignInOutcome.Status} | {NormalizeSummary(riskySignInOutcome.Message)}");
            logs.Add($"Risky sign-in run id: {riskySignInOutcome.RunId}");

            logs.Add("Executing high-risk user password-change protection.");
            var highRiskUserOutcome = await ExecuteRequirePasswordChangeHighRiskUsersAsync(
                connectionId,
                ownerOperatorId,
                launchedByOperatorId,
                launchedByOperatorName,
                approvalJustification,
                launchMode,
                excludeGroupId,
                cancellationToken);
            logs.Add($"High-risk user result: {highRiskUserOutcome.Status} | {NormalizeSummary(highRiskUserOutcome.Message)}");
            logs.Add($"High-risk user run id: {highRiskUserOutcome.RunId}");

            var completedUtc = DateTimeOffset.UtcNow;
            var allSucceeded = riskySignInOutcome.Succeeded && highRiskUserOutcome.Succeeded;
            var allAlreadyExist = riskySignInOutcome.AlreadyExists && highRiskUserOutcome.AlreadyExists;

            if (!allSucceeded)
            {
                var failureSummary =
                    $"The Entra risk policies package completed with failures. Risky sign-ins: {NormalizeSummary(riskySignInOutcome.Message)} High-risk users: {NormalizeSummary(highRiskUserOutcome.Message)}";
                var failedRun = await PersistRunAsync(
                    request,
                    EntraRiskPoliciesTemplateKey,
                    EntraRiskPoliciesTemplateName,
                    connection.DisplayName,
                    startedUtc,
                    completedUtc,
                    RemediationRunStatus.Failed,
                    failureSummary,
                    null,
                    string.IsNullOrWhiteSpace(excludeGroupId) ? null : excludeGroupId.Trim(),
                    null,
                    null,
                    "CompositeFailure",
                    false,
                    logs,
                    cancellationToken);

                return new RemediationExecutionOutcome(
                    failedRun.Id,
                    EntraRiskPoliciesTemplateKey,
                    connectionId,
                    connection.DisplayName,
                    RemediationRunStatus.Failed,
                    false,
                    false,
                    failureSummary,
                    completedUtc,
                    null,
                    "CompositeFailure");
            }

            var packageSummary = allAlreadyExist
                ? $"The Entra risk policies package was already in {DescribeLaunchMode(launchMode).ToLowerInvariant()} state."
                : $"Executed the Entra risk policies package in {DescribeLaunchMode(launchMode).ToLowerInvariant()} mode.";
            var packageStatus = allAlreadyExist ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                EntraRiskPoliciesTemplateKey,
                EntraRiskPoliciesTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                packageStatus,
                packageSummary,
                null,
                string.IsNullOrWhiteSpace(excludeGroupId) ? null : excludeGroupId.Trim(),
                null,
                null,
                $"{DescribeLaunchMode(launchMode)} package",
                allAlreadyExist,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                EntraRiskPoliciesTemplateKey,
                connectionId,
                connection.DisplayName,
                packageStatus,
                true,
                allAlreadyExist,
                packageSummary,
                completedUtc,
                null,
                $"{DescribeLaunchMode(launchMode)} package");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            logs.Add($"Execution failed: {ex.Message}");

            var failedRun = await PersistRunAsync(
                request,
                EntraRiskPoliciesTemplateKey,
                EntraRiskPoliciesTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                NormalizeSummary(ex.Message),
                null,
                string.IsNullOrWhiteSpace(excludeGroupId) ? null : excludeGroupId.Trim(),
                null,
                null,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                EntraRiskPoliciesTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{EntraRiskPoliciesTemplateName} failed. {NormalizeSummary(ex.Message)}",
                failedRun.CompletedUtc,
                null,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteEntraIdentityHygieneAssessmentAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        CancellationToken cancellationToken)
    {
        if (launchMode != RemediationLaunchMode.ReportOnly)
        {
            throw new InvalidOperationException("Entra admin and consent hygiene only supports report-only assessment mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            string.Empty,
            null);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing the Entra admin and consent hygiene assessment.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired a Microsoft Graph application token for Entra identity policy assessment.");

            var result = await _directoryClient.AssessEntraIdentityHygieneAsync(accessToken, cancellationToken);

            logs.Add($"Controls assessed: {result.FindingCount}.");
            logs.Add($"Satisfied controls: {result.SatisfiedCount}.");
            logs.Add($"Controls needing follow-up: {result.NeedsFollowUpCount}.");
            logs.Add($"Manual-review controls: {result.ManualReviewCount}.");
            logs.Add($"Not-applicable controls: {result.NotApplicableCount}.");

            foreach (var finding in result.Findings)
            {
                logs.Add($"Identity hygiene finding: {SummarizeEntraIdentityHygieneFinding(finding)}");
            }

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var policyState = result.NeedsFollowUpCount > 0
                ? "NeedsFollowUp"
                : result.ManualReviewCount > 0
                    ? "ManualReviewRequired"
                    : "Healthy";
            var summary = result.FindingCount == 0
                ? "No Entra identity-hygiene controls were assessed."
                : result.NeedsFollowUpCount > 0
                    ? $"Assessed {result.FindingCount} Entra identity-hygiene control(s): {result.SatisfiedCount} satisfied, {result.NeedsFollowUpCount} needing follow-up, and {result.ManualReviewCount} requiring manual review."
                    : result.ManualReviewCount > 0
                        ? $"Assessed {result.FindingCount} Entra identity-hygiene control(s): {result.SatisfiedCount} satisfied, no direct follow-up required, and {result.ManualReviewCount} still requiring manual review."
                        : $"Assessed {result.FindingCount} Entra identity-hygiene control(s) and found the evaluated tenant settings already aligned with the Securityzator posture.";
            var runStatus = result.NeedsFollowUpCount > 0 || result.ManualReviewCount > 0
                ? RemediationRunStatus.Succeeded
                : RemediationRunStatus.Skipped;

            var storedRun = await PersistRunAsync(
                request,
                EntraIdentityHygieneTemplateKey,
                EntraIdentityHygieneTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                null,
                null,
                null,
                EntraIdentityHygieneTargetName,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                EntraIdentityHygieneTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                EntraIdentityHygieneTargetName,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeSummary(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                EntraIdentityHygieneTemplateKey,
                EntraIdentityHygieneTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                null,
                null,
                EntraIdentityHygieneTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                EntraIdentityHygieneTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{EntraIdentityHygieneTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                EntraIdentityHygieneTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteEntraDailyUseHardeningAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        CancellationToken cancellationToken)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Entra daily-use consent and password hardening only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            string.Empty,
            null);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing the Entra daily-use consent and password hardening workflow.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired a Microsoft Graph application token for Entra tenant-setting automation.");

            var result = await _directoryClient.ApplyEntraDailyUseHardeningAsync(accessToken, cancellationToken);

            logs.Add($"Authorization policy before: {SummarizeAuthorizationPolicy(result.AuthorizationPolicyBefore)}");
            logs.Add($"Authorization policy after: {SummarizeAuthorizationPolicy(result.AuthorizationPolicyAfter)}");
            logs.Add($"Admin consent workflow before: {SummarizeAdminConsentRequestPolicy(result.AdminConsentRequestPolicyBefore)}");
            logs.Add($"Admin consent workflow after: {SummarizeAdminConsentRequestPolicy(result.AdminConsentRequestPolicyAfter)}");
            logs.Add($"Default domain before: {SummarizeDomainPasswordPolicy(result.DefaultDomainBefore)}");
            logs.Add($"Default domain after: {SummarizeDomainPasswordPolicy(result.DefaultDomainAfter)}");
            logs.Add($"User consent updated: {result.UserConsentUpdated}.");
            logs.Add($"Admin consent workflow updated: {result.AdminConsentWorkflowUpdated}.");
            logs.Add($"Password policy updated: {result.PasswordPolicyUpdated}.");

            foreach (var reviewer in result.ReviewerDisplayNames.Where(name => !string.IsNullOrWhiteSpace(name)))
            {
                logs.Add($"Reviewer seed: {NormalizeSummary(reviewer)}");
            }

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "Entra daily-use tenant settings were already aligned with the Securityzator baseline."
                : $"Applied Entra daily-use hardening. Updated user consent={result.UserConsentUpdated}, admin consent workflow={result.AdminConsentWorkflowUpdated}, password policy={result.PasswordPolicyUpdated}.";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var policyState = result.AlreadyCompliant ? "AlreadyCompliant" : "Updated";

            var storedRun = await PersistRunAsync(
                request,
                EntraDailyUseHardeningTemplateKey,
                EntraDailyUseHardeningTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                null,
                null,
                null,
                EntraDailyUseHardeningTargetName,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                EntraDailyUseHardeningTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                EntraDailyUseHardeningTargetName,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeSummary(EnhanceEntraDailyUseFailure(ex.Message));
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                EntraDailyUseHardeningTemplateKey,
                EntraDailyUseHardeningTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                null,
                null,
                EntraDailyUseHardeningTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                EntraDailyUseHardeningTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{EntraDailyUseHardeningTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                EntraDailyUseHardeningTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteEntraLowImpactAppConsentAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        CancellationToken cancellationToken)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Entra low-impact app consent only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            string.Empty,
            null);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing the Entra low-impact app consent workflow.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired a Microsoft Graph application token for Entra authorization-policy automation.");

            var result = await _directoryClient.ApplyEntraLowImpactAppConsentAsync(accessToken, cancellationToken);

            logs.Add($"Authorization policy before: {SummarizeAuthorizationPolicy(result.AuthorizationPolicyBefore)}");
            logs.Add($"Authorization policy after: {SummarizeAuthorizationPolicy(result.AuthorizationPolicyAfter)}");
            logs.Add($"User consent updated: {result.UserConsentUpdated}.");

            foreach (var preservedPolicy in result.PreservedOwnedResourcePolicies.Where(policy => !string.IsNullOrWhiteSpace(policy)))
            {
                logs.Add($"Preserved owned-resource policy: {NormalizeSummary(preservedPolicy)}");
            }

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "Entra low-impact app consent was already aligned with the Securityzator baseline."
                : "Restricted default user consent to low-impact permissions for verified publishers or tenant-registered apps while preserving owned-resource consent assignments.";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var policyState = result.AlreadyCompliant ? "AlreadyCompliant" : "Updated";

            var storedRun = await PersistRunAsync(
                request,
                EntraLowImpactAppConsentTemplateKey,
                EntraLowImpactAppConsentTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                null,
                null,
                null,
                EntraLowImpactAppConsentTargetName,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                EntraLowImpactAppConsentTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                EntraLowImpactAppConsentTargetName,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeSummary(EnhanceEntraLowImpactAppConsentFailure(ex.Message));
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                EntraLowImpactAppConsentTemplateKey,
                EntraLowImpactAppConsentTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                null,
                null,
                EntraLowImpactAppConsentTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                EntraLowImpactAppConsentTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{EntraLowImpactAppConsentTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                EntraLowImpactAppConsentTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteRequireMfaGuestAccessAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        CancellationToken cancellationToken)
    {
        return await ExecuteGroupTargetedConditionalAccessAsync(
            new TemplateExecutionRequest(
                connectionId,
                ownerOperatorId,
                launchedByOperatorId,
                launchedByOperatorName,
                approvalJustification,
                launchMode,
                string.Empty,
                excludeGroupId),
            RequireMfaGuestAccessTemplateKey,
            RequireMfaGuestAccessTemplateName,
            RequireMfaGuestAccessPolicyDisplayName,
            "All guest and external users",
            (token, launchModeValue, _, normalizedExcludeGroupId, tokenCancellation) =>
                _conditionalAccessClient.CreateRequireMfaForGuestAccessPolicyAsync(
                    token,
                    launchModeValue,
                    normalizedExcludeGroupId,
                    tokenCancellation),
            cancellationToken);
    }

    private async Task<RemediationExecutionOutcome> ExecuteRequireMfaAdminPortalsAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        CancellationToken cancellationToken)
    {
        return await ExecuteGroupTargetedConditionalAccessAsync(
            new TemplateExecutionRequest(
                connectionId,
                ownerOperatorId,
                launchedByOperatorId,
                launchedByOperatorName,
                approvalJustification,
                launchMode,
                string.Empty,
                excludeGroupId),
            RequireMfaAdminPortalsTemplateKey,
            RequireMfaAdminPortalsTemplateName,
            RequireMfaAdminPortalsPolicyDisplayName,
            "Protected administrator roles",
            (token, launchModeValue, _, normalizedExcludeGroupId, tokenCancellation) =>
                _conditionalAccessClient.CreateRequireMfaForAdminPortalsPolicyAsync(
                    token,
                    launchModeValue,
                    normalizedExcludeGroupId,
                    tokenCancellation),
            cancellationToken);
    }

    private async Task<RemediationExecutionOutcome> ExecuteRequireMfaAzureManagementAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        CancellationToken cancellationToken)
    {
        return await ExecuteGroupTargetedConditionalAccessAsync(
            new TemplateExecutionRequest(
                connectionId,
                ownerOperatorId,
                launchedByOperatorId,
                launchedByOperatorName,
                approvalJustification,
                launchMode,
                string.Empty,
                excludeGroupId),
            RequireMfaAzureManagementTemplateKey,
            RequireMfaAzureManagementTemplateName,
            RequireMfaAzureManagementPolicyDisplayName,
            "All users",
            (token, launchModeValue, _, normalizedExcludeGroupId, tokenCancellation) =>
                _conditionalAccessClient.CreateRequireMfaForAzureManagementPolicyAsync(
                    token,
                    launchModeValue,
                    normalizedExcludeGroupId,
                    tokenCancellation),
            cancellationToken);
    }

    private async Task<RemediationExecutionOutcome> ExecuteRequireMfaRiskySignInsAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        CancellationToken cancellationToken)
    {
        return await ExecuteGroupTargetedConditionalAccessAsync(
            new TemplateExecutionRequest(
                connectionId,
                ownerOperatorId,
                launchedByOperatorId,
                launchedByOperatorName,
                approvalJustification,
                launchMode,
                string.Empty,
                excludeGroupId),
            RequireMfaRiskySignInsTemplateKey,
            RequireMfaRiskySignInsTemplateName,
            RequireMfaRiskySignInsPolicyDisplayName,
            "All users excluding guests and protected admin roles",
            (token, launchModeValue, _, normalizedExcludeGroupId, tokenCancellation) =>
                _conditionalAccessClient.CreateRequireMfaForRiskySignInsPolicyAsync(
                    token,
                    launchModeValue,
                    normalizedExcludeGroupId,
                    tokenCancellation),
                cancellationToken);
    }

    private async Task<RemediationExecutionOutcome> ExecuteSecureSecurityInfoRegistrationAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        CancellationToken cancellationToken)
    {
        return await ExecuteGroupTargetedConditionalAccessAsync(
            new TemplateExecutionRequest(
                connectionId,
                ownerOperatorId,
                launchedByOperatorId,
                launchedByOperatorName,
                approvalJustification,
                launchMode,
                string.Empty,
                excludeGroupId),
            SecureSecurityInfoRegistrationTemplateKey,
            SecureSecurityInfoRegistrationTemplateName,
            SecureSecurityInfoRegistrationPolicyDisplayName,
            "All users outside trusted locations, excluding guests and emergency exclusions",
            (token, launchModeValue, _, normalizedExcludeGroupId, tokenCancellation) =>
                _conditionalAccessClient.CreateSecureSecurityInfoRegistrationPolicyAsync(
                    token,
                    launchModeValue,
                    normalizedExcludeGroupId,
                    tokenCancellation),
            cancellationToken);
    }

    private async Task<RemediationExecutionOutcome> ExecuteRequirePasswordChangeHighRiskUsersAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        CancellationToken cancellationToken)
    {
        return await ExecuteGroupTargetedConditionalAccessAsync(
            new TemplateExecutionRequest(
                connectionId,
                ownerOperatorId,
                launchedByOperatorId,
                launchedByOperatorName,
                approvalJustification,
                launchMode,
                string.Empty,
                excludeGroupId),
            RequirePasswordChangeHighRiskUsersTemplateKey,
            RequirePasswordChangeHighRiskUsersTemplateName,
            RequirePasswordChangeHighRiskUsersPolicyDisplayName,
            "All users excluding guests and protected admin roles",
            (token, launchModeValue, _, normalizedExcludeGroupId, tokenCancellation) =>
                _conditionalAccessClient.CreateRequirePasswordChangeForHighRiskUsersPolicyAsync(
                    token,
                    launchModeValue,
                    normalizedExcludeGroupId,
                    tokenCancellation),
            cancellationToken);
    }

    public async Task<RemediationExecutionOutcome> ExecuteRequirePhishingResistantMfaAdminsAsync(
        RequirePhishingResistantMfaAdminsRequest request,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteGroupTargetedConditionalAccessAsync(
            new TemplateExecutionRequest(
                request.ConnectionId,
                request.OwnerOperatorId,
                request.LaunchedByOperatorId,
                request.LaunchedByOperatorName,
                request.ApprovalJustification,
                request.LaunchMode,
                request.IncludeGroupId,
                request.ExcludeGroupId),
            RequirePhishingResistantMfaAdminsTemplateKey,
            RequirePhishingResistantMfaAdminsTemplateName,
            RequirePhishingResistantMfaAdminsPolicyDisplayName,
            null,
            (token, launchMode, includeGroupId, excludeGroupId, tokenCancellation) =>
                _conditionalAccessClient.CreateRequirePhishingResistantMfaForAdminsPolicyAsync(
                    token,
                    launchMode,
                    includeGroupId,
                    excludeGroupId,
                    tokenCancellation),
            cancellationToken);
    }

    private async Task<RemediationExecutionOutcome> ExecuteDefenderForOfficeSafeLinksAndAttachmentsAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        CancellationToken cancellationToken)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Defender for Office Safe Links and attachments only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            string.Empty,
            null);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Defender for Office Safe Links and attachments baseline automation.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);

            if (string.IsNullOrWhiteSpace(connection.AutomationCertificateThumbprint))
            {
                throw new InvalidOperationException(
                    "This connection does not have an automation certificate thumbprint. Save a certificate-backed automation profile before queueing the Defender for Office baseline.");
            }

            logs.Add("Resolved the saved automation certificate metadata for Exchange Online app-only authentication.");
            var exchangeOrganization = await ResolveExchangeOrganizationAsync(connection, cancellationToken);
            logs.Add($"Resolved Exchange Online organization identifier '{exchangeOrganization}'.");

            var result = await _defenderForOfficeAutomationClient.ApplySafeLinksAndAttachmentsBaselineAsync(
                exchangeOrganization,
                connection.ClientId,
                connection.AutomationCertificateThumbprint,
                connection.AutomationCertificateStoreLocation,
                connection.AutomationCertificateStoreName,
                cancellationToken);

            logs.Add($"Defender global protection: {SummarizeDefenderForOfficeGlobalProtection(result.GlobalProtection)}");
            logs.Add($"Safe Links baseline: {SummarizeDefenderForOfficeSafeLinks(result.SafeLinks)}");
            logs.Add($"Safe Attachments baseline: {SummarizeDefenderForOfficeSafeAttachments(result.SafeAttachments)}");

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The Defender for Office Safe Links and attachments baseline already matched Securityzator's Business Premium baseline."
                : "Updated Defender for Office Safe Links and attachments to Securityzator's Business Premium baseline.";
            var policyState = result.AlreadyCompliant ? "AlreadyCompliant" : "Updated";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                MdoSafeLinksAndAttachmentsTemplateKey,
                MdoSafeLinksAndAttachmentsTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                null,
                null,
                null,
                MdoSafeLinksAndAttachmentsTargetName,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                MdoSafeLinksAndAttachmentsTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                MdoSafeLinksAndAttachmentsTargetName,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeExchangeAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                MdoSafeLinksAndAttachmentsTemplateKey,
                MdoSafeLinksAndAttachmentsTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                null,
                null,
                MdoSafeLinksAndAttachmentsTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                MdoSafeLinksAndAttachmentsTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{MdoSafeLinksAndAttachmentsTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                MdoSafeLinksAndAttachmentsTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteDefenderForOfficeAntiPhishBaselineAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        CancellationToken cancellationToken)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Defender for Office anti-phishing and impersonation only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            string.Empty,
            null);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Defender for Office anti-phishing and impersonation baseline automation.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);

            if (string.IsNullOrWhiteSpace(connection.AutomationCertificateThumbprint))
            {
                throw new InvalidOperationException(
                    "This connection does not have an automation certificate thumbprint. Save a certificate-backed automation profile before queueing the Defender for Office anti-phish baseline.");
            }

            logs.Add("Resolved the saved automation certificate metadata for Exchange Online app-only authentication.");
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired a Microsoft Graph application token for anti-phish protected-user discovery.");
            var exchangeOrganization = await ResolveExchangeOrganizationAsync(connection, accessToken, cancellationToken);
            logs.Add($"Resolved Exchange Online organization identifier '{exchangeOrganization}'.");

            var protectedUsersToProtect = Array.Empty<string>();

            try
            {
                var privilegedUsers = await _directoryClient.ListRecommendedAntiPhishProtectedUsersAsync(accessToken, cancellationToken);
                protectedUsersToProtect = privilegedUsers
                    .Select(user => user.AntiPhishIdentity)
                    .Where(value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                logs.Add($"Derived {protectedUsersToProtect.Length} privileged account(s) for anti-phish targeted user protection.");
            }
            catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or GraphServiceException)
            {
                logs.Add($"Protected-user discovery warning: {NormalizeSummary(ex.Message)}");
                logs.Add("Continuing with domain impersonation protection and mailbox intelligence while leaving user impersonation protection for operator follow-up.");
            }

            var result = await _defenderForOfficeAutomationClient.ApplyAntiPhishBaselineAsync(
                exchangeOrganization,
                connection.ClientId,
                connection.AutomationCertificateThumbprint,
                connection.AutomationCertificateStoreLocation,
                connection.AutomationCertificateStoreName,
                protectedUsersToProtect,
                cancellationToken);

            logs.Add($"Anti-phish baseline: {SummarizeDefenderForOfficeAntiPhish(result.AntiPhish)}");

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The Defender for Office anti-phishing and impersonation baseline already matched Securityzator's managed Business Premium baseline."
                : "Updated Defender for Office anti-phishing and impersonation to Securityzator's managed Business Premium baseline.";

            if (result.NeedsManualFollowUp)
            {
                summary = $"{summary} Manual follow-up remains for the protected-user seed list.";
            }

            var policyState = result.AlreadyCompliant
                ? result.NeedsManualFollowUp ? "AlreadyCompliantWithFollowUp" : "AlreadyCompliant"
                : result.NeedsManualFollowUp ? "UpdatedWithFollowUp" : "Updated";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                MdoAntiPhishingAndImpersonationTemplateKey,
                MdoAntiPhishingAndImpersonationTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                null,
                null,
                null,
                MdoAntiPhishingAndImpersonationTargetName,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                MdoAntiPhishingAndImpersonationTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                MdoAntiPhishingAndImpersonationTargetName,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or GraphServiceException)
        {
            var normalizedFailure = NormalizeExchangeAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                MdoAntiPhishingAndImpersonationTemplateKey,
                MdoAntiPhishingAndImpersonationTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                null,
                null,
                MdoAntiPhishingAndImpersonationTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                MdoAntiPhishingAndImpersonationTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{MdoAntiPhishingAndImpersonationTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                MdoAntiPhishingAndImpersonationTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteDefenderForOfficeAntiMalwareBaselineAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        CancellationToken cancellationToken)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Defender for Office anti-malware hardening only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            string.Empty,
            null);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Defender for Office anti-malware baseline automation.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);

            if (string.IsNullOrWhiteSpace(connection.AutomationCertificateThumbprint))
            {
                throw new InvalidOperationException(
                    "This connection does not have an automation certificate thumbprint. Save a certificate-backed automation profile before queueing the Defender for Office anti-malware baseline.");
            }

            logs.Add("Resolved the saved automation certificate metadata for Exchange Online app-only authentication.");
            var exchangeOrganization = await ResolveExchangeOrganizationAsync(connection, cancellationToken);
            logs.Add($"Resolved Exchange Online organization identifier '{exchangeOrganization}'.");

            var result = await _defenderForOfficeAutomationClient.ApplyAntiMalwareBaselineAsync(
                exchangeOrganization,
                connection.ClientId,
                connection.AutomationCertificateThumbprint,
                connection.AutomationCertificateStoreLocation,
                connection.AutomationCertificateStoreName,
                cancellationToken);

            logs.Add($"Anti-malware baseline: {SummarizeDefenderForOfficeAntiMalware(result.AntiMalware)}");

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The Defender for Office anti-malware baseline already matched Securityzator's managed Business Premium baseline."
                : "Updated Defender for Office anti-malware posture to Securityzator's managed Business Premium baseline.";

            if (result.NeedsManualFollowUp)
            {
                summary = $"{summary} Manual follow-up remains for preset-policy precedence or inbound-only scope review.";
            }

            var policyState = result.AlreadyCompliant
                ? result.NeedsManualFollowUp ? "AlreadyCompliantWithFollowUp" : "AlreadyCompliant"
                : result.NeedsManualFollowUp ? "UpdatedWithFollowUp" : "Updated";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                MdoAntiMalwareTemplateKey,
                MdoAntiMalwareTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                null,
                null,
                null,
                MdoAntiMalwareTargetName,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                MdoAntiMalwareTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                MdoAntiMalwareTargetName,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeExchangeAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                MdoAntiMalwareTemplateKey,
                MdoAntiMalwareTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                null,
                null,
                MdoAntiMalwareTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                MdoAntiMalwareTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{MdoAntiMalwareTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                MdoAntiMalwareTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteDefenderForOfficeSpamAndForwardingBaselineAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        CancellationToken cancellationToken)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Defender for Office spam and forwarding hardening only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            string.Empty,
            null);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Defender for Office spam and forwarding baseline automation.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);

            if (string.IsNullOrWhiteSpace(connection.AutomationCertificateThumbprint))
            {
                throw new InvalidOperationException(
                    "This connection does not have an automation certificate thumbprint. Save a certificate-backed automation profile before queueing the Defender for Office spam and forwarding baseline.");
            }

            logs.Add("Resolved the saved automation certificate metadata for Exchange Online app-only authentication.");
            var exchangeOrganization = await ResolveExchangeOrganizationAsync(connection, cancellationToken);
            logs.Add($"Resolved Exchange Online organization identifier '{exchangeOrganization}'.");

            var result = await _defenderForOfficeAutomationClient.ApplySpamAndForwardingBaselineAsync(
                exchangeOrganization,
                connection.ClientId,
                connection.AutomationCertificateThumbprint,
                connection.AutomationCertificateStoreLocation,
                connection.AutomationCertificateStoreName,
                cancellationToken);

            logs.Add($"Inbound spam baseline: {SummarizeDefenderForOfficeInboundSpam(result.InboundSpam)}");
            logs.Add($"Outbound spam baseline: {SummarizeDefenderForOfficeOutboundSpam(result.OutboundSpam)}");
            logs.Add($"Connection filter review: {SummarizeDefenderForOfficeConnectionFilter(result.ConnectionFilter)}");

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The Defender for Office spam and forwarding baseline already matched Securityzator's managed Business Premium baseline."
                : "Updated Defender for Office spam and forwarding posture to Securityzator's managed Business Premium baseline.";

            if (result.NeedsManualFollowUp)
            {
                summary = $"{summary} Manual follow-up remains for connection filter or mail-flow review items.";
            }

            var policyState = result.AlreadyCompliant
                ? result.NeedsManualFollowUp ? "AlreadyCompliantWithFollowUp" : "AlreadyCompliant"
                : result.NeedsManualFollowUp ? "UpdatedWithFollowUp" : "Updated";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                MdoSpamAndForwardingTemplateKey,
                MdoSpamAndForwardingTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                null,
                null,
                null,
                MdoSpamAndForwardingTargetName,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                MdoSpamAndForwardingTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                MdoSpamAndForwardingTargetName,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeExchangeAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                MdoSpamAndForwardingTemplateKey,
                MdoSpamAndForwardingTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                null,
                null,
                MdoSpamAndForwardingTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                MdoSpamAndForwardingTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{MdoSpamAndForwardingTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                MdoSpamAndForwardingTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteExchangeOnlineCollaborationMailboxBaselineAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        CancellationToken cancellationToken)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Exchange Online collaboration and mailbox hardening only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            string.Empty,
            null);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Exchange Online collaboration and mailbox hardening baseline automation.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);

            if (string.IsNullOrWhiteSpace(connection.AutomationCertificateThumbprint))
            {
                throw new InvalidOperationException(
                    "This connection does not have an automation certificate thumbprint. Save a certificate-backed automation profile before queueing the Exchange collaboration baseline.");
            }

            logs.Add("Resolved the saved automation certificate metadata for Exchange Online app-only authentication.");
            var exchangeOrganization = await ResolveExchangeOrganizationAsync(connection, cancellationToken);
            logs.Add($"Resolved Exchange Online organization identifier '{exchangeOrganization}'.");

            var result = await _defenderForOfficeAutomationClient.ApplyExchangeCollaborationMailboxBaselineAsync(
                exchangeOrganization,
                connection.ClientId,
                connection.AutomationCertificateThumbprint,
                connection.AutomationCertificateStoreLocation,
                connection.AutomationCertificateStoreName,
                cancellationToken);

            logs.Add($"Exchange organization baseline: {SummarizeExchangeOrganizationSnapshot(result.Organization)}");
            logs.Add($"Default OWA mailbox policy: {SummarizeExchangeOwaMailboxPolicySnapshot(result.OwaMailboxPolicy)}");
            logs.Add($"Default sharing policy review: {SummarizeExchangeSharingPolicySnapshot(result.SharingPolicy)}");

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The Exchange Online collaboration and mailbox baseline already matched Securityzator's managed Business Premium baseline."
                : "Updated Exchange Online collaboration and mailbox settings to Securityzator's managed Business Premium baseline.";

            if (result.NeedsManualFollowUp)
            {
                summary = $"{summary} Manual follow-up remains for sharing policy or licensing-dependent items.";
            }

            var policyState = result.AlreadyCompliant
                ? result.NeedsManualFollowUp ? "AlreadyCompliantWithFollowUp" : "AlreadyCompliant"
                : result.NeedsManualFollowUp ? "UpdatedWithFollowUp" : "Updated";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                ExchangeOnlineCollaborationMailboxTemplateKey,
                ExchangeOnlineCollaborationMailboxTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                null,
                null,
                null,
                ExchangeOnlineCollaborationMailboxTargetName,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                ExchangeOnlineCollaborationMailboxTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                ExchangeOnlineCollaborationMailboxTargetName,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or GraphServiceException)
        {
            var normalizedFailure = NormalizeExchangeAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                ExchangeOnlineCollaborationMailboxTemplateKey,
                ExchangeOnlineCollaborationMailboxTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                null,
                null,
                ExchangeOnlineCollaborationMailboxTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                ExchangeOnlineCollaborationMailboxTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{ExchangeOnlineCollaborationMailboxTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                ExchangeOnlineCollaborationMailboxTargetName,
                "Failed");
        }
    }

    private static string NormalizeExchangeAutomationFailure(string message)
    {
        var normalized = NormalizeSummary(message);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return ExchangeDelegatedBootstrapHint;
        }

        if (normalized.Contains("Enable-OrganizationCustomization", StringComparison.OrdinalIgnoreCase))
        {
            return $"{normalized} {ExchangeDelegatedBootstrapHint}";
        }

        return normalized;
    }

    private static string NormalizeIntuneAutomationFailure(string message)
    {
        var normalized = NormalizeSummary(message);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return "Intune endpoint automation failed without returning a reason. Confirm active Intune licensing, DeviceManagementConfiguration.ReadWrite.All, and the selected pilot group scope.";
        }

        if (normalized.Contains("DeviceManagementConfiguration.ReadWrite.All", StringComparison.OrdinalIgnoreCase))
        {
            return $"{normalized} Add or grant Microsoft Graph DeviceManagementConfiguration.ReadWrite.All and then revalidate the saved connection.";
        }

        if (normalized.Contains("Intune license", StringComparison.OrdinalIgnoreCase))
        {
            return $"{normalized} Confirm that Intune licensing is active and assigned for the target tenant and pilot devices.";
        }

        return normalized;
    }

    private async Task<RemediationExecutionOutcome> ExecuteTeamsMeetingHardeningBaselineAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        CancellationToken cancellationToken)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Teams meeting hardening only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            string.Empty,
            null);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Microsoft Teams meeting policy automation.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            var clientSecret = _secretProtector.Unprotect(connection.ProtectedClientSecret);
            logs.Add("Resolved the saved app secret for Teams meeting policy automation.");

            var result = await _teamsMeetingPolicyAutomationClient.ApplyGlobalMeetingHardeningBaselineAsync(
                connection.TenantId,
                connection.ClientId,
                clientSecret,
                cancellationToken);

            if (result.Before is not null)
            {
                logs.Add($"Teams policy before: {SummarizeTeamsMeetingPolicy(result.Before)}");
            }

            logs.Add($"Teams policy after: {SummarizeTeamsMeetingPolicy(result.After)}");

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The Global Teams meeting policy already matched the Securityzator baseline."
                : "Updated the Global Teams meeting policy to the Securityzator baseline.";
            var policyState = result.AlreadyCompliant ? "AlreadyCompliant" : "Updated";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                TeamsMeetingHardeningTemplateKey,
                TeamsMeetingHardeningTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                null,
                null,
                null,
                result.PolicyIdentity,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                TeamsMeetingHardeningTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                result.PolicyIdentity,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            logs.Add($"Execution failed: {ex.Message}");

            var failedRun = await PersistRunAsync(
                request,
                TeamsMeetingHardeningTemplateKey,
                TeamsMeetingHardeningTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                NormalizeSummary(ex.Message),
                null,
                null,
                null,
                TeamsMeetingHardeningPolicyIdentity,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                TeamsMeetingHardeningTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{TeamsMeetingHardeningTemplateName} failed. {NormalizeSummary(ex.Message)}",
                failedRun.CompletedUtc,
                TeamsMeetingHardeningPolicyIdentity,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteDefenderEndpointCoreProtectionBaselineAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Defender for Endpoint core protection only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            includeGroupId,
            excludeGroupId);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Intune endpoint core protection baseline automation.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired a Microsoft Graph application token for Intune endpoint configuration automation.");

            var result = await _intuneEndpointAutomationClient.ApplyCoreProtectionBaselineAsync(
                accessToken,
                includeGroupId,
                excludeGroupId,
                allUsersAssignment,
                cancellationToken);

            if (result.Before is not null)
            {
                logs.Add($"Endpoint baseline before: {SummarizeEndpointCoreProtectionSnapshot(result.Before)}");
            }

            logs.Add($"Endpoint baseline after: {SummarizeEndpointCoreProtectionSnapshot(result.After)}");
            logs.Add($"Endpoint assignments: {SummarizeEndpointAssignmentTargets(result.Assignments)}");
            logs.Add($"Endpoint core protection profile id: {result.ConfigurationId}");

            if (result.HardeningBefore is not null)
            {
                logs.Add($"Endpoint hardening baseline before: {SummarizeEndpointCoreProtectionHardeningSnapshot(result.HardeningBefore)}");
            }

            logs.Add($"Endpoint hardening baseline after: {SummarizeEndpointCoreProtectionHardeningSnapshot(result.HardeningAfter)}");
            logs.Add($"Endpoint hardening assignments: {SummarizeEndpointAssignmentTargets(result.HardeningAssignments)}");
            logs.Add($"Endpoint hardening profile id: {result.HardeningConfigurationId}");

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            string? includeGroupName = null;
            string? excludeGroupName = null;

            try
            {
                var groups = await _directoryClient.ListGroupsAsync(accessToken, cancellationToken);
                includeGroupName = ResolveGroupName(groups, includeGroupId);
                excludeGroupName = ResolveGroupName(groups, excludeGroupId);
            }
            catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
            {
                logs.Add($"Group name resolution warning: {NormalizeSummary(ex.Message)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The Intune endpoint core protection package already matched Securityzator's pilot profiles and assignments."
                : result.CreatedConfiguration
                    ? "Created the Intune endpoint core protection package and applied the requested pilot assignments."
                    : "Updated the Intune endpoint core protection package and pilot assignments to the Securityzator baseline.";

            if (result.Notes.Count > 0)
            {
                summary = $"{summary} Residual follow-up remains for unsupported core-protection items.";
            }

            var policyState = result.AlreadyCompliant
                ? "AlreadyCompliantWithResidualFollowUp"
                : "UpdatedWithResidualFollowUp";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                DefenderEndpointCoreProtectionTemplateKey,
                DefenderEndpointCoreProtectionTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                includeGroupName,
                excludeGroupId,
                excludeGroupName,
                DefenderEndpointCoreProtectionTargetName,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                DefenderEndpointCoreProtectionTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                DefenderEndpointCoreProtectionTargetName,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeIntuneAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                DefenderEndpointCoreProtectionTemplateKey,
                DefenderEndpointCoreProtectionTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                excludeGroupId,
                null,
                DefenderEndpointCoreProtectionTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                DefenderEndpointCoreProtectionTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{DefenderEndpointCoreProtectionTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                DefenderEndpointCoreProtectionTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteDefenderEndpointFirewallAndSmartScreenBaselineAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Defender Firewall and SmartScreen baseline only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            includeGroupId,
            excludeGroupId);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Intune endpoint firewall and SmartScreen baseline automation.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired a Microsoft Graph application token for Intune firewall and SmartScreen automation.");

            var result = await _intuneEndpointAutomationClient.ApplyFirewallAndSmartScreenBaselineAsync(
                accessToken,
                includeGroupId,
                excludeGroupId,
                allUsersAssignment,
                cancellationToken);

            if (result.Before is not null)
            {
                logs.Add($"Endpoint firewall baseline before: {SummarizeEndpointFirewallAndSmartScreenSnapshot(result.Before)}");
            }

            logs.Add($"Endpoint firewall baseline after: {SummarizeEndpointFirewallAndSmartScreenSnapshot(result.After)}");
            logs.Add($"Endpoint assignments: {SummarizeEndpointAssignmentTargets(result.Assignments)}");
            logs.Add($"Endpoint firewall profile id: {result.ConfigurationId}");

            if (result.EdgeBefore is not null)
            {
                logs.Add($"Endpoint Edge SmartScreen baseline before: {SummarizeEndpointEdgeSmartScreenSnapshot(result.EdgeBefore)}");
            }

            logs.Add($"Endpoint Edge SmartScreen baseline after: {SummarizeEndpointEdgeSmartScreenSnapshot(result.EdgeAfter)}");
            logs.Add($"Endpoint Edge SmartScreen assignments: {SummarizeEndpointAssignmentTargets(result.EdgeAssignments)}");
            logs.Add($"Endpoint Edge SmartScreen profile id: {result.EdgeConfigurationId}");

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            string? includeGroupName = null;
            string? excludeGroupName = null;

            try
            {
                var groups = await _directoryClient.ListGroupsAsync(accessToken, cancellationToken);
                includeGroupName = ResolveGroupName(groups, includeGroupId);
                excludeGroupName = ResolveGroupName(groups, excludeGroupId);
            }
            catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
            {
                logs.Add($"Group name resolution warning: {NormalizeSummary(ex.Message)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The Intune firewall and SmartScreen package already matched Securityzator's pilot profiles and assignments."
                : result.CreatedConfiguration
                    ? "Created the Intune firewall and SmartScreen package and applied the requested pilot assignments."
                    : "Updated the Intune firewall and SmartScreen package and pilot assignments to the Securityzator baseline.";

            if (result.Notes.Count > 0)
            {
                summary = $"{summary} Residual follow-up remains for broader browser-specific controls.";
            }

            var policyState = result.AlreadyCompliant
                ? "AlreadyCompliantWithResidualFollowUp"
                : "UpdatedWithResidualFollowUp";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                DefenderEndpointFirewallAndSmartScreenTemplateKey,
                DefenderEndpointFirewallAndSmartScreenTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                includeGroupName,
                excludeGroupId,
                excludeGroupName,
                DefenderEndpointFirewallAndSmartScreenTargetName,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                DefenderEndpointFirewallAndSmartScreenTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                DefenderEndpointFirewallAndSmartScreenTargetName,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeIntuneAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                DefenderEndpointFirewallAndSmartScreenTemplateKey,
                DefenderEndpointFirewallAndSmartScreenTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                excludeGroupId,
                null,
                DefenderEndpointFirewallAndSmartScreenTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                DefenderEndpointFirewallAndSmartScreenTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{DefenderEndpointFirewallAndSmartScreenTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                DefenderEndpointFirewallAndSmartScreenTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteDefenderEndpointBrowserHardeningBaselineAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Defender browser hardening baseline only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            includeGroupId,
            excludeGroupId);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Intune browser hardening baseline automation.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired a Microsoft Graph application token for Intune browser hardening automation.");

            var result = await _intuneEndpointAutomationClient.ApplyBrowserHardeningBaselineAsync(
                accessToken,
                includeGroupId,
                excludeGroupId,
                allUsersAssignment,
                cancellationToken);

            if (result.Before is not null)
            {
                logs.Add($"Endpoint browser baseline before: {SummarizeEndpointBrowserHardeningSnapshot(result.Before)}");
            }

            logs.Add($"Endpoint browser baseline after: {SummarizeEndpointBrowserHardeningSnapshot(result.After)}");
            logs.Add($"Endpoint assignments: {SummarizeEndpointAssignmentTargets(result.Assignments)}");

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            string? includeGroupName = null;
            string? excludeGroupName = null;

            try
            {
                var groups = await _directoryClient.ListGroupsAsync(accessToken, cancellationToken);
                includeGroupName = ResolveGroupName(groups, includeGroupId);
                excludeGroupName = ResolveGroupName(groups, excludeGroupId);
            }
            catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
            {
                logs.Add($"Group name resolution warning: {NormalizeSummary(ex.Message)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The Intune browser hardening baseline already matched Securityzator's pilot profile and assignments."
                : result.CreatedConfiguration
                    ? "Created the Intune browser hardening baseline and applied the requested pilot assignments."
                    : "Updated the Intune browser hardening baseline and pilot assignments to the Securityzator baseline.";

            if (result.Notes.Count > 0)
            {
                summary = $"{summary} Residual follow-up remains for removed Chrome plugin policy coverage and Adobe-specific browser controls.";
            }

            var policyState = result.AlreadyCompliant
                ? "AlreadyCompliantWithResidualFollowUp"
                : "UpdatedWithResidualFollowUp";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                DefenderEndpointBrowserHardeningTemplateKey,
                DefenderEndpointBrowserHardeningTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                includeGroupName,
                excludeGroupId,
                excludeGroupName,
                result.ConfigurationId,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                DefenderEndpointBrowserHardeningTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                result.ConfigurationId,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeIntuneAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                DefenderEndpointBrowserHardeningTemplateKey,
                DefenderEndpointBrowserHardeningTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                excludeGroupId,
                null,
                DefenderEndpointBrowserHardeningTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                DefenderEndpointBrowserHardeningTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{DefenderEndpointBrowserHardeningTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                DefenderEndpointBrowserHardeningTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteDefenderEndpointBrowserAndAdobePolicySurfaceAssessmentAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        CancellationToken cancellationToken)
    {
        if (launchMode != RemediationLaunchMode.ReportOnly)
        {
            throw new InvalidOperationException("Defender browser and Adobe policy-surface readiness only supports report-only assessment mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            string.Empty,
            null);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Intune browser and Adobe policy-surface readiness assessment.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired a Microsoft Graph application token for Intune policy-surface assessment.");

            var result = await _intuneEndpointAutomationClient.AssessBrowserAndAdobePolicySurfaceAsync(
                accessToken,
                cancellationToken);

            logs.Add($"Policy surfaces assessed: {result.SurfaceCount}.");
            logs.Add($"Ready policy surfaces: {result.ReadySurfaceCount}.");
            logs.Add($"Policy surfaces needing follow-up: {result.FollowUpSurfaceCount}.");

            foreach (var finding in result.Findings)
            {
                logs.Add($"Surface assessment: {SummarizeBrowserAndAdobePolicySurfaceFinding(finding)}");
            }

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The tenant exposes both the Chrome and Adobe Intune policy surfaces Securityzator needs for the remaining browser-app controls."
                : $"Assessed {result.SurfaceCount} browser or Adobe policy surface(s) and found {result.FollowUpSurfaceCount} needing follow-up before those controls become durable automation.";
            var policyState = result.AlreadyCompliant ? "Ready" : "NeedsFollowUp";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;

            var storedRun = await PersistRunAsync(
                request,
                DefenderEndpointBrowserAndAdobePolicySurfaceTemplateKey,
                DefenderEndpointBrowserAndAdobePolicySurfaceTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                null,
                null,
                null,
                DefenderEndpointBrowserAndAdobePolicySurfaceTargetName,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                DefenderEndpointBrowserAndAdobePolicySurfaceTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                false,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                DefenderEndpointBrowserAndAdobePolicySurfaceTargetName,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeIntuneAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                DefenderEndpointBrowserAndAdobePolicySurfaceTemplateKey,
                DefenderEndpointBrowserAndAdobePolicySurfaceTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                null,
                null,
                DefenderEndpointBrowserAndAdobePolicySurfaceTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                DefenderEndpointBrowserAndAdobePolicySurfaceTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{DefenderEndpointBrowserAndAdobePolicySurfaceTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                DefenderEndpointBrowserAndAdobePolicySurfaceTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteDefenderEndpointBitLockerBaselineAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Defender BitLocker startup baseline only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            includeGroupId,
            excludeGroupId);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Intune BitLocker baseline automation.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired a Microsoft Graph application token for Intune BitLocker automation.");

            var result = await _intuneEndpointAutomationClient.ApplyBitLockerBaselineAsync(
                accessToken,
                includeGroupId,
                excludeGroupId,
                allUsersAssignment,
                cancellationToken);

            if (result.Before is not null)
            {
                logs.Add($"Endpoint BitLocker baseline before: {SummarizeEndpointBitLockerSnapshot(result.Before)}");
            }

            logs.Add($"Endpoint BitLocker baseline after: {SummarizeEndpointBitLockerSnapshot(result.After)}");
            logs.Add($"Endpoint assignments: {SummarizeEndpointAssignmentTargets(result.Assignments)}");

            IntuneEndpointAutomationClient.EndpointBitLockerDeploymentAssessmentResult? assessmentResult = null;

            try
            {
                var includeMembers = await _directoryClient.ListGroupMembersAsync(includeGroupId, accessToken, cancellationToken);
                var excludeMembers = string.IsNullOrWhiteSpace(excludeGroupId)
                    ? Array.Empty<DirectoryGraphClient.GraphDirectoryGroupMember>()
                    : await _directoryClient.ListGroupMembersAsync(excludeGroupId, accessToken, cancellationToken);

                var includeUserIds = includeMembers
                    .Where(member => member.IsUser && !string.IsNullOrWhiteSpace(member.Id))
                    .Select(member => member.Id)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
                var includeDeviceIds = includeMembers
                    .Where(member => member.IsDevice)
                    .SelectMany(member => new[] { member.Id, member.DeviceId })
                    .Where(id => !string.IsNullOrWhiteSpace(id))
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
                var excludeUserIds = excludeMembers
                    .Where(member => member.IsUser && !string.IsNullOrWhiteSpace(member.Id))
                    .Select(member => member.Id)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
                var excludeDeviceIds = excludeMembers
                    .Where(member => member.IsDevice)
                    .SelectMany(member => new[] { member.Id, member.DeviceId })
                    .Where(id => !string.IsNullOrWhiteSpace(id))
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                logs.Add($"Scoped include group members: {includeMembers.Count}.");

                if (!string.IsNullOrWhiteSpace(excludeGroupId))
                {
                    logs.Add($"Scoped exclusion group members: {excludeMembers.Count}.");
                }

                assessmentResult = await _intuneEndpointAutomationClient.AssessBitLockerDeploymentStateAsync(
                    accessToken,
                    includeUserIds,
                    includeDeviceIds,
                    excludeUserIds,
                    excludeDeviceIds,
                    excludeGroupId,
                    allUsersAssignment,
                    cancellationToken);

                logs.Add($"Scoped Windows devices assessed: {assessmentResult.ScopedDeviceCount}.");
                logs.Add($"Healthy BitLocker devices: {assessmentResult.HealthyDeviceCount}.");
                logs.Add($"Devices needing BitLocker follow-up: {assessmentResult.NeedsFollowUpDeviceCount}.");

                foreach (var finding in assessmentResult.Findings)
                {
                    logs.Add($"Device assessment: {SummarizeManagedWindowsBitLockerAssessment(finding)}");
                }

                foreach (var note in assessmentResult.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
                {
                    logs.Add($"Note: {NormalizeSummary(note)}");
                }
            }
            catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
            {
                logs.Add($"BitLocker rollout-health assessment warning: {NormalizeSummary(ex.Message)}");
            }

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            string? includeGroupName = null;
            string? excludeGroupName = null;

            try
            {
                var groups = await _directoryClient.ListGroupsAsync(accessToken, cancellationToken);
                includeGroupName = ResolveGroupName(groups, includeGroupId);
                excludeGroupName = ResolveGroupName(groups, excludeGroupId);
            }
            catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
            {
                logs.Add($"Group name resolution warning: {NormalizeSummary(ex.Message)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The Intune BitLocker baseline already matched Securityzator's pilot profile and assignments."
                : result.CreatedConfiguration
                    ? "Created the Intune BitLocker baseline and applied the requested pilot assignments."
                    : "Updated the Intune BitLocker baseline and pilot assignments to the Securityzator baseline.";
            string policyState;

            if (assessmentResult is null)
            {
                summary = $"{summary} BitLocker rollout-health assessment could not be completed, so device-level follow-up remains required.";
                policyState = result.AlreadyCompliant
                    ? "AlreadyCompliantWithAssessmentWarning"
                    : "UpdatedWithAssessmentWarning";
            }
            else if (assessmentResult.ScopedDeviceCount == 0)
            {
                summary = $"{summary} No Windows managed devices in the selected pilot scope have reported BitLocker encryption telemetry yet.";
                policyState = result.AlreadyCompliant
                    ? "AlreadyCompliantAwaitingDeviceTelemetry"
                    : "UpdatedAwaitingDeviceTelemetry";
            }
            else if (assessmentResult.AlreadyCompliant)
            {
                summary = $"{summary} Scoped BitLocker rollout health is currently clean.";
                policyState = result.AlreadyCompliant ? "AlreadyCompliant" : "Updated";
            }
            else
            {
                summary = $"{summary} BitLocker rollout follow-up remains for {assessmentResult.NeedsFollowUpDeviceCount} scoped device(s).";
                policyState = result.AlreadyCompliant
                    ? "AlreadyCompliantWithResidualFollowUp"
                    : "UpdatedWithResidualFollowUp";
            }

            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                DefenderEndpointBitLockerTemplateKey,
                DefenderEndpointBitLockerTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                includeGroupName,
                excludeGroupId,
                excludeGroupName,
                result.ConfigurationId,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                DefenderEndpointBitLockerTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                result.ConfigurationId,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeIntuneAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                DefenderEndpointBitLockerTemplateKey,
                DefenderEndpointBitLockerTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                excludeGroupId,
                null,
                DefenderEndpointBitLockerTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                DefenderEndpointBitLockerTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{DefenderEndpointBitLockerTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                DefenderEndpointBitLockerTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteDefenderEndpointExploitProtectionBaselineAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Defender exploit protection baseline only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            includeGroupId,
            excludeGroupId);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Intune endpoint exploit protection baseline automation.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired a Microsoft Graph application token for Intune exploit protection automation.");

            var result = await _intuneEndpointAutomationClient.ApplyExploitProtectionBaselineAsync(
                accessToken,
                includeGroupId,
                excludeGroupId,
                allUsersAssignment,
                cancellationToken);

            if (result.Before is not null)
            {
                logs.Add($"Endpoint exploit protection baseline before: {SummarizeEndpointExploitProtectionSnapshot(result.Before)}");
            }

            logs.Add($"Endpoint exploit protection baseline after: {SummarizeEndpointExploitProtectionSnapshot(result.After)}");
            logs.Add($"Endpoint assignments: {SummarizeEndpointAssignmentTargets(result.Assignments)}");

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            string? includeGroupName = null;
            string? excludeGroupName = null;

            try
            {
                var groups = await _directoryClient.ListGroupsAsync(accessToken, cancellationToken);
                includeGroupName = ResolveGroupName(groups, includeGroupId);
                excludeGroupName = ResolveGroupName(groups, excludeGroupId);
            }
            catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
            {
                logs.Add($"Group name resolution warning: {NormalizeSummary(ex.Message)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The Intune exploit protection baseline already matched Securityzator's pilot profile and assignments."
                : result.CreatedConfiguration
                    ? "Created the Intune exploit protection baseline and applied the requested pilot assignments."
                    : "Updated the Intune exploit protection baseline and pilot assignments to the Securityzator baseline.";

            if (result.Notes.Count > 0)
            {
                summary = $"{summary} Residual follow-up remains for reboot-sensitive rollout checks and application-specific exploit mitigations.";
            }

            var policyState = result.AlreadyCompliant
                ? "AlreadyCompliantWithResidualFollowUp"
                : "UpdatedWithResidualFollowUp";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                DefenderEndpointExploitProtectionTemplateKey,
                DefenderEndpointExploitProtectionTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                includeGroupName,
                excludeGroupId,
                excludeGroupName,
                result.ConfigurationId,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                DefenderEndpointExploitProtectionTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                result.ConfigurationId,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeIntuneAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                DefenderEndpointExploitProtectionTemplateKey,
                DefenderEndpointExploitProtectionTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                excludeGroupId,
                null,
                DefenderEndpointExploitProtectionTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                DefenderEndpointExploitProtectionTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{DefenderEndpointExploitProtectionTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                DefenderEndpointExploitProtectionTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteDefenderEndpointSensorAndAgentHealthAssessmentAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        if (launchMode != RemediationLaunchMode.ReportOnly)
        {
            throw new InvalidOperationException("Defender for Endpoint sensor and agent health only supports report-only assessment mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            includeGroupId,
            excludeGroupId);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Defender for Endpoint sensor and agent health assessment.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired a Microsoft Graph application token for Intune managed device assessment.");

            var includeMembers = await _directoryClient.ListGroupMembersAsync(includeGroupId, accessToken, cancellationToken);
            var excludeMembers = string.IsNullOrWhiteSpace(excludeGroupId)
                ? Array.Empty<DirectoryGraphClient.GraphDirectoryGroupMember>()
                : await _directoryClient.ListGroupMembersAsync(excludeGroupId, accessToken, cancellationToken);

            var includeUserIds = includeMembers
                .Where(member => member.IsUser && !string.IsNullOrWhiteSpace(member.Id))
                .Select(member => member.Id)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var includeDeviceIds = includeMembers
                .Where(member => member.IsDevice)
                .SelectMany(member => new[] { member.Id, member.DeviceId })
                .Where(id => !string.IsNullOrWhiteSpace(id))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var excludeUserIds = excludeMembers
                .Where(member => member.IsUser && !string.IsNullOrWhiteSpace(member.Id))
                .Select(member => member.Id)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var excludeDeviceIds = excludeMembers
                .Where(member => member.IsDevice)
                .SelectMany(member => new[] { member.Id, member.DeviceId })
                .Where(id => !string.IsNullOrWhiteSpace(id))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            logs.Add($"Scoped include group members: {includeMembers.Count}.");

            if (!string.IsNullOrWhiteSpace(excludeGroupId))
            {
                logs.Add($"Scoped exclusion group members: {excludeMembers.Count}.");
            }

            var result = await _intuneEndpointAutomationClient.AssessEndpointSensorAndAgentHealthAsync(
                accessToken,
                includeGroupId,
                includeUserIds,
                includeDeviceIds,
                excludeUserIds,
                excludeDeviceIds,
                excludeGroupId,
                allUsersAssignment,
                cancellationToken);

            logs.Add($"Scoped Windows devices assessed: {result.ScopedDeviceCount}.");
            logs.Add($"Healthy devices: {result.HealthyDeviceCount}.");
            logs.Add($"Devices needing follow-up: {result.NeedsFollowUpDeviceCount}.");
            logs.Add($"Endpoint detection and response policies discovered: {result.OnboardingPolicies.Count}.");
            logs.Add($"Endpoint detection and response policies covering the pilot scope: {result.OnboardingPolicies.Count(policy => policy.TargetsPilotScope || policy.HasBroadAssignment)}.");

            foreach (var finding in result.Findings)
            {
                logs.Add($"Device assessment: {SummarizeManagedWindowsDeviceHealthAssessment(finding)}");
            }

            foreach (var policy in result.OnboardingPolicies)
            {
                logs.Add($"Onboarding policy assessment: {SummarizeEndpointEdrOnboardingPolicyAssessment(policy)}");
            }

            logs.Add($"WSL readiness: {SummarizeEndpointWslPluginReadinessAssessment(result.WslPluginReadiness)}");

            foreach (var evidenceItem in result.WslPluginReadiness.Evidence.Where(item => !string.IsNullOrWhiteSpace(item)))
            {
                logs.Add($"WSL evidence: {NormalizeSummary(evidenceItem)}");
            }

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            string? includeGroupName = null;
            string? excludeGroupName = null;

            try
            {
                var groups = await _directoryClient.ListGroupsAsync(accessToken, cancellationToken);
                includeGroupName = ResolveGroupName(groups, includeGroupId);
                excludeGroupName = ResolveGroupName(groups, excludeGroupId);
            }
            catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
            {
                logs.Add($"Group name resolution warning: {NormalizeSummary(ex.Message)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var scopedOnboardingPolicyCount = result.OnboardingPolicies.Count(policy => policy.TargetsPilotScope || policy.HasBroadAssignment);
            var summary = result.ScopedDeviceCount == 0
                ? "No Windows managed devices matched the selected pilot scope for Defender sensor and agent-health assessment."
                : result.AlreadyCompliant
                    ? scopedOnboardingPolicyCount > 0
                        ? $"Assessed {result.ScopedDeviceCount} Windows managed device(s), found healthy Defender telemetry, and confirmed {scopedOnboardingPolicyCount} Intune endpoint detection and response policy assignment(s) covering the pilot scope."
                        : $"Assessed {result.ScopedDeviceCount} Windows managed device(s) and found healthy Defender telemetry. No direct Intune endpoint detection and response policy targeted the pilot scope, so the current onboarding path may be manual or legacy."
                    : $"Assessed {result.ScopedDeviceCount} Windows managed device(s) and found {result.NeedsFollowUpDeviceCount} device(s) needing Defender sensor, onboarding, or agent-health follow-up.";
            var policyState = result.ScopedDeviceCount == 0
                ? "NoScopedDevices"
                : result.AlreadyCompliant
                    ? "Healthy"
                    : "NeedsFollowUp";
            var runStatus = result.ScopedDeviceCount == 0 || result.AlreadyCompliant
                ? RemediationRunStatus.Skipped
                : RemediationRunStatus.Succeeded;

            var storedRun = await PersistRunAsync(
                request,
                DefenderEndpointSensorAndAgentHealthTemplateKey,
                DefenderEndpointSensorAndAgentHealthTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                includeGroupName,
                excludeGroupId,
                excludeGroupName,
                DefenderEndpointSensorAndAgentHealthTargetName,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                DefenderEndpointSensorAndAgentHealthTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                DefenderEndpointSensorAndAgentHealthTargetName,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeIntuneAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                DefenderEndpointSensorAndAgentHealthTemplateKey,
                DefenderEndpointSensorAndAgentHealthTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                excludeGroupId,
                null,
                DefenderEndpointSensorAndAgentHealthTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                DefenderEndpointSensorAndAgentHealthTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{DefenderEndpointSensorAndAgentHealthTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                DefenderEndpointSensorAndAgentHealthTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteDefenderEndpointOsSecurityBaselineAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Endpoint OS and platform security baseline only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            includeGroupId,
            excludeGroupId);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Intune endpoint OS security baseline automation.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired a Microsoft Graph application token for Intune endpoint OS security automation.");

            var result = await _intuneEndpointAutomationClient.ApplyOsSecurityBaselineAsync(
                accessToken,
                includeGroupId,
                excludeGroupId,
                allUsersAssignment,
                cancellationToken);

            if (result.Before is not null)
            {
                logs.Add($"Endpoint OS baseline before: {SummarizeEndpointOsSecuritySnapshot(result.Before)}");
            }

            logs.Add($"Endpoint OS baseline after: {SummarizeEndpointOsSecuritySnapshot(result.After)}");
            logs.Add($"Endpoint assignments: {SummarizeEndpointAssignmentTargets(result.Assignments)}");

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            string? includeGroupName = null;
            string? excludeGroupName = null;

            try
            {
                var groups = await _directoryClient.ListGroupsAsync(accessToken, cancellationToken);
                includeGroupName = ResolveGroupName(groups, includeGroupId);
                excludeGroupName = ResolveGroupName(groups, excludeGroupId);
            }
            catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
            {
                logs.Add($"Group name resolution warning: {NormalizeSummary(ex.Message)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The Intune endpoint OS security baseline already matched Securityzator's pilot profile and assignments."
                : result.CreatedConfiguration
                    ? "Created the Intune endpoint OS security baseline and applied the requested pilot assignments."
                    : "Updated the Intune endpoint OS security baseline and pilot assignments to the Securityzator baseline.";

            if (result.Notes.Count > 0)
            {
                summary = $"{summary} Residual follow-up remains for unsupported OS and infrastructure-sensitive items.";
            }

            var policyState = result.AlreadyCompliant
                ? "AlreadyCompliantWithResidualFollowUp"
                : "UpdatedWithResidualFollowUp";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                DefenderEndpointOsSecurityBaselineTemplateKey,
                DefenderEndpointOsSecurityBaselineTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                includeGroupName,
                excludeGroupId,
                excludeGroupName,
                result.ConfigurationId,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                DefenderEndpointOsSecurityBaselineTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                result.ConfigurationId,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeIntuneAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                DefenderEndpointOsSecurityBaselineTemplateKey,
                DefenderEndpointOsSecurityBaselineTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                excludeGroupId,
                null,
                DefenderEndpointOsSecurityBaselineTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                DefenderEndpointOsSecurityBaselineTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{DefenderEndpointOsSecurityBaselineTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                DefenderEndpointOsSecurityBaselineTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteDefenderEndpointCredentialAndElevationHardeningBaselineAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Defender credential and elevation hardening only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            includeGroupId,
            excludeGroupId);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Intune endpoint credential and elevation hardening automation.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired a Microsoft Graph application token for Intune credential and elevation hardening automation.");

            var result = await _intuneEndpointAutomationClient.ApplyCredentialAndElevationHardeningBaselineAsync(
                accessToken,
                includeGroupId,
                excludeGroupId,
                allUsersAssignment,
                cancellationToken);

            if (result.Before is not null)
            {
                logs.Add($"Endpoint credential/elevation baseline before: {SummarizeEndpointCredentialAndElevationSnapshot(result.Before)}");
            }

            logs.Add($"Endpoint credential/elevation baseline after: {SummarizeEndpointCredentialAndElevationSnapshot(result.After)}");
            logs.Add($"Endpoint assignments: {SummarizeEndpointAssignmentTargets(result.Assignments)}");

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            string? includeGroupName = null;
            string? excludeGroupName = null;

            try
            {
                var groups = await _directoryClient.ListGroupsAsync(accessToken, cancellationToken);
                includeGroupName = ResolveGroupName(groups, includeGroupId);
                excludeGroupName = ResolveGroupName(groups, excludeGroupId);
            }
            catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
            {
                logs.Add($"Group name resolution warning: {NormalizeSummary(ex.Message)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The Intune credential and elevation hardening baseline already matched Securityzator's pilot profile and assignments."
                : result.CreatedConfiguration
                    ? "Created the Intune credential and elevation hardening baseline and applied the requested pilot assignments."
                    : "Updated the Intune credential and elevation hardening baseline and pilot assignments to the Securityzator baseline.";

            if (result.Notes.Count > 0)
            {
                summary = $"{summary} Residual follow-up remains for adjacent credential and remote-management items.";
            }

            var policyState = result.AlreadyCompliant
                ? "AlreadyCompliantWithResidualFollowUp"
                : "UpdatedWithResidualFollowUp";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                DefenderEndpointCredentialAndElevationHardeningTemplateKey,
                DefenderEndpointCredentialAndElevationHardeningTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                includeGroupName,
                excludeGroupId,
                excludeGroupName,
                result.ConfigurationId,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                DefenderEndpointCredentialAndElevationHardeningTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                result.ConfigurationId,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeIntuneAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                DefenderEndpointCredentialAndElevationHardeningTemplateKey,
                DefenderEndpointCredentialAndElevationHardeningTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                excludeGroupId,
                null,
                DefenderEndpointCredentialAndElevationHardeningTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                DefenderEndpointCredentialAndElevationHardeningTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{DefenderEndpointCredentialAndElevationHardeningTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                DefenderEndpointCredentialAndElevationHardeningTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteDefenderEndpointAttackSurfaceReductionBaselineAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Defender for Endpoint attack surface reduction only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            includeGroupId,
            excludeGroupId);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Intune endpoint attack surface reduction baseline automation.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired a Microsoft Graph application token for Intune attack surface reduction automation.");

            var result = await _intuneEndpointAutomationClient.ApplyAttackSurfaceReductionBaselineAsync(
                accessToken,
                includeGroupId,
                excludeGroupId,
                allUsersAssignment,
                cancellationToken);

            if (result.Before is not null)
            {
                logs.Add($"ASR baseline before: {SummarizeEndpointAttackSurfaceReductionSnapshot(result.Before)}");
            }

            logs.Add($"ASR baseline after: {SummarizeEndpointAttackSurfaceReductionSnapshot(result.After)}");
            logs.Add($"Endpoint assignments: {SummarizeEndpointAssignmentTargets(result.Assignments)}");

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            string? includeGroupName = null;
            string? excludeGroupName = null;

            try
            {
                var groups = await _directoryClient.ListGroupsAsync(accessToken, cancellationToken);
                includeGroupName = ResolveGroupName(groups, includeGroupId);
                excludeGroupName = ResolveGroupName(groups, excludeGroupId);
            }
            catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
            {
                logs.Add($"Group name resolution warning: {NormalizeSummary(ex.Message)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The Intune attack surface reduction baseline already matched Securityzator's pilot profile and assignments."
                : result.CreatedConfiguration
                    ? "Created the Intune attack surface reduction baseline and applied the requested pilot assignments."
                    : "Updated the Intune attack surface reduction baseline and pilot assignments to the Securityzator baseline.";

            if (result.Notes.Count > 0)
            {
                summary = $"{summary} Residual follow-up remains for unsupported ASR and browser or server-specific items.";
            }

            var policyState = result.AlreadyCompliant
                ? "AlreadyCompliantWithResidualFollowUp"
                : "UpdatedWithResidualFollowUp";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                DefenderEndpointAttackSurfaceReductionTemplateKey,
                DefenderEndpointAttackSurfaceReductionTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                includeGroupName,
                excludeGroupId,
                excludeGroupName,
                result.ConfigurationId,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                DefenderEndpointAttackSurfaceReductionTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                result.ConfigurationId,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeIntuneAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                DefenderEndpointAttackSurfaceReductionTemplateKey,
                DefenderEndpointAttackSurfaceReductionTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                excludeGroupId,
                null,
                DefenderEndpointAttackSurfaceReductionTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                DefenderEndpointAttackSurfaceReductionTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{DefenderEndpointAttackSurfaceReductionTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                DefenderEndpointAttackSurfaceReductionTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteDefenderEndpointRemoteAccessAndNetworkHardeningBaselineAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid launchedByOperatorId,
        string launchedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        if (launchMode != RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException("Defender remote access and network hardening only supports direct-apply mode.");
        }

        var request = new TemplateExecutionRequest(
            connectionId,
            ownerOperatorId,
            launchedByOperatorId,
            launchedByOperatorName,
            approvalJustification,
            launchMode,
            includeGroupId,
            excludeGroupId);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Preparing Intune endpoint remote access and network hardening automation.",
            $"Approval justification: {NormalizeSummary(approvalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(connectionId, ownerOperatorId, true, cancellationToken);
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired a Microsoft Graph application token for Intune endpoint remote access and network hardening automation.");

            var result = await _intuneEndpointAutomationClient.ApplyRemoteAccessAndNetworkHardeningBaselineAsync(
                accessToken,
                includeGroupId,
                excludeGroupId,
                allUsersAssignment,
                cancellationToken);

            if (result.Before is not null)
            {
                logs.Add($"Endpoint remote/network baseline before: {SummarizeEndpointRemoteAccessAndNetworkHardeningSnapshot(result.Before)}");
            }

            logs.Add($"Endpoint remote/network baseline after: {SummarizeEndpointRemoteAccessAndNetworkHardeningSnapshot(result.After)}");
            logs.Add($"Endpoint assignments: {SummarizeEndpointAssignmentTargets(result.Assignments)}");

            foreach (var note in result.Notes.Where(note => !string.IsNullOrWhiteSpace(note)))
            {
                logs.Add($"Note: {NormalizeSummary(note)}");
            }

            string? includeGroupName = null;
            string? excludeGroupName = null;

            try
            {
                var groups = await _directoryClient.ListGroupsAsync(accessToken, cancellationToken);
                includeGroupName = ResolveGroupName(groups, includeGroupId);
                excludeGroupName = ResolveGroupName(groups, excludeGroupId);
            }
            catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
            {
                logs.Add($"Group name resolution warning: {NormalizeSummary(ex.Message)}");
            }

            var completedUtc = DateTimeOffset.UtcNow;
            var summary = result.AlreadyCompliant
                ? "The Intune remote access and network hardening baseline already matched Securityzator's pilot profile and assignments."
                : result.CreatedConfiguration
                    ? "Created the Intune remote access and network hardening baseline and applied the requested pilot assignments."
                    : "Updated the Intune remote access and network hardening baseline and pilot assignments to the Securityzator baseline.";

            if (result.Notes.Count > 0)
            {
                summary = $"{summary} Residual follow-up remains for adjacent host-network and remote-management items.";
            }

            var policyState = result.AlreadyCompliant
                ? "AlreadyCompliantWithResidualFollowUp"
                : "UpdatedWithResidualFollowUp";
            var runStatus = result.AlreadyCompliant ? RemediationRunStatus.Skipped : RemediationRunStatus.Succeeded;
            var storedRun = await PersistRunAsync(
                request,
                DefenderEndpointRemoteAccessAndNetworkHardeningTemplateKey,
                DefenderEndpointRemoteAccessAndNetworkHardeningTemplateName,
                connection.DisplayName,
                startedUtc,
                completedUtc,
                runStatus,
                summary,
                includeGroupName,
                excludeGroupId,
                excludeGroupName,
                result.ConfigurationId,
                policyState,
                result.AlreadyCompliant,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                storedRun.Id,
                DefenderEndpointRemoteAccessAndNetworkHardeningTemplateKey,
                connectionId,
                connection.DisplayName,
                runStatus,
                true,
                result.AlreadyCompliant,
                summary,
                completedUtc,
                result.ConfigurationId,
                policyState);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            var normalizedFailure = NormalizeIntuneAutomationFailure(ex.Message);
            logs.Add($"Execution failed: {normalizedFailure}");

            var failedRun = await PersistRunAsync(
                request,
                DefenderEndpointRemoteAccessAndNetworkHardeningTemplateKey,
                DefenderEndpointRemoteAccessAndNetworkHardeningTemplateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                normalizedFailure,
                null,
                excludeGroupId,
                null,
                DefenderEndpointRemoteAccessAndNetworkHardeningTargetName,
                "Failed",
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                DefenderEndpointRemoteAccessAndNetworkHardeningTemplateKey,
                connectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{DefenderEndpointRemoteAccessAndNetworkHardeningTemplateName} failed. {normalizedFailure}",
                failedRun.CompletedUtc,
                DefenderEndpointRemoteAccessAndNetworkHardeningTargetName,
                "Failed");
        }
    }

    private async Task<RemediationExecutionOutcome> ExecuteGroupTargetedConditionalAccessAsync(
        TemplateExecutionRequest request,
        string templateKey,
        string templateName,
        string policyDisplayName,
        string? includeTargetFallbackName,
        Func<string, RemediationLaunchMode, string, string?, CancellationToken, Task<ConditionalAccessPolicySummary>> createPolicyAsync,
        CancellationToken cancellationToken)
    {
        if (request.LaunchMode == RemediationLaunchMode.DirectApply)
        {
            throw new InvalidOperationException($"Template '{templateKey}' does not support direct-apply mode through the Conditional Access engine.");
        }

        var normalizedIncludeGroupId = string.IsNullOrWhiteSpace(request.IncludeGroupId)
            ? string.Empty
            : request.IncludeGroupId.Trim();
        var normalizedExcludeGroupId = string.IsNullOrWhiteSpace(request.ExcludeGroupId)
            ? null
            : request.ExcludeGroupId.Trim();
        var desiredPolicyState = ResolveConditionalAccessState(request.LaunchMode);
        var startedUtc = DateTimeOffset.UtcNow;
        var logs = new List<string>
        {
            "Resolving the saved Azure connection.",
            "Validating backend token acquisition against Microsoft Entra.",
            $"Launch mode: {DescribeLaunchMode(request.LaunchMode)}",
            $"Approval justification: {NormalizeSummary(request.ApprovalJustification)}"
        };

        try
        {
            var connection = await ResolveConnectionAsync(request.ConnectionId, request.OwnerOperatorId, true, cancellationToken);
            var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
            logs.Add("Acquired Microsoft Graph app token.");

            var groups = await _directoryClient.ListGroupsAsync(accessToken, cancellationToken);
            var includeGroupName = ResolveGroupName(groups, normalizedIncludeGroupId) ?? includeTargetFallbackName;
            var excludeGroupName = ResolveGroupName(groups, normalizedExcludeGroupId);
            logs.Add("Resolved tenant targets for include and exclusion inputs.");

            logs.Add($"Checking for an existing Conditional Access policy named '{policyDisplayName}'.");
            var existingPolicy = await _conditionalAccessClient.FindPolicyByDisplayNameAsync(
                accessToken,
                policyDisplayName,
                cancellationToken);

            if (existingPolicy is not null)
            {
                if (string.Equals(existingPolicy.State, desiredPolicyState, StringComparison.OrdinalIgnoreCase))
                {
                    logs.Add($"Existing policy found with id '{existingPolicy.Id}' already in state '{existingPolicy.State}'.");
                    var skippedRun = await PersistRunAsync(
                        request,
                        templateKey,
                        templateName,
                        connection.DisplayName,
                        startedUtc,
                        DateTimeOffset.UtcNow,
                        RemediationRunStatus.Skipped,
                        $"'{policyDisplayName}' already exists in {DescribeLaunchMode(request.LaunchMode).ToLowerInvariant()} state.",
                        includeGroupName,
                        normalizedExcludeGroupId,
                        excludeGroupName,
                        existingPolicy.Id,
                        existingPolicy.State,
                        true,
                        logs,
                        cancellationToken);

                    return new RemediationExecutionOutcome(
                        skippedRun.Id,
                        templateKey,
                        request.ConnectionId,
                        connection.DisplayName,
                        RemediationRunStatus.Skipped,
                        true,
                        true,
                        $"'{policyDisplayName}' already exists in {DescribeLaunchMode(request.LaunchMode).ToLowerInvariant()} state for '{connection.DisplayName}'.",
                        skippedRun.CompletedUtc,
                        existingPolicy.Id,
                        existingPolicy.State);
                }

                if (request.LaunchMode == RemediationLaunchMode.Enabled)
                {
                    logs.Add($"Existing policy found with id '{existingPolicy.Id}' in state '{existingPolicy.State}'. Promoting it to 'enabled'.");
                    var promotedPolicy = await _conditionalAccessClient.UpdatePolicyStateAsync(
                        accessToken,
                        existingPolicy.Id,
                        desiredPolicyState,
                        cancellationToken);
                    logs.Add($"Updated existing policy '{promotedPolicy.DisplayName}' to state '{promotedPolicy.State}'.");

                    if (!ConditionalAccessStateMatches(promotedPolicy.State, desiredPolicyState))
                    {
                        logs.Add($"Readback mismatch: requested state '{desiredPolicyState}', but Microsoft Graph returned '{promotedPolicy.State}'.");

                        var failedPromotionRun = await PersistRunAsync(
                            request,
                            templateKey,
                            templateName,
                            connection.DisplayName,
                            startedUtc,
                            DateTimeOffset.UtcNow,
                            RemediationRunStatus.Failed,
                            $"Securityzator requested '{desiredPolicyState}' for '{policyDisplayName}', but Graph readback remained '{promotedPolicy.State}'.",
                            includeGroupName,
                            normalizedExcludeGroupId,
                            excludeGroupName,
                            promotedPolicy.Id,
                            promotedPolicy.State,
                            false,
                            logs,
                            cancellationToken);

                        return new RemediationExecutionOutcome(
                            failedPromotionRun.Id,
                            templateKey,
                            request.ConnectionId,
                            connection.DisplayName,
                            RemediationRunStatus.Failed,
                            false,
                            false,
                            $"Requested enabled state for '{policyDisplayName}' on '{connection.DisplayName}', but Graph read back '{promotedPolicy.State}'.",
                            failedPromotionRun.CompletedUtc,
                            promotedPolicy.Id,
                            promotedPolicy.State);
                    }

                    var promotedRun = await PersistRunAsync(
                        request,
                        templateKey,
                        templateName,
                        connection.DisplayName,
                        startedUtc,
                        DateTimeOffset.UtcNow,
                        RemediationRunStatus.Succeeded,
                        $"Promoted '{policyDisplayName}' to enabled state.",
                        includeGroupName,
                        normalizedExcludeGroupId,
                        excludeGroupName,
                        promotedPolicy.Id,
                        promotedPolicy.State,
                        false,
                        logs,
                        cancellationToken);

                    return new RemediationExecutionOutcome(
                        promotedRun.Id,
                        templateKey,
                        request.ConnectionId,
                        connection.DisplayName,
                        RemediationRunStatus.Succeeded,
                        true,
                        false,
                        $"Promoted '{policyDisplayName}' to enabled state for '{connection.DisplayName}'.",
                        promotedRun.CompletedUtc,
                        promotedPolicy.Id,
                        promotedPolicy.State);
                }

                logs.Add($"Existing policy found with id '{existingPolicy.Id}' in stronger state '{existingPolicy.State}'. Securityzator will not downgrade it.");
                var existingEnabledRun = await PersistRunAsync(
                    request,
                    templateKey,
                    templateName,
                    connection.DisplayName,
                    startedUtc,
                    DateTimeOffset.UtcNow,
                    RemediationRunStatus.Skipped,
                    $"'{policyDisplayName}' already exists in state '{existingPolicy.State}'. Securityzator did not downgrade it to report-only.",
                    includeGroupName,
                    normalizedExcludeGroupId,
                    excludeGroupName,
                    existingPolicy.Id,
                    existingPolicy.State,
                    true,
                    logs,
                    cancellationToken);

                return new RemediationExecutionOutcome(
                    existingEnabledRun.Id,
                    templateKey,
                    request.ConnectionId,
                    connection.DisplayName,
                    RemediationRunStatus.Skipped,
                    true,
                    true,
                    $"'{policyDisplayName}' already exists in state '{existingPolicy.State}' for '{connection.DisplayName}'. Securityzator did not downgrade it.",
                    existingEnabledRun.CompletedUtc,
                    existingPolicy.Id,
                    existingPolicy.State);
            }

            logs.Add($"Creating the Conditional Access policy through Microsoft Graph in '{desiredPolicyState}' state.");
            var createdPolicy = await createPolicyAsync(
                accessToken,
                request.LaunchMode,
                normalizedIncludeGroupId,
                normalizedExcludeGroupId,
                cancellationToken);
            logs.Add($"Created policy '{createdPolicy.DisplayName}' with id '{createdPolicy.Id}' in state '{createdPolicy.State}'.");

            if (!ConditionalAccessStateMatches(createdPolicy.State, desiredPolicyState))
            {
                logs.Add($"Readback mismatch: requested state '{desiredPolicyState}', but Microsoft Graph returned '{createdPolicy.State}'.");

                var failedCreationRun = await PersistRunAsync(
                    request,
                    templateKey,
                    templateName,
                    connection.DisplayName,
                    startedUtc,
                    DateTimeOffset.UtcNow,
                    RemediationRunStatus.Failed,
                    $"Securityzator requested '{desiredPolicyState}' for '{policyDisplayName}', but Graph created the policy in '{createdPolicy.State}'.",
                    includeGroupName,
                    normalizedExcludeGroupId,
                    excludeGroupName,
                    createdPolicy.Id,
                    createdPolicy.State,
                    false,
                    logs,
                    cancellationToken);

                return new RemediationExecutionOutcome(
                    failedCreationRun.Id,
                    templateKey,
                    request.ConnectionId,
                    connection.DisplayName,
                    RemediationRunStatus.Failed,
                    false,
                    false,
                    $"Requested {DescribeLaunchMode(request.LaunchMode).ToLowerInvariant()} state for '{policyDisplayName}' on '{connection.DisplayName}', but Graph created '{createdPolicy.State}'.",
                    failedCreationRun.CompletedUtc,
                    createdPolicy.Id,
                    createdPolicy.State);
            }

            var succeededRun = await PersistRunAsync(
                request,
                templateKey,
                templateName,
                connection.DisplayName,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Succeeded,
                $"Created '{policyDisplayName}' in {DescribeLaunchMode(request.LaunchMode).ToLowerInvariant()} state.",
                includeGroupName,
                normalizedExcludeGroupId,
                excludeGroupName,
                createdPolicy.Id,
                createdPolicy.State,
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                succeededRun.Id,
                templateKey,
                request.ConnectionId,
                connection.DisplayName,
                RemediationRunStatus.Succeeded,
                true,
                false,
                $"Created '{policyDisplayName}' in {DescribeLaunchMode(request.LaunchMode).ToLowerInvariant()} state for '{connection.DisplayName}'.",
                succeededRun.CompletedUtc,
                createdPolicy.Id,
                createdPolicy.State);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            logs.Add($"Execution failed: {ex.Message}");

            var failedRun = await PersistRunAsync(
                request,
                templateKey,
                templateName,
                string.Empty,
                startedUtc,
                DateTimeOffset.UtcNow,
                RemediationRunStatus.Failed,
                NormalizeSummary(ex.Message),
                null,
                normalizedExcludeGroupId,
                null,
                null,
                null,
                false,
                logs,
                cancellationToken);

            return new RemediationExecutionOutcome(
                failedRun.Id,
                templateKey,
                request.ConnectionId,
                failedRun.ConnectionDisplayName,
                RemediationRunStatus.Failed,
                false,
                false,
                $"{templateName} failed. {NormalizeSummary(ex.Message)}",
                failedRun.CompletedUtc,
                null,
                null);
        }
    }

    private async Task<StoredAzureConnectionProfile> ResolveConnectionAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        bool requireClientSecret,
        CancellationToken cancellationToken)
    {
        var connection = await _stateStore.ReadAsync(
            state => state.Connections.FirstOrDefault(item =>
                item.Id == connectionId && item.OwnerOperatorId == ownerOperatorId),
            cancellationToken);

        if (connection is null)
        {
            throw new InvalidOperationException("The selected Azure connection could not be found.");
        }

        if (requireClientSecret && string.IsNullOrWhiteSpace(connection.ProtectedClientSecret))
        {
            throw new InvalidOperationException("The selected Azure connection does not have a stored client secret.");
        }

        return connection;
    }

    private async Task<string> AcquireAccessTokenAsync(
        StoredAzureConnectionProfile connection,
        CancellationToken cancellationToken)
    {
        var clientSecret = _secretProtector.Unprotect(connection.ProtectedClientSecret);
        return await _tokenService.AcquireApplicationTokenAsync(
            connection.TenantId,
            connection.ClientId,
            clientSecret,
            cancellationToken);
    }

    private async Task<string> ResolveExchangeOrganizationAsync(
        StoredAzureConnectionProfile connection,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(connection.TenantId, out _))
        {
            return connection.TenantId.Trim();
        }

        var accessToken = await AcquireAccessTokenAsync(connection, cancellationToken);
        return await _directoryClient.ResolveExchangeOrganizationAsync(accessToken, cancellationToken);
    }

    private Task<string> ResolveExchangeOrganizationAsync(
        StoredAzureConnectionProfile connection,
        string accessToken,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(connection.TenantId, out _))
        {
            return Task.FromResult(connection.TenantId.Trim());
        }

        return _directoryClient.ResolveExchangeOrganizationAsync(accessToken, cancellationToken);
    }

    private Task<StoredRemediationRun> PersistRunAsync(
        TemplateExecutionRequest request,
        string templateKey,
        string templateName,
        string connectionDisplayName,
        DateTimeOffset startedUtc,
        DateTimeOffset completedUtc,
        RemediationRunStatus status,
        string summary,
        string? includeGroupName,
        string? excludeGroupId,
        string? excludeGroupName,
        string? policyId,
        string? policyState,
        bool alreadyExists,
        List<string> logs,
        CancellationToken cancellationToken)
    {
        return _stateStore.WriteAsync(state =>
        {
            var stored = new StoredRemediationRun
            {
                Id = Guid.NewGuid(),
                OwnerOperatorId = request.OwnerOperatorId,
                LaunchedByOperatorId = request.LaunchedByOperatorId,
                LaunchedByOperatorName = request.LaunchedByOperatorName.Trim(),
                ApprovalJustification = NormalizeSummary(request.ApprovalJustification),
                LaunchMode = request.LaunchMode,
                ConnectionId = request.ConnectionId,
                ConnectionDisplayName = string.IsNullOrWhiteSpace(connectionDisplayName)
                    ? ResolveConnectionDisplayName(state, request.ConnectionId)
                    : connectionDisplayName,
                TemplateKey = templateKey,
                TemplateName = templateName,
                Status = status,
                Summary = NormalizeSummary(summary),
                StartedUtc = startedUtc,
                CompletedUtc = completedUtc,
                IncludeGroupId = string.IsNullOrWhiteSpace(request.IncludeGroupId)
                    ? string.Empty
                    : request.IncludeGroupId.Trim(),
                IncludeGroupName = includeGroupName,
                ExcludeGroupId = excludeGroupId,
                ExcludeGroupName = excludeGroupName,
                PolicyId = policyId,
                PolicyState = policyState,
                AlreadyExists = alreadyExists,
                Logs = logs.Select(log => log.Trim()).Where(log => log.Length > 0).ToList()
            };

            state.RemediationRuns.Add(stored);
            return stored;
        }, cancellationToken);
    }

    private static string ResolveConnectionDisplayName(SecurityzatorStateDocument state, Guid connectionId)
    {
        return state.Connections.FirstOrDefault(item => item.Id == connectionId)?.DisplayName
               ?? "Unknown connection";
    }

    private static string? ResolveGroupName(
        IReadOnlyList<GraphDirectoryGroup> groups,
        string? groupId)
    {
        if (string.IsNullOrWhiteSpace(groupId))
        {
            return null;
        }

        return groups.FirstOrDefault(group => string.Equals(group.Id, groupId, StringComparison.OrdinalIgnoreCase))
            ?.DisplayName;
    }

    private static RemediationRunRecord ToRecord(StoredRemediationRun stored)
    {
        return new RemediationRunRecord(
            stored.Id,
            stored.TemplateKey,
            stored.TemplateName,
            stored.ConnectionId,
            stored.ConnectionDisplayName,
            stored.Status,
            stored.Summary,
            stored.StartedUtc,
            stored.CompletedUtc,
            stored.LaunchedByOperatorName,
            stored.ApprovalJustification,
            stored.LaunchMode,
            stored.IncludeGroupId,
            stored.IncludeGroupName,
            stored.ExcludeGroupId,
            stored.ExcludeGroupName,
            stored.PolicyId,
            stored.PolicyState,
            stored.AlreadyExists,
            stored.Logs.ToArray());
    }

    private static string SummarizeEndpointCoreProtectionSnapshot(
        IntuneEndpointAutomationClient.EndpointCoreProtectionConfigurationSnapshot snapshot)
    {
        return $"DisplayName={snapshot.DisplayName}; RealTime={snapshot.DefenderRequireRealTimeMonitoring}; Behavior={snapshot.DefenderRequireBehaviorMonitoring}; NetworkInspection={snapshot.DefenderRequireNetworkInspectionSystem}; ScanDownloads={snapshot.DefenderScanDownloads}; ScanArchiveFiles={snapshot.DefenderScanArchiveFiles}; ScanIncomingMail={snapshot.DefenderScanIncomingMail}; ScanRemovableDrivesFull={snapshot.DefenderScanRemovableDrivesDuringFullScan}; CloudProtection={snapshot.DefenderRequireCloudProtection}; CloudBlockLevel={snapshot.DefenderCloudBlockLevel}; SampleSubmission={snapshot.DefenderPromptForSampleSubmission}; FileActivity={snapshot.DefenderMonitorFileActivity}; PuaAction={snapshot.DefenderPotentiallyUnwantedAppAction}; PuaSetting={snapshot.DefenderPotentiallyUnwantedAppActionSetting}";
    }

    private static string SummarizeEndpointCoreProtectionHardeningSnapshot(
        IntuneEndpointAutomationClient.EndpointCoreProtectionHardeningConfigurationSnapshot snapshot)
    {
        return $"DisplayName={snapshot.DisplayName}; TamperProtection={snapshot.WindowsDefenderTamperProtection}; NetworkProtection={snapshot.DefenderNetworkProtectionType}";
    }

    private static string SummarizeEndpointBitLockerSnapshot(
        IntuneEndpointAutomationClient.EndpointBitLockerConfigurationSnapshot snapshot)
    {
        return $"DisplayName={snapshot.DisplayName}; EncryptDevice={snapshot.BitLockerEncryptDevice}; EncryptionMethod={snapshot.EncryptionMethod}; StartupAuthenticationRequired={snapshot.StartupAuthenticationRequired}; AllowWithoutTpm={snapshot.StartupAuthenticationBlockWithoutTpmChip}; TpmUsage={snapshot.StartupAuthenticationTpmUsage}; TpmPinUsage={snapshot.StartupAuthenticationTpmPinUsage}; TpmKeyUsage={snapshot.StartupAuthenticationTpmKeyUsage}; TpmPinAndKeyUsage={snapshot.StartupAuthenticationTpmPinAndKeyUsage}; MinimumPinLength={snapshot.MinimumPinLength}";
    }

    private static string SummarizeEndpointCredentialAndElevationSnapshot(
        IntuneEndpointAutomationClient.EndpointCredentialAndElevationConfigurationSnapshot snapshot)
    {
        return $"DisplayName={snapshot.DisplayName}; Vbs={snapshot.EnableVirtualizationBasedSecurity}; CredentialGuard={snapshot.CredentialGuardConfiguration}; NoCredentialStorage={snapshot.BlockCredentialStorageForNetworkAuthentication}; AdminApprovalMode={snapshot.RunAllAdministratorsInAdminApprovalMode}; StandardUserElevation={snapshot.ElevationPromptForStandardUsers}; SecureDesktop={snapshot.SwitchToSecureDesktopForElevation}; OnlyElevateSigned={snapshot.OnlyElevateSignedAndValidatedExecutables}; LsaProtectedProcess={snapshot.ConfigureLsaProtectedProcess}; SafeDllSearchMode={snapshot.SafeDllSearchMode}; EnumerateAdminsOnElevation={snapshot.EnumerateAdministratorsOnElevation}; UacRestrictionsLocalAccountsNetworkLogon={snapshot.ApplyUacRestrictionsToLocalAccountsOnNetworkLogon}; AlwaysInstallElevated={snapshot.AlwaysInstallElevated}; WDigest={snapshot.WDigestAuthentication}";
    }

    private static string SummarizeEndpointRemoteAccessAndNetworkHardeningSnapshot(
        IntuneEndpointAutomationClient.EndpointRemoteAccessAndNetworkHardeningConfigurationSnapshot snapshot)
    {
        return $"DisplayName={snapshot.DisplayName}; NoNetworkBridge={snapshot.ProhibitInstallationAndConfigurationOfNetworkBridge}; ElevateForNetworkLocation={snapshot.RequireDomainUsersToElevateWhenSettingNetworkLocation}; NoIcs={snapshot.ProhibitInternetConnectionSharing}; OfferRemoteAssistance={snapshot.ConfigureOfferRemoteAssistance}; SolicitedRemoteAssistance={snapshot.ConfigureSolicitedRemoteAssistance}; WinRmClientBasic={snapshot.AllowBasicAuthenticationWinRmClient}; WinRmServiceBasic={snapshot.AllowBasicAuthenticationWinRmService}; NoAutoPlayNonVolume={snapshot.DisallowAutoplayForNonVolumeDevices}; NoAutoPlayAllDrives={snapshot.TurnOffAutoPlayAllDrives}; AutoRunDefault={snapshot.SetDefaultAutoRunBehavior}; NoSmbV1Client={snapshot.ConfigureSmbV1ClientDriver}; NoSmbV1Server={snapshot.ConfigureSmbV1Server}; NoIpv6SourceRouting={snapshot.Ipv6SourceRoutingProtectionLevel}; NoIpSourceRouting={snapshot.IpSourceRoutingProtectionLevel}; RdpSecurityLayer={snapshot.RemoteDesktopSecurityLayer}";
    }

    private static string SummarizeEndpointFirewallAndSmartScreenSnapshot(
        IntuneEndpointAutomationClient.EndpointFirewallAndSmartScreenConfigurationSnapshot snapshot)
    {
        return $"DisplayName={snapshot.DisplayName}; DomainFirewall={snapshot.DomainFirewallEnabled}; DomainIncomingBlocked={snapshot.DomainIncomingTrafficBlocked}; DomainNotificationsBlocked={snapshot.DomainInboundNotificationsBlocked}; PrivateFirewall={snapshot.PrivateFirewallEnabled}; PrivateIncomingBlocked={snapshot.PrivateIncomingTrafficBlocked}; PrivateNotificationsBlocked={snapshot.PrivateInboundNotificationsBlocked}; PublicFirewall={snapshot.PublicFirewallEnabled}; PublicIncomingBlocked={snapshot.PublicIncomingTrafficBlocked}; PublicNotificationsBlocked={snapshot.PublicInboundNotificationsBlocked}; PublicPolicyRulesMerged={snapshot.PublicPolicyRulesFromGroupPolicyMerged}; PublicConnectionRulesMerged={snapshot.PublicConnectionSecurityRulesFromGroupPolicyMerged}; SmartScreenShell={snapshot.SmartScreenEnableInShell}; SmartScreenFileOverrideBlocked={snapshot.SmartScreenBlockOverrideForFiles}";
    }

    private static string SummarizeEndpointEdgeSmartScreenSnapshot(
        IntuneEndpointAutomationClient.EndpointEdgeSmartScreenConfigurationSnapshot snapshot)
    {
        return $"DisplayName={snapshot.DisplayName}; IngestionType={snapshot.PolicyConfigurationIngestionType}; EdgeSmartScreen={snapshot.SmartScreenEnabled?.ToString() ?? "Missing"}; PreventBypassSites={snapshot.PreventBypassForSites?.ToString() ?? "Missing"}; ForceChecksDownloads={snapshot.ForceChecksOnDownloads?.ToString() ?? "Missing"}; BlockPua={snapshot.BlockPotentiallyUnwantedApps?.ToString() ?? "Missing"}";
    }

    private static string SummarizeEndpointBrowserHardeningSnapshot(
        IntuneEndpointAutomationClient.EndpointBrowserHardeningConfigurationSnapshot snapshot)
    {
        return $"DisplayName={snapshot.DisplayName}; IngestionType={snapshot.PolicyConfigurationIngestionType}; BackgroundApps={snapshot.ContinueRunningBackgroundApps?.ToString() ?? "Missing"}; AutoFillAddresses={snapshot.EnableAutoFillAddresses?.ToString() ?? "Missing"}; AutoFillCreditCards={snapshot.EnableAutoFillCreditCards?.ToString() ?? "Missing"}; PasswordManager={snapshot.EnablePasswordManager?.ToString() ?? "Missing"}; ThirdPartyCookiesBlocked={snapshot.BlockThirdPartyCookies?.ToString() ?? "Missing"}";
    }

    private static string SummarizeEndpointExploitProtectionSnapshot(
        IntuneEndpointAutomationClient.EndpointExploitProtectionConfigurationSnapshot snapshot)
    {
        return $"DisplayName={snapshot.DisplayName}; XmlFileName={snapshot.DefenderExploitProtectionXmlFileName}; BlockOverride={snapshot.DefenderSecurityCenterBlockExploitProtectionOverride}; XmlPresent={!string.IsNullOrWhiteSpace(snapshot.DefenderExploitProtectionXml)}";
    }

    private static string SummarizeEntraIdentityHygieneFinding(
        DirectoryGraphClient.EntraIdentityHygieneFinding finding)
    {
        var evidenceSummary = finding.Evidence.Count == 0
            ? "None"
            : string.Join(" | ", finding.Evidence.Select(NormalizeSummary));

        return $"ControlId={finding.ControlId}; Status={finding.Status}; Title={finding.ControlTitle}; Summary={NormalizeSummary(finding.Summary)}; Evidence={evidenceSummary}";
    }

    private static string EnhanceEntraDailyUseFailure(string failure)
    {
        var normalizedFailure = NormalizeSummary(failure);

        return normalizedFailure.Contains("Authorization_RequestDenied", StringComparison.OrdinalIgnoreCase)
               || normalizedFailure.Contains("Insufficient privileges", StringComparison.OrdinalIgnoreCase)
            ? $"{normalizedFailure} {EntraDailyUsePermissionsHint}"
            : normalizedFailure;
    }

    private static string EnhanceEntraLowImpactAppConsentFailure(string failure)
    {
        var normalizedFailure = NormalizeSummary(failure);

        return normalizedFailure.Contains("Authorization_RequestDenied", StringComparison.OrdinalIgnoreCase)
               || normalizedFailure.Contains("Insufficient privileges", StringComparison.OrdinalIgnoreCase)
            ? $"{normalizedFailure} {EntraLowImpactAppConsentPermissionsHint}"
            : normalizedFailure;
    }

    private static string SummarizeAuthorizationPolicy(
        DirectoryGraphClient.GraphAuthorizationPolicy policy)
    {
        var consentAssignments = policy.PermissionGrantPoliciesAssigned.Count == 0
            ? "None"
            : string.Join(" | ", policy.PermissionGrantPoliciesAssigned.Select(NormalizeSummary));

        return $"AllowedToUseSSPR={policy.AllowedToUseSspr}; AllowUserConsentForRiskyApps={policy.AllowUserConsentForRiskyApps}; AllowedToCreateSecurityGroups={policy.AllowedToCreateSecurityGroups}; PermissionGrantPoliciesAssigned={consentAssignments}";
    }

    private static string SummarizeAdminConsentRequestPolicy(
        DirectoryGraphClient.GraphAdminConsentRequestPolicy policy)
    {
        var reviewers = policy.ReviewerQueries.Count == 0
            ? "None"
            : string.Join(" | ", policy.ReviewerQueries.Select(NormalizeSummary));

        return $"IsEnabled={policy.IsEnabled}; NotifyReviewers={policy.NotifyReviewers}; RemindersEnabled={policy.RemindersEnabled}; RequestDurationInDays={policy.RequestDurationInDays?.ToString() ?? "Missing"}; Reviewers={reviewers}";
    }

    private static string SummarizeDomainPasswordPolicy(
        DirectoryGraphClient.GraphDomainPasswordPolicy domain)
    {
        return $"Domain={domain.Id}; IsDefault={domain.IsDefault}; IsInitial={domain.IsInitial}; PasswordValidityPeriodInDays={domain.PasswordValidityPeriodInDays?.ToString() ?? "Missing"}; PasswordNotificationWindowInDays={domain.PasswordNotificationWindowInDays?.ToString() ?? "Missing"}";
    }

    private static string SummarizeManagedWindowsDeviceHealthAssessment(
        IntuneEndpointAutomationClient.ManagedWindowsDeviceHealthAssessment assessment)
    {
        var lastSync = assessment.LastSyncDateTime?.ToString("O") ?? "Missing";
        var lastReported = assessment.ProtectionState?.LastReportedDateTime?.ToString("O") ?? "Missing";
        var issueSummary = assessment.Issues.Count == 0
            ? "Healthy"
            : string.Join(" | ", assessment.Issues.Select(NormalizeSummary));

        return $"Device={assessment.DeviceName}; UserId={assessment.UserId}; AzureAdDeviceId={assessment.AzureAdDeviceId}; LastSync={lastSync}; LastReported={lastReported}; Issues={issueSummary}";
    }

    private static string SummarizeEndpointEdrOnboardingPolicyAssessment(
        IntuneEndpointAutomationClient.EndpointEdrOnboardingPolicyAssessment assessment)
    {
        var assignmentSummary = assessment.Assignments.Count == 0
            ? "None"
            : string.Join(
                " | ",
                assessment.Assignments.Select(assignment =>
                    $"{assignment.TargetODataType}:{(string.IsNullOrWhiteSpace(assignment.EntraObjectId) ? "NoObjectId" : assignment.EntraObjectId)}"));

        return $"Name={assessment.Name}; Assigned={assessment.IsAssigned}; TargetsPilotScope={assessment.TargetsPilotScope}; BroadAssignment={assessment.HasBroadAssignment}; TemplateFamily={assessment.TemplateFamily}; Assignments={assignmentSummary}";
    }

    private static string SummarizeEndpointWslPluginReadinessAssessment(
        IntuneEndpointAutomationClient.EndpointWslPluginReadinessAssessment assessment)
    {
        return $"ReadyForHostValidation={assessment.ReadyForHostValidation}; Summary={NormalizeSummary(assessment.Summary)}";
    }

    private static string SummarizeManagedWindowsBitLockerAssessment(
        IntuneEndpointAutomationClient.ManagedWindowsBitLockerAssessment assessment)
    {
        var lastSync = assessment.LastSyncDateTime?.ToString("O") ?? "Missing";
        var issueSummary = assessment.Issues.Count == 0
            ? "Healthy"
            : string.Join(" | ", assessment.Issues.Select(NormalizeSummary));
        var encryptionSummary = assessment.EncryptionState is null
            ? "NoEncryptionTelemetry"
            : $"EncryptionState={assessment.EncryptionState.EncryptionState}; Readiness={assessment.EncryptionState.EncryptionReadinessState}; PolicyState={assessment.EncryptionState.EncryptionPolicySettingState}; AdvancedState={assessment.EncryptionState.AdvancedBitLockerStates}; Policies={(assessment.EncryptionState.PolicyNames.Count == 0 ? "none" : string.Join(", ", assessment.EncryptionState.PolicyNames))}";

        return $"Device={assessment.DeviceName}; UserId={assessment.UserId}; AzureAdDeviceId={assessment.AzureAdDeviceId}; LastSync={lastSync}; Encryption={encryptionSummary}; Issues={issueSummary}";
    }

    private static string SummarizeBrowserAndAdobePolicySurfaceFinding(
        IntuneEndpointAutomationClient.EndpointBrowserAndAdobePolicySurfaceFinding finding)
    {
        var evidence = finding.Evidence.Count == 0
            ? "none"
            : string.Join(" | ", finding.Evidence.Select(NormalizeSummary));

        return $"Surface={finding.SurfaceName}; Ready={finding.IsReady}; Summary={NormalizeSummary(finding.Summary)}; Evidence={evidence}";
    }

    private static string SummarizeEndpointAttackSurfaceReductionSnapshot(
        IntuneEndpointAutomationClient.EndpointAttackSurfaceReductionConfigurationSnapshot snapshot)
    {
        return $"DisplayName={snapshot.DisplayName}; OfficeChildProcess={snapshot.DefenderOfficeAppsLaunchChildProcessType}/{snapshot.DefenderOfficeAppsLaunchChildProcess}; OfficeExecutableContent={snapshot.DefenderOfficeAppsExecutableContentCreationOrLaunchType}/{snapshot.DefenderOfficeAppsExecutableContentCreationOrLaunch}; OfficeInjection={snapshot.DefenderOfficeAppsOtherProcessInjectionType}/{snapshot.DefenderOfficeAppsOtherProcessInjection}; OutlookChildProcess={snapshot.DefenderOfficeCommunicationAppsLaunchChildProcess}; Win32Imports={snapshot.DefenderOfficeMacroCodeAllowWin32ImportsType}/{snapshot.DefenderOfficeMacroCodeAllowWin32Imports}; ObfuscatedScripts={snapshot.DefenderScriptObfuscatedMacroCodeType}/{snapshot.DefenderScriptObfuscatedMacroCode}; DownloadedPayload={snapshot.DefenderScriptDownloadedPayloadExecutionType}/{snapshot.DefenderScriptDownloadedPayloadExecution}; EmailExecution={snapshot.DefenderEmailContentExecutionType}/{snapshot.DefenderEmailContentExecution}; CredentialStealing={snapshot.DefenderPreventCredentialStealingType}; PSExecOrWmi={snapshot.DefenderProcessCreationType}/{snapshot.DefenderProcessCreation}; UntrustedUsb={snapshot.DefenderUntrustedUSBProcessType}/{snapshot.DefenderUntrustedUSBProcess}; UntrustedExecutable={snapshot.DefenderUntrustedExecutableType}/{snapshot.DefenderUntrustedExecutable}; Ransomware={snapshot.DefenderAdvancedRansomewareProtectionType}; GuardMyFolders={snapshot.DefenderGuardMyFoldersType}; WmiPersistence={snapshot.DefenderBlockPersistenceThroughWmiType}";
    }

    private static string SummarizeEndpointOsSecuritySnapshot(
        IntuneEndpointAutomationClient.EndpointOsSecurityConfigurationSnapshot snapshot)
    {
        var inactivity = snapshot.LocalSecurityOptionsMachineInactivityLimitInMinutes != 0
            ? snapshot.LocalSecurityOptionsMachineInactivityLimitInMinutes
            : snapshot.LocalSecurityOptionsMachineInactivityLimit;

        return $"DisplayName={snapshot.DisplayName}; DisableAdministrator={snapshot.LocalSecurityOptionsDisableAdministratorAccount}; DisableGuest={snapshot.LocalSecurityOptionsDisableGuestAccount}; InactivityLimitMinutes={inactivity}; BlankPasswordRemoteLogonBlocked={snapshot.LocalSecurityOptionsBlockRemoteLogonWithBlankPassword}; NoLmHash={snapshot.LocalSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange}; RestrictAnonymousPipesShares={snapshot.LocalSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares}; NoAnonymousSam={snapshot.LocalSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts}; AnonymousSamAndSharesAllowed={snapshot.LocalSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares}; NoPlaintextSmbPasswords={snapshot.LocalSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers}; RequireSmbClientSigning={snapshot.LocalSecurityOptionsClientDigitallySignCommunicationsAlways}; LanManagerLevel={snapshot.LanManagerAuthenticationLevel}";
    }

    private static string SummarizeEndpointAssignmentTargets(
        IReadOnlyList<IntuneEndpointAutomationClient.EndpointAssignmentTargetSnapshot> assignments)
    {
        if (assignments.Count == 0)
        {
            return "No assignments were returned.";
        }

        return string.Join(
            "; ",
            assignments.Select(assignment =>
            {
                var targetKind = assignment.IsExcludeGroup
                    ? "ExcludeGroup"
                    : assignment.IsIncludeGroup
                        ? "IncludeGroup"
                        : assignment.TargetType;
                return $"{targetKind}={assignment.TargetId}";
            }));
    }

    private static string SummarizeTeamsMeetingPolicy(TeamsMeetingPolicyAutomationClient.TeamsMeetingPolicySnapshot snapshot)
    {
        return $"Identity={snapshot.Identity}; AutoAdmittedUsers={snapshot.AutoAdmittedUsers}; Presenters={snapshot.DesignatedPresenterRoleMode}; AnonymousJoin={snapshot.AllowAnonymousUsersToJoinMeeting}; AnonymousStart={snapshot.AllowAnonymousUsersToStartMeeting}; PSTNBypassLobby={snapshot.AllowPstnUsersToBypassLobby}; ExternalControl={snapshot.AllowExternalParticipantGiveRequestControl}";
    }

    private static string SummarizeDefenderForOfficeGlobalProtection(
        DefenderForOfficeAutomationClient.DefenderForOfficeGlobalProtectionSnapshot snapshot)
    {
        return $"SafeAttachmentsForSharePointOneDriveTeams={snapshot.EnableAtpForSpoTeamsOdb}; SafeDocs={snapshot.EnableSafeDocs?.ToString() ?? "Unavailable"}; AllowSafeDocsOpen={snapshot.AllowSafeDocsOpen?.ToString() ?? "Unavailable"}";
    }

    private static string SummarizeDefenderForOfficeSafeLinks(
        DefenderForOfficeAutomationClient.DefenderForOfficeSafeLinksSnapshot snapshot)
    {
        return $"PolicyExists={snapshot.PolicyExists}; RuleExists={snapshot.RuleExists}; Email={snapshot.EnableSafeLinksForEmail}; Teams={snapshot.EnableSafeLinksForTeams}; Office={snapshot.EnableSafeLinksForOffice}; TrackClicks={snapshot.TrackClicks}; AllowClickThrough={snapshot.AllowClickThrough}; InternalSenders={snapshot.EnableForInternalSenders}; DomainCount={snapshot.RecipientDomains?.Count ?? 0}";
    }

    private static string SummarizeDefenderForOfficeSafeAttachments(
        DefenderForOfficeAutomationClient.DefenderForOfficeSafeAttachmentsSnapshot snapshot)
    {
        return $"PolicyExists={snapshot.PolicyExists}; RuleExists={snapshot.RuleExists}; Enabled={snapshot.Enable}; Action={snapshot.Action}; Redirect={snapshot.Redirect}; DomainCount={snapshot.RecipientDomains?.Count ?? 0}";
    }

    private static string SummarizeDefenderForOfficeAntiPhish(
        DefenderForOfficeAutomationClient.DefenderForOfficeAntiPhishSnapshot snapshot)
    {
        return $"PolicyExists={snapshot.PolicyExists}; RuleExists={snapshot.RuleExists}; RuleState={snapshot.RuleState}; MailboxIntelligence={snapshot.EnableMailboxIntelligence}; MailboxIntelligenceAction={snapshot.MailboxIntelligenceProtectionAction}; DomainProtection={snapshot.EnableTargetedDomainsProtection}; DomainAction={snapshot.TargetedDomainProtectionAction}; UserProtection={snapshot.EnableTargetedUserProtection}; UserAction={snapshot.TargetedUserProtectionAction}; PhishThreshold={snapshot.PhishThresholdLevel}; DomainCount={snapshot.TargetedDomains?.Count ?? 0}; ProtectedUserCount={snapshot.TargetedUsers?.Count ?? 0}";
    }

    private static string SummarizeDefenderForOfficeAntiMalware(
        DefenderForOfficeAutomationClient.DefenderForOfficeAntiMalwareSnapshot snapshot)
    {
        return $"PolicyExists={snapshot.PolicyExists}; RuleExists={snapshot.RuleExists}; RuleState={snapshot.RuleState}; FileFilter={snapshot.EnableFileFilter}; FileTypeAction={snapshot.FileTypeAction}; ZapEnabled={snapshot.ZapEnabled}; QuarantineTag={snapshot.QuarantineTag}; DomainCount={snapshot.RecipientDomains?.Count ?? 0}";
    }

    private static string SummarizeExchangeOrganizationSnapshot(
        DefenderForOfficeAutomationClient.DefenderForOfficeExchangeOrganizationSnapshot snapshot)
    {
        return $"AuditDisabled={snapshot.AuditDisabled}; MailTipsAllTipsEnabled={snapshot.MailTipsAllTipsEnabled}; AppsForOfficeEnabled={snapshot.AppsForOfficeEnabled}; OAuth2ClientProfileEnabled={snapshot.OAuth2ClientProfileEnabled}";
    }

    private static string SummarizeExchangeOwaMailboxPolicySnapshot(
        DefenderForOfficeAutomationClient.DefenderForOfficeExchangeOwaMailboxPolicySnapshot snapshot)
    {
        return $"PolicyExists={snapshot.PolicyExists}; Identity={snapshot.Identity}; IsDefault={snapshot.IsDefault}; AdditionalStorageProvidersAvailable={snapshot.AdditionalStorageProvidersAvailable}";
    }

    private static string SummarizeExchangeSharingPolicySnapshot(
        DefenderForOfficeAutomationClient.DefenderForOfficeExchangeSharingPolicySnapshot snapshot)
    {
        return $"PolicyExists={snapshot.PolicyExists}; Identity={snapshot.Identity}; DomainCount={snapshot.Domains.Count}; AnonymousCalendarSharing={snapshot.HasAnonymousCalendarSharing}";
    }

    private static string SummarizeDefenderForOfficeInboundSpam(
        DefenderForOfficeAutomationClient.DefenderForOfficeInboundSpamSnapshot snapshot)
    {
        return $"PolicyExists={snapshot.PolicyExists}; RuleExists={snapshot.RuleExists}; Spam={snapshot.SpamAction}; HighConfidenceSpam={snapshot.HighConfidenceSpamAction}; Bulk={snapshot.BulkSpamAction}; BulkThreshold={snapshot.BulkThreshold}; PhishZap={snapshot.PhishZapEnabled}; SpamZap={snapshot.SpamZapEnabled}; DomainCount={snapshot.RecipientDomains?.Count ?? 0}; AllowedSenderDomainCount={snapshot.AllowedSenderDomains?.Count ?? 0}";
    }

    private static string SummarizeDefenderForOfficeOutboundSpam(
        DefenderForOfficeAutomationClient.DefenderForOfficeOutboundSpamSnapshot snapshot)
    {
        return $"PolicyExists={snapshot.PolicyExists}; RuleExists={snapshot.RuleExists}; AutoForwarding={snapshot.AutoForwardingMode}; NotifyOutboundSpam={snapshot.NotifyOutboundSpam}; ExternalPerHour={snapshot.RecipientLimitExternalPerHour}; InternalPerHour={snapshot.RecipientLimitInternalPerHour}; PerDay={snapshot.RecipientLimitPerDay}; ThresholdAction={snapshot.ActionWhenThresholdReached}; SenderDomainCount={snapshot.SenderDomains?.Count ?? 0}";
    }

    private static string SummarizeDefenderForOfficeConnectionFilter(
        DefenderForOfficeAutomationClient.DefenderForOfficeConnectionFilterSnapshot snapshot)
    {
        return $"PolicyExists={snapshot.PolicyExists}; Name={snapshot.PolicyName}; IpAllowListCount={snapshot.IpAllowList?.Count ?? 0}; ReadbackError={(string.IsNullOrWhiteSpace(snapshot.ReadbackError) ? "None" : snapshot.ReadbackError)}";
    }

    private static string NormalizeSummary(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "No remediation summary was recorded.";
        }

        var normalized = value.Trim().ReplaceLineEndings(" ");
        return normalized.Length <= 320 ? normalized : normalized[..320];
    }

    private static string ResolveConditionalAccessState(RemediationLaunchMode launchMode)
    {
        return launchMode switch
        {
            RemediationLaunchMode.ReportOnly => "enabledForReportingButNotEnforced",
            RemediationLaunchMode.Enabled => "enabled",
            _ => throw new InvalidOperationException("Direct-apply mode does not map to a Conditional Access policy state.")
        };
    }

    private static bool ConditionalAccessStateMatches(string actualState, string desiredState)
    {
        return string.Equals(actualState?.Trim(), desiredState?.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    private static string DescribeLaunchMode(RemediationLaunchMode launchMode)
    {
        return launchMode switch
        {
            RemediationLaunchMode.ReportOnly => "Report-only",
            RemediationLaunchMode.Enabled => "Enabled",
            _ => "Direct apply"
        };
    }

    private sealed record TemplateExecutionRequest(
        Guid ConnectionId,
        Guid OwnerOperatorId,
        Guid LaunchedByOperatorId,
        string LaunchedByOperatorName,
        string ApprovalJustification,
        RemediationLaunchMode LaunchMode,
        string IncludeGroupId,
        string? ExcludeGroupId);
}
