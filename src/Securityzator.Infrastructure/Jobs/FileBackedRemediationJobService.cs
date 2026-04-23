using Securityzator.Application.Jobs;
using Securityzator.Application.Remediations;
using Securityzator.Infrastructure.Storage;

namespace Securityzator.Infrastructure.Jobs;

public sealed class FileBackedRemediationJobService : IRemediationJobService
{
    private const string BlockLegacyAuthTemplateKey = "block-legacy-auth";
    private const string BlockLegacyAuthTemplateName = "Block legacy authentication";
    private const string RequireMfaAdminsTemplateKey = "require-mfa-admins";
    private const string RequireMfaAdminsTemplateName = "Require MFA for privileged admins";
    private const string RequireMfaAllUsersTemplateKey = "mfa-all-users";
    private const string RequireMfaAllUsersTemplateName = "Require MFA for all users";
    private const string EntraRiskPoliciesTemplateKey = "entra-risk-policies";
    private const string EntraRiskPoliciesTemplateName = "Enable Entra risk policies";
    private const string EntraIdentityHygieneTemplateKey = "entra-identity-hygiene-baseline";
    private const string EntraIdentityHygieneTemplateName = "Entra admin and consent hygiene";
    private const string EntraDailyUseHardeningTemplateKey = "entra-daily-use-hardening";
    private const string EntraDailyUseHardeningTemplateName = "Entra daily-use consent and password hardening";
    private const string RequireMfaGuestAccessTemplateKey = "require-mfa-guest-access";
    private const string RequireMfaGuestAccessTemplateName = "Require MFA for guest access";
    private const string RequireMfaAdminPortalsTemplateKey = "require-mfa-admin-portals";
    private const string RequireMfaAdminPortalsTemplateName = "Require MFA for Microsoft admin portals";
    private const string RequireMfaAzureManagementTemplateKey = "require-mfa-azure-management";
    private const string RequireMfaAzureManagementTemplateName = "Require MFA for Azure management";
    private const string SecureSecurityInfoRegistrationTemplateKey = "secure-security-info-registration";
    private const string SecureSecurityInfoRegistrationTemplateName = "Secure security info registration";
    private const string RequireMfaRiskySignInsTemplateKey = "require-mfa-risky-sign-ins";
    private const string RequireMfaRiskySignInsTemplateName = "Require MFA when risky sign-ins are detected";
    private const string RequirePasswordChangeHighRiskUsersTemplateKey = "require-password-change-high-risk-users";
    private const string RequirePasswordChangeHighRiskUsersTemplateName = "Require password change for high-risk users";
    private const string RequirePhishingResistantMfaAdminsTemplateKey = "require-phishing-resistant-mfa-admins";
    private const string RequirePhishingResistantMfaAdminsTemplateName = "Require phishing-resistant MFA for privileged admins";
    private const string MdoAntiPhishingAndImpersonationTemplateKey = "mdo-anti-phishing-and-impersonation";
    private const string MdoAntiPhishingAndImpersonationTemplateName = "Defender for Office anti-phishing and impersonation";
    private const string MdoSafeLinksAndAttachmentsTemplateKey = "mdo-safe-links-and-attachments";
    private const string MdoSafeLinksAndAttachmentsTemplateName = "Defender for Office Safe Links and attachments";
    private const string MdoSpamAndForwardingTemplateKey = "mdo-spam-and-forwarding-baseline";
    private const string MdoSpamAndForwardingTemplateName = "Defender for Office spam and forwarding hardening";
    private const string ExchangeOnlineCollaborationMailboxTemplateKey = "exchange-online-collaboration-and-mailbox";
    private const string ExchangeOnlineCollaborationMailboxTemplateName = "Exchange Online collaboration and mailbox hardening";
    private const string TeamsMeetingHardeningTemplateKey = "teams-meeting-hardening";
    private const string TeamsMeetingHardeningTemplateName = "Teams meeting hardening baseline";
    private const string DefenderEndpointBitLockerTemplateKey = "defender-endpoint-bitlocker-baseline";
    private const string DefenderEndpointBitLockerTemplateName = "Defender BitLocker startup baseline";
    private const string DefenderEndpointCredentialAndElevationHardeningTemplateKey = "defender-endpoint-credential-and-elevation-hardening";
    private const string DefenderEndpointCredentialAndElevationHardeningTemplateName = "Defender credential and elevation hardening";
    private const string DefenderEndpointRemoteAccessAndNetworkHardeningTemplateKey = "defender-endpoint-remote-access-and-network-hardening";
    private const string DefenderEndpointRemoteAccessAndNetworkHardeningTemplateName = "Defender remote access and network hardening";
    private const string DefenderEndpointCoreProtectionTemplateKey = "defender-endpoint-core-protection";
    private const string DefenderEndpointCoreProtectionTemplateName = "Defender for Endpoint core protection baseline";
    private const string DefenderEndpointFirewallAndSmartScreenTemplateKey = "defender-endpoint-firewall-and-smartscreen";
    private const string DefenderEndpointFirewallAndSmartScreenTemplateName = "Defender Firewall and SmartScreen baseline";
    private const string DefenderEndpointBrowserHardeningTemplateKey = "defender-endpoint-browser-hardening";
    private const string DefenderEndpointBrowserHardeningTemplateName = "Defender browser hardening baseline";
    private const string DefenderEndpointBrowserAndAdobePolicySurfaceTemplateKey = "defender-endpoint-browser-and-adobe-policy-surface-readiness";
    private const string DefenderEndpointBrowserAndAdobePolicySurfaceTemplateName = "Defender browser and Adobe policy-surface readiness";
    private const string DefenderEndpointExploitProtectionTemplateKey = "defender-endpoint-exploit-protection";
    private const string DefenderEndpointExploitProtectionTemplateName = "Defender exploit protection baseline";
    private const string DefenderEndpointSensorAndAgentHealthTemplateKey = "defender-endpoint-sensor-and-agent-health";
    private const string DefenderEndpointSensorAndAgentHealthTemplateName = "Defender for Endpoint sensor and agent health";
    private const string DefenderEndpointOsSecurityBaselineTemplateKey = "defender-endpoint-os-security-baseline";
    private const string DefenderEndpointOsSecurityBaselineTemplateName = "Endpoint OS and platform security baseline";
    private const string DefenderEndpointAttackSurfaceReductionTemplateKey = "defender-endpoint-attack-surface-reduction";
    private const string DefenderEndpointAttackSurfaceReductionTemplateName = "Defender for Endpoint attack surface reduction";
    private static readonly TimeSpan RetryDelay = TimeSpan.FromMinutes(2);
    private readonly JsonFileSecurityzatorStateStore _stateStore;

    public FileBackedRemediationJobService(JsonFileSecurityzatorStateStore stateStore)
    {
        _stateStore = stateStore;
    }

    public Task<RemediationJobRecord> EnqueueQueueableTemplateAsync(
        EnqueueQueueableTemplateJobRequest request,
        CancellationToken cancellationToken = default)
    {
        var templateName = ResolveTemplateName(request.TemplateKey);

        return EnqueueAsync(
            request.ConnectionId,
            request.OwnerOperatorId,
            request.RequestedByOperatorId,
            request.RequestedByOperatorName,
            request.ApprovalJustification,
            request.LaunchMode,
            request.IncludeGroupId,
            request.ExcludeGroupId,
            request.TemplateKey,
            templateName,
            cancellationToken);
    }

    public Task<RemediationJobRecord> EnqueueBlockLegacyAuthenticationAsync(
        EnqueueBlockLegacyAuthenticationJobRequest request,
        CancellationToken cancellationToken = default)
    {
        return EnqueueAsync(
            request.ConnectionId,
            request.OwnerOperatorId,
            request.RequestedByOperatorId,
            request.RequestedByOperatorName,
            request.ApprovalJustification,
            RemediationLaunchMode.ReportOnly,
            request.IncludeGroupId,
            request.ExcludeGroupId,
            BlockLegacyAuthTemplateKey,
            BlockLegacyAuthTemplateName,
            cancellationToken);
    }

    public Task<RemediationJobRecord> EnqueueRequireMfaAdminsAsync(
        EnqueueRequireMfaAdminsJobRequest request,
        CancellationToken cancellationToken = default)
    {
        return EnqueueAsync(
            request.ConnectionId,
            request.OwnerOperatorId,
            request.RequestedByOperatorId,
            request.RequestedByOperatorName,
            request.ApprovalJustification,
            RemediationLaunchMode.ReportOnly,
            request.IncludeGroupId,
            request.ExcludeGroupId,
            RequireMfaAdminsTemplateKey,
            RequireMfaAdminsTemplateName,
            cancellationToken);
    }

    public Task<RemediationJobRecord> EnqueueRequireMfaAllUsersAsync(
        EnqueueRequireMfaAllUsersJobRequest request,
        CancellationToken cancellationToken = default)
    {
        return EnqueueAsync(
            request.ConnectionId,
            request.OwnerOperatorId,
            request.RequestedByOperatorId,
            request.RequestedByOperatorName,
            request.ApprovalJustification,
            RemediationLaunchMode.ReportOnly,
            string.Empty,
            request.ExcludeGroupId,
            RequireMfaAllUsersTemplateKey,
            RequireMfaAllUsersTemplateName,
            cancellationToken);
    }

    public Task<RemediationJobRecord> EnqueueRequirePhishingResistantMfaAdminsAsync(
        EnqueueRequirePhishingResistantMfaAdminsJobRequest request,
        CancellationToken cancellationToken = default)
    {
        return EnqueueAsync(
            request.ConnectionId,
            request.OwnerOperatorId,
            request.RequestedByOperatorId,
            request.RequestedByOperatorName,
            request.ApprovalJustification,
            RemediationLaunchMode.ReportOnly,
            request.IncludeGroupId,
            request.ExcludeGroupId,
            RequirePhishingResistantMfaAdminsTemplateKey,
            RequirePhishingResistantMfaAdminsTemplateName,
            cancellationToken);
    }

    private Task<RemediationJobRecord> EnqueueAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        Guid requestedByOperatorId,
        string requestedByOperatorName,
        string approvalJustification,
        RemediationLaunchMode launchMode,
        string includeGroupId,
        string? excludeGroupId,
        string templateKey,
        string templateName,
        CancellationToken cancellationToken)
    {
        return _stateStore.WriteAsync(state =>
        {
            var connection = state.Connections.FirstOrDefault(item =>
                item.Id == connectionId && item.OwnerOperatorId == ownerOperatorId);

            if (connection is null)
            {
                throw new InvalidOperationException("The selected Azure connection could not be found.");
            }

            var createdUtc = DateTimeOffset.UtcNow;
            var job = new StoredRemediationJob
            {
                Id = Guid.NewGuid(),
                TemplateKey = templateKey,
                TemplateName = templateName,
                ConnectionId = connection.Id,
                ConnectionDisplayName = connection.DisplayName,
                OwnerOperatorId = ownerOperatorId,
                RequestedByOperatorId = requestedByOperatorId,
                RequestedByOperatorName = requestedByOperatorName.Trim(),
                ApprovalJustification = Normalize(approvalJustification),
                LaunchMode = launchMode,
                Status = RemediationJobStatus.Queued,
                AttemptCount = 0,
                MaxAttempts = 3,
                CreatedUtc = createdUtc,
                NextAttemptUtc = createdUtc,
                IncludeGroupId = includeGroupId.Trim(),
                ExcludeGroupId = string.IsNullOrWhiteSpace(excludeGroupId)
                    ? null
                    : excludeGroupId.Trim(),
                Logs =
                [
                    $"Queued '{templateName}' by {requestedByOperatorName.Trim()} at {createdUtc:O}.",
                    $"Launch mode: {launchMode}.",
                    $"Approval justification: {Normalize(approvalJustification)}",
                    $"Waiting for worker pickup for connection '{connection.DisplayName}'."
                ]
            };

            state.RemediationJobs.Add(job);
            return ToRecord(job);
        }, cancellationToken);
    }

    public Task<IReadOnlyList<RemediationJobRecord>> ListForOperatorAsync(
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default)
    {
        return _stateStore.ReadAsync<IReadOnlyList<RemediationJobRecord>>(state =>
            state.RemediationJobs
                .Where(job => job.OwnerOperatorId == ownerOperatorId)
                .OrderByDescending(job => job.CreatedUtc)
                .Select(ToRecord)
                .ToArray(), cancellationToken);
    }

    public Task<RemediationJobWorkItem?> TryClaimNextAsync(
        string workerName,
        CancellationToken cancellationToken = default)
    {
        return _stateStore.WriteAsync<RemediationJobWorkItem?>(state =>
        {
            var now = DateTimeOffset.UtcNow;
            var job = state.RemediationJobs
                .Where(item =>
                    (item.Status == RemediationJobStatus.Queued || item.Status == RemediationJobStatus.RetryScheduled)
                    && (!item.NextAttemptUtc.HasValue || item.NextAttemptUtc <= now))
                .OrderBy(item => item.CreatedUtc)
                .FirstOrDefault();

            if (job is null)
            {
                return null;
            }

            job.Status = RemediationJobStatus.Running;
            job.AttemptCount += 1;
            job.StartedUtc = now;
            job.CompletedUtc = null;
            job.NextAttemptUtc = null;
            job.ClaimedByWorker = workerName.Trim();
            job.LastError = null;
            job.Logs.Add($"Claimed by worker '{job.ClaimedByWorker}' at {now:O}. Attempt {job.AttemptCount} of {job.MaxAttempts}.");

            return new RemediationJobWorkItem(
                job.Id,
                job.TemplateKey,
                job.ConnectionId,
                job.OwnerOperatorId,
                job.RequestedByOperatorId,
                job.RequestedByOperatorName,
                job.ApprovalJustification,
                job.LaunchMode,
                job.ConnectionDisplayName,
                job.IncludeGroupId,
                job.ExcludeGroupId,
                job.AttemptCount,
                job.MaxAttempts);
        }, cancellationToken);
    }

    public Task<RemediationJobRecord?> MarkSucceededAsync(
        Guid jobId,
        Guid remediationRunId,
        string summary,
        string? policyId,
        string? policyState,
        CancellationToken cancellationToken = default)
    {
        return _stateStore.WriteAsync<RemediationJobRecord?>(state =>
        {
            var job = state.RemediationJobs.FirstOrDefault(item => item.Id == jobId);

            if (job is null)
            {
                return null;
            }

            var completedUtc = DateTimeOffset.UtcNow;
            job.Status = RemediationJobStatus.Succeeded;
            job.CompletedUtc = completedUtc;
            job.NextAttemptUtc = null;
            job.LastError = null;
            job.RemediationRunId = remediationRunId;
            job.PolicyId = policyId;
            job.PolicyState = policyState;
            job.Logs.Add($"Worker completed the job successfully at {completedUtc:O}. {Normalize(summary)}");

            return ToRecord(job);
        }, cancellationToken);
    }

    public Task<RemediationJobRecord?> MarkFailedAsync(
        Guid jobId,
        string errorMessage,
        CancellationToken cancellationToken = default)
    {
        return _stateStore.WriteAsync<RemediationJobRecord?>(state =>
        {
            var job = state.RemediationJobs.FirstOrDefault(item => item.Id == jobId);

            if (job is null)
            {
                return null;
            }

            var failureMessage = Normalize(errorMessage);
            var now = DateTimeOffset.UtcNow;
            job.LastError = failureMessage;

            if (job.AttemptCount < job.MaxAttempts)
            {
                job.Status = RemediationJobStatus.RetryScheduled;
                job.NextAttemptUtc = now.Add(RetryDelay);
                job.CompletedUtc = null;
                job.Logs.Add($"Attempt {job.AttemptCount} failed at {now:O}. Retrying after {RetryDelay.TotalMinutes:0} minute(s). {failureMessage}");
            }
            else
            {
                job.Status = RemediationJobStatus.Failed;
                job.CompletedUtc = now;
                job.NextAttemptUtc = null;
                job.Logs.Add($"Job failed permanently at {now:O} after {job.AttemptCount} attempt(s). {failureMessage}");
            }

            return ToRecord(job);
        }, cancellationToken);
    }

    private static RemediationJobRecord ToRecord(StoredRemediationJob job)
    {
        return new RemediationJobRecord(
            job.Id,
            job.TemplateKey,
            job.TemplateName,
            job.ConnectionId,
            job.ConnectionDisplayName,
            job.OwnerOperatorId,
            job.RequestedByOperatorName,
            job.ApprovalJustification,
            job.LaunchMode,
            job.Status,
            job.AttemptCount,
            job.MaxAttempts,
            job.CreatedUtc,
            job.StartedUtc,
            job.CompletedUtc,
            job.NextAttemptUtc,
            job.IncludeGroupId,
            job.ExcludeGroupId,
            job.PolicyId,
            job.PolicyState,
            job.RemediationRunId,
            job.LastError,
            job.Logs.ToArray());
    }

    private static string Normalize(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "No message was recorded.";
        }

        var normalized = value.Trim().ReplaceLineEndings(" ");
        return normalized.Length <= 320 ? normalized : normalized[..320];
    }

    private static string ResolveTemplateName(string templateKey)
    {
        return templateKey.Trim() switch
        {
            BlockLegacyAuthTemplateKey => BlockLegacyAuthTemplateName,
            RequireMfaAdminsTemplateKey => RequireMfaAdminsTemplateName,
            RequireMfaAllUsersTemplateKey => RequireMfaAllUsersTemplateName,
            EntraRiskPoliciesTemplateKey => EntraRiskPoliciesTemplateName,
            EntraIdentityHygieneTemplateKey => EntraIdentityHygieneTemplateName,
            EntraDailyUseHardeningTemplateKey => EntraDailyUseHardeningTemplateName,
            RequireMfaGuestAccessTemplateKey => RequireMfaGuestAccessTemplateName,
            RequireMfaAdminPortalsTemplateKey => RequireMfaAdminPortalsTemplateName,
            RequireMfaAzureManagementTemplateKey => RequireMfaAzureManagementTemplateName,
            SecureSecurityInfoRegistrationTemplateKey => SecureSecurityInfoRegistrationTemplateName,
            RequireMfaRiskySignInsTemplateKey => RequireMfaRiskySignInsTemplateName,
            RequirePasswordChangeHighRiskUsersTemplateKey => RequirePasswordChangeHighRiskUsersTemplateName,
            RequirePhishingResistantMfaAdminsTemplateKey => RequirePhishingResistantMfaAdminsTemplateName,
            MdoAntiPhishingAndImpersonationTemplateKey => MdoAntiPhishingAndImpersonationTemplateName,
            MdoSafeLinksAndAttachmentsTemplateKey => MdoSafeLinksAndAttachmentsTemplateName,
            MdoSpamAndForwardingTemplateKey => MdoSpamAndForwardingTemplateName,
            ExchangeOnlineCollaborationMailboxTemplateKey => ExchangeOnlineCollaborationMailboxTemplateName,
            TeamsMeetingHardeningTemplateKey => TeamsMeetingHardeningTemplateName,
            DefenderEndpointBitLockerTemplateKey => DefenderEndpointBitLockerTemplateName,
            DefenderEndpointCredentialAndElevationHardeningTemplateKey => DefenderEndpointCredentialAndElevationHardeningTemplateName,
            DefenderEndpointRemoteAccessAndNetworkHardeningTemplateKey => DefenderEndpointRemoteAccessAndNetworkHardeningTemplateName,
            DefenderEndpointCoreProtectionTemplateKey => DefenderEndpointCoreProtectionTemplateName,
            DefenderEndpointFirewallAndSmartScreenTemplateKey => DefenderEndpointFirewallAndSmartScreenTemplateName,
            DefenderEndpointBrowserHardeningTemplateKey => DefenderEndpointBrowserHardeningTemplateName,
            DefenderEndpointBrowserAndAdobePolicySurfaceTemplateKey => DefenderEndpointBrowserAndAdobePolicySurfaceTemplateName,
            DefenderEndpointExploitProtectionTemplateKey => DefenderEndpointExploitProtectionTemplateName,
            DefenderEndpointSensorAndAgentHealthTemplateKey => DefenderEndpointSensorAndAgentHealthTemplateName,
            DefenderEndpointOsSecurityBaselineTemplateKey => DefenderEndpointOsSecurityBaselineTemplateName,
            DefenderEndpointAttackSurfaceReductionTemplateKey => DefenderEndpointAttackSurfaceReductionTemplateName,
            _ => throw new InvalidOperationException($"Unsupported template key '{templateKey}'.")
        };
    }
}
