namespace Securityzator.Application.Jobs;

public interface IRemediationJobService
{
    Task<RemediationJobRecord> EnqueueQueueableTemplateAsync(
        EnqueueQueueableTemplateJobRequest request,
        CancellationToken cancellationToken = default);

    Task<RemediationJobRecord> EnqueueBlockLegacyAuthenticationAsync(
        EnqueueBlockLegacyAuthenticationJobRequest request,
        CancellationToken cancellationToken = default);

    Task<RemediationJobRecord> EnqueueRequireMfaAdminsAsync(
        EnqueueRequireMfaAdminsJobRequest request,
        CancellationToken cancellationToken = default);

    Task<RemediationJobRecord> EnqueueRequireMfaAllUsersAsync(
        EnqueueRequireMfaAllUsersJobRequest request,
        CancellationToken cancellationToken = default);

    Task<RemediationJobRecord> EnqueueRequirePhishingResistantMfaAdminsAsync(
        EnqueueRequirePhishingResistantMfaAdminsJobRequest request,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<RemediationJobRecord>> ListForOperatorAsync(
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default);

    Task<RemediationJobWorkItem?> TryClaimNextAsync(
        string workerName,
        CancellationToken cancellationToken = default);

    Task<RemediationJobRecord?> MarkSucceededAsync(
        Guid jobId,
        Guid remediationRunId,
        string summary,
        string? policyId,
        string? policyState,
        CancellationToken cancellationToken = default);

    Task<RemediationJobRecord?> MarkFailedAsync(
        Guid jobId,
        string errorMessage,
        CancellationToken cancellationToken = default);
}
