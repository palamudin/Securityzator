namespace Securityzator.Application.Remediations;

public interface IRemediationService
{
    Task<RemediationExecutionOutcome> ExecuteQueueableTemplateAsync(
        QueueableRemediationTemplateRequest request,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<DirectoryGroupEntry>> ListGroupsAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<RemediationRunRecord>> ListRunsAsync(
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default);

    Task<RemediationExecutionOutcome> ExecuteBlockLegacyAuthenticationAsync(
        BlockLegacyAuthenticationRequest request,
        CancellationToken cancellationToken = default);

    Task<RemediationExecutionOutcome> ExecuteRequireMfaAdminsAsync(
        RequireMfaAdminsRequest request,
        CancellationToken cancellationToken = default);

    Task<RemediationExecutionOutcome> ExecuteRequireMfaAllUsersAsync(
        RequireMfaAllUsersRequest request,
        CancellationToken cancellationToken = default);

    Task<RemediationExecutionOutcome> ExecuteRequirePhishingResistantMfaAdminsAsync(
        RequirePhishingResistantMfaAdminsRequest request,
        CancellationToken cancellationToken = default);
}
