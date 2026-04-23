namespace Securityzator.Application.Jobs;

public sealed record EnqueueRequireMfaAllUsersJobRequest(
    Guid ConnectionId,
    Guid OwnerOperatorId,
    Guid RequestedByOperatorId,
    string RequestedByOperatorName,
    string ApprovalJustification,
    string? ExcludeGroupId);
