namespace Securityzator.Application.Jobs;

public sealed record EnqueueRequireMfaAdminsJobRequest(
    Guid ConnectionId,
    Guid OwnerOperatorId,
    Guid RequestedByOperatorId,
    string RequestedByOperatorName,
    string ApprovalJustification,
    string IncludeGroupId,
    string? ExcludeGroupId);
