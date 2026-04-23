namespace Securityzator.Application.Jobs;

public sealed record EnqueueRequirePhishingResistantMfaAdminsJobRequest(
    Guid ConnectionId,
    Guid OwnerOperatorId,
    Guid RequestedByOperatorId,
    string RequestedByOperatorName,
    string ApprovalJustification,
    string IncludeGroupId,
    string? ExcludeGroupId);
