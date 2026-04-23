using Securityzator.Application.Remediations;

namespace Securityzator.Application.Jobs;

public sealed record RemediationJobWorkItem(
    Guid Id,
    string TemplateKey,
    Guid ConnectionId,
    Guid OwnerOperatorId,
    Guid RequestedByOperatorId,
    string RequestedByOperatorName,
    string ApprovalJustification,
    RemediationLaunchMode LaunchMode,
    string ConnectionDisplayName,
    string IncludeGroupId,
    string? ExcludeGroupId,
    int AttemptCount,
    int MaxAttempts);
