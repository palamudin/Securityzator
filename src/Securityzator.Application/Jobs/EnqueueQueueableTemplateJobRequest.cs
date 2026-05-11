using Securityzator.Application.Remediations;

namespace Securityzator.Application.Jobs;

public sealed record EnqueueQueueableTemplateJobRequest(
    Guid ConnectionId,
    Guid OwnerOperatorId,
    Guid RequestedByOperatorId,
    string RequestedByOperatorName,
    string ApprovalJustification,
    RemediationLaunchMode LaunchMode,
    string TemplateKey,
    string IncludeGroupId,
    string? ExcludeGroupId,
    bool AllUsersAssignment = false);
