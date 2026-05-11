namespace Securityzator.Application.Remediations;

public sealed record QueueableRemediationTemplateRequest(
    Guid ConnectionId,
    Guid OwnerOperatorId,
    Guid LaunchedByOperatorId,
    string LaunchedByOperatorName,
    string ApprovalJustification,
    RemediationLaunchMode LaunchMode,
    string TemplateKey,
    string IncludeGroupId,
    string? ExcludeGroupId,
    bool AllUsersAssignment = false);
