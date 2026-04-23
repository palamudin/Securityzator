namespace Securityzator.Application.Remediations;

public sealed record RequireMfaAllUsersRequest(
    Guid ConnectionId,
    Guid OwnerOperatorId,
    Guid LaunchedByOperatorId,
    string LaunchedByOperatorName,
    string ApprovalJustification,
    RemediationLaunchMode LaunchMode,
    string? ExcludeGroupId);
