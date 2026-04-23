namespace Securityzator.Application.Remediations;

public sealed record RequireMfaAdminsRequest(
    Guid ConnectionId,
    Guid OwnerOperatorId,
    Guid LaunchedByOperatorId,
    string LaunchedByOperatorName,
    string ApprovalJustification,
    RemediationLaunchMode LaunchMode,
    string IncludeGroupId,
    string? ExcludeGroupId);
