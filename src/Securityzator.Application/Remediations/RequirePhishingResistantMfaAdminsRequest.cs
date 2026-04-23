namespace Securityzator.Application.Remediations;

public sealed record RequirePhishingResistantMfaAdminsRequest(
    Guid ConnectionId,
    Guid OwnerOperatorId,
    Guid LaunchedByOperatorId,
    string LaunchedByOperatorName,
    string ApprovalJustification,
    RemediationLaunchMode LaunchMode,
    string IncludeGroupId,
    string? ExcludeGroupId);
