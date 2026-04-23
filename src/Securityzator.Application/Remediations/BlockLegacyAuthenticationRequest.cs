namespace Securityzator.Application.Remediations;

public sealed record BlockLegacyAuthenticationRequest(
    Guid ConnectionId,
    Guid OwnerOperatorId,
    Guid LaunchedByOperatorId,
    string LaunchedByOperatorName,
    string ApprovalJustification,
    RemediationLaunchMode LaunchMode,
    string IncludeGroupId,
    string? ExcludeGroupId);
