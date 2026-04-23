namespace Securityzator.Application.Remediations;

public sealed record RemediationRunRecord(
    Guid Id,
    string TemplateKey,
    string TemplateName,
    Guid ConnectionId,
    string ConnectionDisplayName,
    RemediationRunStatus Status,
    string Summary,
    DateTimeOffset StartedUtc,
    DateTimeOffset CompletedUtc,
    string LaunchedByOperatorName,
    string ApprovalJustification,
    RemediationLaunchMode LaunchMode,
    string IncludeGroupId,
    string? IncludeGroupName,
    string? ExcludeGroupId,
    string? ExcludeGroupName,
    string? PolicyId,
    string? PolicyState,
    bool AlreadyExists,
    IReadOnlyList<string> Logs);
