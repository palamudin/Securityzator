using Securityzator.Application.Remediations;

namespace Securityzator.Application.Jobs;

public sealed record RemediationJobRecord(
    Guid Id,
    string TemplateKey,
    string TemplateName,
    Guid ConnectionId,
    string ConnectionDisplayName,
    Guid OwnerOperatorId,
    string RequestedByOperatorName,
    string ApprovalJustification,
    RemediationLaunchMode LaunchMode,
    RemediationJobStatus Status,
    int AttemptCount,
    int MaxAttempts,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? StartedUtc,
    DateTimeOffset? CompletedUtc,
    DateTimeOffset? NextAttemptUtc,
    string IncludeGroupId,
    string? ExcludeGroupId,
    string? PolicyId,
    string? PolicyState,
    Guid? RemediationRunId,
    string? LastError,
    IReadOnlyList<string> Logs);
