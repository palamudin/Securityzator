using Securityzator.Application.Jobs;
using Securityzator.Application.Remediations;

namespace Securityzator.Infrastructure.Storage;

public sealed class StoredRemediationJob
{
    public Guid Id { get; set; }

    public string TemplateKey { get; set; } = string.Empty;

    public string TemplateName { get; set; } = string.Empty;

    public Guid ConnectionId { get; set; }

    public string ConnectionDisplayName { get; set; } = string.Empty;

    public Guid OwnerOperatorId { get; set; }

    public Guid RequestedByOperatorId { get; set; }

    public string RequestedByOperatorName { get; set; } = string.Empty;

    public string ApprovalJustification { get; set; } = string.Empty;

    public RemediationLaunchMode LaunchMode { get; set; } = RemediationLaunchMode.ReportOnly;

    public RemediationJobStatus Status { get; set; } = RemediationJobStatus.Queued;

    public int AttemptCount { get; set; }

    public int MaxAttempts { get; set; } = 3;

    public DateTimeOffset CreatedUtc { get; set; }

    public DateTimeOffset? StartedUtc { get; set; }

    public DateTimeOffset? CompletedUtc { get; set; }

    public DateTimeOffset? NextAttemptUtc { get; set; }

    public string IncludeGroupId { get; set; } = string.Empty;

    public string? ExcludeGroupId { get; set; }

    public bool AllUsersAssignment { get; set; }

    public string? PolicyId { get; set; }

    public string? PolicyState { get; set; }

    public Guid? RemediationRunId { get; set; }

    public string? LastError { get; set; }

    public string? ClaimedByWorker { get; set; }

    public List<string> Logs { get; set; } = [];
}
