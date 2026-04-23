using Securityzator.Application.Remediations;

namespace Securityzator.Infrastructure.Storage;

public sealed class StoredRemediationRun
{
    public Guid Id { get; set; }

    public Guid OwnerOperatorId { get; set; }

    public Guid LaunchedByOperatorId { get; set; }

    public string LaunchedByOperatorName { get; set; } = string.Empty;

    public string ApprovalJustification { get; set; } = string.Empty;

    public RemediationLaunchMode LaunchMode { get; set; } = RemediationLaunchMode.ReportOnly;

    public Guid ConnectionId { get; set; }

    public string ConnectionDisplayName { get; set; } = string.Empty;

    public string TemplateKey { get; set; } = string.Empty;

    public string TemplateName { get; set; } = string.Empty;

    public RemediationRunStatus Status { get; set; }

    public string Summary { get; set; } = string.Empty;

    public DateTimeOffset StartedUtc { get; set; }

    public DateTimeOffset CompletedUtc { get; set; }

    public string IncludeGroupId { get; set; } = string.Empty;

    public string? IncludeGroupName { get; set; }

    public string? ExcludeGroupId { get; set; }

    public string? ExcludeGroupName { get; set; }

    public string? PolicyId { get; set; }

    public string? PolicyState { get; set; }

    public bool AlreadyExists { get; set; }

    public List<string> Logs { get; set; } = [];
}
