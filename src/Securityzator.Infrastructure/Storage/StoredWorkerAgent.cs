namespace Securityzator.Infrastructure.Storage;

public sealed class StoredWorkerAgent
{
    public string WorkerName { get; set; } = string.Empty;

    public int State { get; set; }

    public DateTimeOffset StartedUtc { get; set; }

    public DateTimeOffset LastHeartbeatUtc { get; set; }

    public DateTimeOffset? LastCompletedUtc { get; set; }

    public Guid? CurrentJobId { get; set; }

    public string? CurrentConnectionDisplayName { get; set; }

    public string? LastSummary { get; set; }

    public string? LastError { get; set; }
}
