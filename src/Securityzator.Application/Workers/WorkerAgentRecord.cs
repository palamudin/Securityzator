namespace Securityzator.Application.Workers;

public sealed record WorkerAgentRecord(
    string WorkerName,
    WorkerExecutionState State,
    DateTimeOffset StartedUtc,
    DateTimeOffset LastHeartbeatUtc,
    DateTimeOffset? LastCompletedUtc,
    Guid? CurrentJobId,
    string? CurrentConnectionDisplayName,
    string? LastSummary,
    string? LastError,
    bool IsStale);
