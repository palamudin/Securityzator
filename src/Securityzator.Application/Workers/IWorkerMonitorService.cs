namespace Securityzator.Application.Workers;

public interface IWorkerMonitorService
{
    Task ReportStartedAsync(
        string workerName,
        CancellationToken cancellationToken = default);

    Task ReportIdleAsync(
        string workerName,
        string? summary,
        string? error,
        DateTimeOffset? lastCompletedUtc,
        CancellationToken cancellationToken = default);

    Task ReportJobClaimedAsync(
        string workerName,
        Guid jobId,
        string connectionDisplayName,
        string summary,
        CancellationToken cancellationToken = default);

    Task ReportStoppedAsync(
        string workerName,
        string? summary,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<WorkerAgentRecord>> ListAsync(
        CancellationToken cancellationToken = default);
}
