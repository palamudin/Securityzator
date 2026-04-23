using Microsoft.Extensions.Options;
using Securityzator.Application.Workers;
using Securityzator.Infrastructure.Storage;

namespace Securityzator.Infrastructure.Workers;

public sealed class FileBackedWorkerMonitorService : IWorkerMonitorService
{
    private readonly JsonFileSecurityzatorStateStore _stateStore;
    private readonly IOptions<WorkerMonitorOptions> _options;

    public FileBackedWorkerMonitorService(
        JsonFileSecurityzatorStateStore stateStore,
        IOptions<WorkerMonitorOptions> options)
    {
        _stateStore = stateStore;
        _options = options;
    }

    public async Task ReportStartedAsync(
        string workerName,
        CancellationToken cancellationToken = default)
    {
        await _stateStore.WriteAsync(state =>
        {
            var now = DateTimeOffset.UtcNow;
            var stored = GetOrCreateWorker(state, workerName, now);
            stored.State = (int)WorkerExecutionState.Starting;
            stored.LastHeartbeatUtc = now;
            stored.LastSummary = "Worker process started and is preparing to poll for jobs.";
            stored.LastError = null;
            stored.CurrentJobId = null;
            stored.CurrentConnectionDisplayName = null;
            return true;
        }, cancellationToken);
    }

    public async Task ReportIdleAsync(
        string workerName,
        string? summary,
        string? error,
        DateTimeOffset? lastCompletedUtc,
        CancellationToken cancellationToken = default)
    {
        await _stateStore.WriteAsync(state =>
        {
            var now = DateTimeOffset.UtcNow;
            var stored = GetOrCreateWorker(state, workerName, now);
            stored.State = (int)WorkerExecutionState.Idle;
            stored.LastHeartbeatUtc = now;
            stored.LastCompletedUtc = lastCompletedUtc ?? stored.LastCompletedUtc;

            if (!string.IsNullOrWhiteSpace(summary))
            {
                stored.LastSummary = Normalize(summary);
            }

            if (error is not null)
            {
                stored.LastError = NormalizeNullable(error);
            }

            stored.CurrentJobId = null;
            stored.CurrentConnectionDisplayName = null;
            return true;
        }, cancellationToken);
    }

    public async Task ReportJobClaimedAsync(
        string workerName,
        Guid jobId,
        string connectionDisplayName,
        string summary,
        CancellationToken cancellationToken = default)
    {
        await _stateStore.WriteAsync(state =>
        {
            var now = DateTimeOffset.UtcNow;
            var stored = GetOrCreateWorker(state, workerName, now);
            stored.State = (int)WorkerExecutionState.Processing;
            stored.LastHeartbeatUtc = now;
            stored.CurrentJobId = jobId;
            stored.CurrentConnectionDisplayName = connectionDisplayName.Trim();
            stored.LastSummary = Normalize(summary);
            stored.LastError = null;
            return true;
        }, cancellationToken);
    }

    public async Task ReportStoppedAsync(
        string workerName,
        string? summary,
        CancellationToken cancellationToken = default)
    {
        await _stateStore.WriteAsync(state =>
        {
            var now = DateTimeOffset.UtcNow;
            var stored = GetOrCreateWorker(state, workerName, now);
            stored.State = (int)WorkerExecutionState.Stopped;
            stored.LastHeartbeatUtc = now;
            stored.LastSummary = Normalize(summary);
            stored.LastError = null;
            stored.CurrentJobId = null;
            stored.CurrentConnectionDisplayName = null;
            return true;
        }, cancellationToken);
    }

    public Task<IReadOnlyList<WorkerAgentRecord>> ListAsync(
        CancellationToken cancellationToken = default)
    {
        return _stateStore.ReadAsync<IReadOnlyList<WorkerAgentRecord>>(state =>
        {
            var now = DateTimeOffset.UtcNow;
            var staleAfter = TimeSpan.FromSeconds(Math.Max(10, _options.Value.HeartbeatStaleAfterSeconds));

            return state.Workers
                .OrderByDescending(worker => worker.LastHeartbeatUtc)
                .Select(worker => new WorkerAgentRecord(
                    worker.WorkerName,
                    Enum.IsDefined(typeof(WorkerExecutionState), worker.State)
                        ? (WorkerExecutionState)worker.State
                        : WorkerExecutionState.Stopped,
                    worker.StartedUtc,
                    worker.LastHeartbeatUtc,
                    worker.LastCompletedUtc,
                    worker.CurrentJobId,
                    worker.CurrentConnectionDisplayName,
                    worker.LastSummary,
                    worker.LastError,
                    IsStale(worker, now, staleAfter)))
                .ToArray();
        }, cancellationToken);
    }

    private static StoredWorkerAgent GetOrCreateWorker(
        SecurityzatorStateDocument state,
        string workerName,
        DateTimeOffset now)
    {
        var normalizedWorkerName = workerName.Trim();
        var stored = state.Workers.FirstOrDefault(item =>
            string.Equals(item.WorkerName, normalizedWorkerName, StringComparison.OrdinalIgnoreCase));

        if (stored is not null)
        {
            if (stored.StartedUtc == default)
            {
                stored.StartedUtc = now;
            }

            return stored;
        }

        stored = new StoredWorkerAgent
        {
            WorkerName = normalizedWorkerName,
            StartedUtc = now,
            LastHeartbeatUtc = now,
            State = (int)WorkerExecutionState.Starting
        };

        state.Workers.Add(stored);
        return stored;
    }

    private static bool IsStale(
        StoredWorkerAgent worker,
        DateTimeOffset now,
        TimeSpan staleAfter)
    {
        if ((WorkerExecutionState)worker.State == WorkerExecutionState.Stopped)
        {
            return false;
        }

        if (worker.LastHeartbeatUtc == default)
        {
            return true;
        }

        return now - worker.LastHeartbeatUtc > staleAfter;
    }

    private static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "No detail recorded.";
        }

        var normalized = value.Trim().ReplaceLineEndings(" ");
        return normalized.Length <= 320 ? normalized : normalized[..320];
    }

    private static string? NormalizeNullable(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : Normalize(value);
    }
}
