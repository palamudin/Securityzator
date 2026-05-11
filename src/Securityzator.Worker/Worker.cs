using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Securityzator.Application.Jobs;
using Securityzator.Application.Remediations;
using Securityzator.Application.Workers;

namespace Securityzator.Worker;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly IRemediationJobService _jobService;
    private readonly IRemediationService _remediationService;
    private readonly IWorkerMonitorService _workerMonitorService;
    private readonly WorkerOptions _options;

    public Worker(
        ILogger<Worker> logger,
        IRemediationJobService jobService,
        IRemediationService remediationService,
        IWorkerMonitorService workerMonitorService,
        IOptions<WorkerOptions> options)
    {
        _logger = logger;
        _jobService = jobService;
        _remediationService = remediationService;
        _workerMonitorService = workerMonitorService;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var workerName = $"{Environment.MachineName}/Securityzator.Worker";
        _logger.LogInformation("Securityzator worker started as {WorkerName}.", workerName);
        await _workerMonitorService.ReportStartedAsync(workerName, stoppingToken);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await _workerMonitorService.ReportIdleAsync(
                    workerName,
                    null,
                    null,
                    null,
                    stoppingToken);

                var claimedJob = await _jobService.TryClaimNextAsync(workerName, stoppingToken);

                if (claimedJob is null)
                {
                    await Task.Delay(TimeSpan.FromSeconds(Math.Max(1, _options.IdleDelaySeconds)), stoppingToken);
                    continue;
                }

                _logger.LogInformation(
                    "Worker picked up job {JobId} for connection {ConnectionDisplayName}. Attempt {AttemptCount}/{MaxAttempts}.",
                    claimedJob.Id,
                    claimedJob.ConnectionDisplayName,
                    claimedJob.AttemptCount,
                    claimedJob.MaxAttempts);
                await _workerMonitorService.ReportJobClaimedAsync(
                    workerName,
                    claimedJob.Id,
                    claimedJob.ConnectionDisplayName,
                    $"Processing '{claimedJob.TemplateKey}' for '{claimedJob.ConnectionDisplayName}'. Attempt {claimedJob.AttemptCount} of {claimedJob.MaxAttempts}.",
                    stoppingToken);

                try
                {
                    var outcome = await _remediationService.ExecuteQueueableTemplateAsync(
                        new QueueableRemediationTemplateRequest(
                            claimedJob.ConnectionId,
                            claimedJob.OwnerOperatorId,
                            claimedJob.RequestedByOperatorId,
                            claimedJob.RequestedByOperatorName,
                            claimedJob.ApprovalJustification,
                            claimedJob.LaunchMode,
                            claimedJob.TemplateKey,
                            claimedJob.IncludeGroupId,
                            claimedJob.ExcludeGroupId,
                            claimedJob.AllUsersAssignment),
                        stoppingToken);

                    if (outcome.Succeeded)
                    {
                        await _jobService.MarkSucceededAsync(
                            claimedJob.Id,
                            outcome.RunId,
                            outcome.Message,
                            outcome.PolicyId,
                            outcome.PolicyState,
                            stoppingToken);
                        await _workerMonitorService.ReportIdleAsync(
                            workerName,
                            outcome.Message,
                            string.Empty,
                            outcome.CompletedUtc,
                            stoppingToken);
                    }
                    else
                    {
                        await _jobService.MarkFailedAsync(claimedJob.Id, outcome.Message, stoppingToken);
                        await _workerMonitorService.ReportIdleAsync(
                            workerName,
                            outcome.Message,
                            outcome.Message,
                            outcome.CompletedUtc,
                            stoppingToken);
                    }
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Worker failed while processing job {JobId}.", claimedJob.Id);
                    await _jobService.MarkFailedAsync(claimedJob.Id, ex.Message, stoppingToken);
                    await _workerMonitorService.ReportIdleAsync(
                        workerName,
                        $"Worker failure while processing job '{claimedJob.Id}'.",
                        ex.Message,
                        DateTimeOffset.UtcNow,
                        stoppingToken);
                }

                await Task.Delay(TimeSpan.FromSeconds(Math.Max(1, _options.PollIntervalSeconds)), stoppingToken);
            }
        }
        finally
        {
            using var shutdownCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                await _workerMonitorService.ReportStoppedAsync(
                    workerName,
                    "Worker process stopped.",
                    shutdownCts.Token);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to record worker shutdown status for {WorkerName}.", workerName);
            }
        }
    }
}
