using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Securityzator.Application.Blueprints;
using Securityzator.Application.Connections;
using Securityzator.Application.Jobs;
using Securityzator.Application.Recommendations;
using Securityzator.Web.Infrastructure;
using Securityzator.Web.Models.Home;
using Securityzator.Web.Models;

namespace Securityzator.Web.Controllers;

[Authorize]
public class HomeController : Controller
{
    private const int RotationWarningDays = 45;
    private const int RotationCriticalDays = 75;
    private readonly IProductBlueprintService _blueprintService;
    private readonly IAzureConnectionService _connectionService;
    private readonly IRecommendationService _recommendationService;
    private readonly IRemediationJobService _jobService;

    public HomeController(
        IProductBlueprintService blueprintService,
        IAzureConnectionService connectionService,
        IRecommendationService recommendationService,
        IRemediationJobService jobService)
    {
        _blueprintService = blueprintService;
        _connectionService = connectionService;
        _recommendationService = recommendationService;
        _jobService = jobService;
    }

    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        var operatorId = User.GetOperatorId();
        var blueprint = await _blueprintService.GetPortalBlueprintAsync(cancellationToken);
        var connections = await _connectionService.ListForOperatorAsync(operatorId, cancellationToken);
        var recommendationSummaries = await _recommendationService.ListConnectionSummariesAsync(operatorId, cancellationToken);
        var recommendationCoverageSummaries = await _recommendationService.ListCoverageSummariesAsync(operatorId, cancellationToken);
        var jobs = await _jobService.ListForOperatorAsync(operatorId, cancellationToken);

        var validatedConnectionCount = connections.Count(connection =>
            connection.ValidationStatus == AzureConnectionValidationStatus.Succeeded);
        var connectionValidationFailureCount = connections.Count(connection =>
            connection.ValidationStatus == AzureConnectionValidationStatus.Failed);
        var recommendationReadyConnectionCount = recommendationSummaries.Count(summary =>
            summary.SyncStatus == RecommendationSyncStatus.Succeeded && summary.RecommendationCount > 0);
        var secretsNeedingRotationCount = connections.Count(connection =>
            GetSecretAgeDays(connection.SecretUpdatedUtc) >= RotationWarningDays);
        var secretsPastRotationCount = connections.Count(connection =>
            GetSecretAgeDays(connection.SecretUpdatedUtc) >= RotationCriticalDays);
        var activeJobCount = jobs.Count(job =>
            job.Status is RemediationJobStatus.Queued or RemediationJobStatus.Running or RemediationJobStatus.RetryScheduled);
        var jobsNeedingAttentionCount = jobs.Count(job =>
            job.Status is RemediationJobStatus.RetryScheduled or RemediationJobStatus.Failed);

        var model = new DashboardViewModel
        {
            Blueprint = blueprint,
            OperatorDisplayName = User.Identity?.Name ?? "Operator",
            WorkspaceName = User.GetWorkspaceName(),
            ConnectionCount = connections.Count,
            ValidatedConnectionCount = validatedConnectionCount,
            ConnectionValidationFailureCount = connectionValidationFailureCount,
            RecommendationReadyConnectionCount = recommendationReadyConnectionCount,
            SecretsNeedingRotationCount = secretsNeedingRotationCount,
            SecretsPastRotationCount = secretsPastRotationCount,
            ActiveJobCount = activeJobCount,
            JobsNeedingAttentionCount = jobsNeedingAttentionCount,
            AttentionItems = BuildAttentionItems(connections, jobs, recommendationSummaries, recommendationCoverageSummaries),
            RecommendationCoverageSummaries = recommendationCoverageSummaries
        };

        return View(model);
    }

    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

    private static IReadOnlyList<string> BuildAttentionItems(
        IReadOnlyList<AzureConnectionProfile> connections,
        IReadOnlyList<RemediationJobRecord> jobs,
        IReadOnlyList<ConnectionRecommendationSummary> recommendationSummaries,
        IReadOnlyList<RecommendationCoverageSummary> recommendationCoverageSummaries)
    {
        var items = new List<string>();

        items.AddRange(connections
            .Where(connection => connection.ValidationStatus == AzureConnectionValidationStatus.Failed)
            .Select(connection => $"Connection '{connection.DisplayName}' failed backend validation. Review the saved secret or Graph permissions."));

        items.AddRange(connections
            .Where(connection => GetSecretAgeDays(connection.SecretUpdatedUtc) >= RotationCriticalDays)
            .Select(connection => $"Connection '{connection.DisplayName}' has a secret age of {GetSecretAgeDays(connection.SecretUpdatedUtc)} day(s). Rotate it now."));

        if (connections.Count > 0 && connections.All(connection => connection.ValidationStatus != AzureConnectionValidationStatus.Succeeded))
        {
            items.Add("No saved tenant connection has passed backend validation yet.");
        }

        if (recommendationSummaries.Count > 0
            && recommendationSummaries.All(summary => summary.SyncStatus != RecommendationSyncStatus.Succeeded))
        {
            items.Add("No tenant recommendation snapshot is currently in a successful synced state.");
        }

        var failedOrRetryCount = jobs.Count(job => job.Status is RemediationJobStatus.RetryScheduled or RemediationJobStatus.Failed);
        if (failedOrRetryCount > 0)
        {
            items.Add($"{failedOrRetryCount} remediation job(s) need attention because they failed or are waiting for retry.");
        }

        var connectionsWithMappingDrift = recommendationCoverageSummaries.Count(summary => summary.HasMappingDrift);
        if (connectionsWithMappingDrift > 0)
        {
            items.Add($"{connectionsWithMappingDrift} recommendation snapshot(s) have cached mapping drift. Refresh cached mappings or re-sync to persist the current routing.");
        }

        return items.Take(6).ToArray();
    }

    private static int GetSecretAgeDays(DateTimeOffset secretUpdatedUtc)
    {
        return Math.Max(0, (int)Math.Floor((DateTimeOffset.UtcNow - secretUpdatedUtc).TotalDays));
    }
}
