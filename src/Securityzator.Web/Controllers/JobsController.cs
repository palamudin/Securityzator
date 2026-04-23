using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Securityzator.Application.Blueprints;
using Securityzator.Application.Jobs;
using Securityzator.Application.Recommendations;
using Securityzator.Application.Remediations;
using Securityzator.Application.Workers;
using Securityzator.Web.Infrastructure;
using Securityzator.Web.Models.Jobs;

namespace Securityzator.Web.Controllers;

[Authorize(Policy = "RequireWorkspaceAdmin")]
public class JobsController : Controller
{
    private readonly IProductBlueprintService _blueprintService;
    private readonly IRemediationJobService _jobService;
    private readonly IRemediationService _remediationService;
    private readonly IWorkerMonitorService _workerMonitorService;
    private readonly IRecommendationService _recommendationService;

    public JobsController(
        IProductBlueprintService blueprintService,
        IRemediationJobService jobService,
        IRemediationService remediationService,
        IWorkerMonitorService workerMonitorService,
        IRecommendationService recommendationService)
    {
        _blueprintService = blueprintService;
        _jobService = jobService;
        _remediationService = remediationService;
        _workerMonitorService = workerMonitorService;
        _recommendationService = recommendationService;
    }

    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        var blueprint = await _blueprintService.GetPortalBlueprintAsync(cancellationToken);
        var jobs = await _jobService.ListForOperatorAsync(User.GetOperatorId(), cancellationToken);
        var runs = await _remediationService.ListRunsAsync(User.GetOperatorId(), cancellationToken);
        var workers = await _workerMonitorService.ListAsync(cancellationToken);
        var coverageSummaries = await _recommendationService.ListCoverageSummariesAsync(User.GetOperatorId(), cancellationToken);
        var model = new JobsPageViewModel
        {
            Blueprint = blueprint,
            WorkspaceName = User.GetWorkspaceName(),
            Jobs = jobs.Take(20).ToArray(),
            Runs = runs.Take(20).ToArray(),
            Workers = workers.Take(8).ToArray(),
            RecommendationCoverageSummaries = coverageSummaries.Take(8).ToArray()
        };

        return View(model);
    }
}
