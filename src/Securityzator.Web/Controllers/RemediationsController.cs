using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Securityzator.Application.Blueprints;
using Securityzator.Application.Connections;
using Securityzator.Application.Jobs;
using Securityzator.Application.Portal;
using Securityzator.Application.Recommendations;
using Securityzator.Application.Remediations;
using Securityzator.Infrastructure.Graph;
using Securityzator.Web.Infrastructure;
using Securityzator.Web.Models.Remediations;

namespace Securityzator.Web.Controllers;

[Authorize(Policy = "RequireWorkspaceAdmin")]
public class RemediationsController : Controller
{
    private readonly IProductBlueprintService _blueprintService;
    private readonly IAzureConnectionService _connectionService;
    private readonly IRemediationJobService _jobService;
    private readonly IRemediationService _remediationService;
    private readonly IRecommendationService _recommendationService;

    public RemediationsController(
        IProductBlueprintService blueprintService,
        IAzureConnectionService connectionService,
        IRemediationJobService jobService,
        IRemediationService remediationService,
        IRecommendationService recommendationService)
    {
        _blueprintService = blueprintService;
        _connectionService = connectionService;
        _jobService = jobService;
        _remediationService = remediationService;
        _recommendationService = recommendationService;
    }

    public async Task<IActionResult> Index(
        Guid? connectionId,
        string? templateKey,
        string? sourceControlId,
        CancellationToken cancellationToken)
    {
        var model = await BuildPageModelAsync(
            new RemediationsPageViewModel
            {
                Blueprint = null!,
                SelectedTemplate = null!,
                OperatorDisplayName = string.Empty,
                WorkspaceName = string.Empty,
                Connections = Array.Empty<RemediationConnectionOptionViewModel>(),
                AvailableGroups = Array.Empty<DirectoryGroupEntry>(),
                RecentJobs = Array.Empty<RemediationJobRecord>(),
                RecentRuns = Array.Empty<RemediationRunRecord>(),
                ConnectionId = connectionId,
                TemplateKey = templateKey ?? string.Empty,
                SourceControlId = sourceControlId,
                ConfirmReportOnly = true
            },
            cancellationToken);

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ExecuteQueueableTemplate(
        RemediationsPageViewModel model,
        CancellationToken cancellationToken)
    {
        var blueprint = await _blueprintService.GetPortalBlueprintAsync(cancellationToken);
        model.SelectedTemplate = ResolveSelectedTemplate(blueprint, model.TemplateKey, null);

        ValidateQueueableGroupPolicy(model);

        if (!ModelState.IsValid)
        {
            var invalidModel = await BuildPageModelAsync(model, cancellationToken);
            return View("Index", invalidModel);
        }

        var queuedJob = await _jobService.EnqueueQueueableTemplateAsync(
            new EnqueueQueueableTemplateJobRequest(
                model.ConnectionId!.Value,
                User.GetOperatorId(),
                User.GetOperatorId(),
                User.Identity?.Name ?? "Operator",
                model.ApprovalJustification,
                model.EffectiveLaunchMode,
                model.TemplateKey,
                model.IncludeGroupId,
                model.ExcludeGroupId,
                model.AllUsersAssignment),
            cancellationToken);

        TempData["StatusMessage"] =
            $"Queued '{queuedJob.TemplateName}' for '{queuedJob.ConnectionDisplayName}' in {queuedJob.LaunchMode} mode. Track execution in Jobs while the worker picks it up.";

        return RedirectToAction(nameof(Index), new
        {
            connectionId = model.ConnectionId,
            templateKey = model.TemplateKey,
            sourceControlId = model.SourceControlId
        });
    }

    private async Task<RemediationsPageViewModel> BuildPageModelAsync(
        RemediationsPageViewModel model,
        CancellationToken cancellationToken)
    {
        var operatorId = User.GetOperatorId();
        var blueprint = await _blueprintService.GetPortalBlueprintAsync(cancellationToken);
        var connections = await _connectionService.ListForOperatorAsync(operatorId, cancellationToken);
        var jobs = await _jobService.ListForOperatorAsync(operatorId, cancellationToken);
        var runs = await _remediationService.ListRunsAsync(operatorId, cancellationToken);
        var sourceRecommendation = await ResolveSourceRecommendationAsync(
            model.ConnectionId,
            model.SourceControlId,
            operatorId,
            cancellationToken);
        var selectedTemplate = ResolveSelectedTemplate(
            blueprint,
            model.TemplateKey,
            sourceRecommendation?.RemediationTemplateKey);
        var availableGroups = Array.Empty<DirectoryGroupEntry>();
        string? transientError = null;
        var effectiveLaunchMode = selectedTemplate.SupportsLaunchModeSelection
            ? model.LaunchMode
            : selectedTemplate.DefaultLaunchMode;

        if (selectedTemplate.SupportsQueueExecution
            && model.ConnectionId.HasValue
            && connections.Any(connection => connection.Id == model.ConnectionId.Value && connection.HasStoredSecret)
            && (selectedTemplate.Targeting.SupportsIncludeGroupSelection || selectedTemplate.Targeting.SupportsExcludeGroupSelection))
        {
            try
            {
                availableGroups = (await _remediationService.ListGroupsAsync(
                    model.ConnectionId.Value,
                    operatorId,
                    cancellationToken)).ToArray();
            }
            catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
            {
                transientError = ex.Message;
            }
        }

        return new RemediationsPageViewModel
        {
            Blueprint = blueprint,
            SelectedTemplate = selectedTemplate,
            SourceRecommendation = sourceRecommendation,
            OperatorDisplayName = User.Identity?.Name ?? "Operator",
            WorkspaceName = User.GetWorkspaceName(),
            Connections = connections
                .Select(connection => new RemediationConnectionOptionViewModel
                {
                    Id = connection.Id,
                    DisplayName = connection.DisplayName,
                    TenantId = connection.TenantId,
                    HasStoredSecret = connection.HasStoredSecret
                })
                .ToArray(),
            AvailableGroups = availableGroups,
            RecentJobs = jobs.Take(8).ToArray(),
            RecentRuns = runs.Take(12).ToArray(),
            ConnectionId = model.ConnectionId,
            TemplateKey = selectedTemplate.Key,
            SourceControlId = model.SourceControlId,
            IncludeGroupId = model.IncludeGroupId,
            ExcludeGroupId = model.ExcludeGroupId,
            LaunchMode = effectiveLaunchMode,
            ApprovalJustification = model.ApprovalJustification,
            ConfirmReportOnly = model.ConfirmReportOnly,
            ConfirmGroupReview = model.ConfirmGroupReview,
            ConfirmEnabledChange = model.ConfirmEnabledChange,
            StatusMessage = TempData["StatusMessage"] as string,
            ErrorMessage = transientError ?? TempData["ErrorMessage"] as string
        };
    }

    private static RemediationTemplate ResolveSelectedTemplate(
        PortalBlueprint blueprint,
        string? templateKey,
        string? fallbackTemplateKey)
    {
        if (!string.IsNullOrWhiteSpace(templateKey))
        {
            var selected = blueprint.RemediationTemplates.FirstOrDefault(template =>
                string.Equals(template.Key, templateKey, StringComparison.OrdinalIgnoreCase));

            if (selected is not null)
            {
                return selected;
            }
        }

        if (!string.IsNullOrWhiteSpace(fallbackTemplateKey))
        {
            var fallback = blueprint.RemediationTemplates.FirstOrDefault(template =>
                string.Equals(template.Key, fallbackTemplateKey, StringComparison.OrdinalIgnoreCase));

            if (fallback is not null)
            {
                return fallback;
            }
        }

        return blueprint.RemediationTemplates.First(template =>
            string.Equals(template.Key, "block-legacy-auth", StringComparison.OrdinalIgnoreCase));
    }

    private async Task<RecommendationRecord?> ResolveSourceRecommendationAsync(
        Guid? connectionId,
        string? sourceControlId,
        Guid operatorId,
        CancellationToken cancellationToken)
    {
        if (!connectionId.HasValue || string.IsNullOrWhiteSpace(sourceControlId))
        {
            return null;
        }

        var snapshot = await _recommendationService.GetLatestSnapshotAsync(
            connectionId.Value,
            operatorId,
            cancellationToken);

        return snapshot?.Recommendations.FirstOrDefault(recommendation =>
            string.Equals(recommendation.ControlId, sourceControlId, StringComparison.OrdinalIgnoreCase));
    }

    private void ValidateQueueableGroupPolicy(RemediationsPageViewModel model)
    {
        if (!model.ConnectionId.HasValue)
        {
            ModelState.AddModelError(nameof(model.ConnectionId), "Select the Azure connection that should execute this quick win.");
        }

        model.LaunchMode = model.EffectiveLaunchMode;
        var requiresIncludeGroup = model.RequiresIncludeGroup;

        if (requiresIncludeGroup)
        {
            if (string.IsNullOrWhiteSpace(model.IncludeGroupId))
            {
                ModelState.AddModelError(nameof(model.IncludeGroupId), "Choose the group that should be targeted by this control.");
            }
            else if (!Guid.TryParse(model.IncludeGroupId, out _))
            {
                ModelState.AddModelError(nameof(model.IncludeGroupId), "Select a valid group object ID.");
            }
        }
        else
        {
            model.IncludeGroupId = string.Empty;
        }

        if (!model.SupportsExcludeGroup)
        {
            model.ExcludeGroupId = string.Empty;
        }
        else if (!string.IsNullOrWhiteSpace(model.ExcludeGroupId) && !Guid.TryParse(model.ExcludeGroupId, out _))
        {
            ModelState.AddModelError(nameof(model.ExcludeGroupId), "Select a valid group object ID.");
        }

        if (string.Equals(model.IncludeGroupId, model.ExcludeGroupId, StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(model.ExcludeGroupId))
        {
            ModelState.AddModelError(nameof(model.ExcludeGroupId), "The exclusion group must be different from the included target group.");
        }

        if (model.RequiresReportOnlyConfirmation && !model.ConfirmReportOnly)
        {
            ModelState.AddModelError(nameof(model.ConfirmReportOnly), "Confirm that this quick win must stay in report-only mode.");
        }

        if (model.RequiresLiveChangeConfirmation && !model.ConfirmReportOnly)
        {
            var templateName = string.IsNullOrWhiteSpace(model.SelectedTemplate?.Name)
                ? "This playbook"
                : $"'{model.SelectedTemplate.Name}'";
            var message = $"Confirm that {templateName} makes a live tenant change and has no report-only equivalent.";
            ModelState.AddModelError(nameof(model.ConfirmReportOnly), message);
        }

        if (model.RequiresEnabledChangeConfirmation && !model.ConfirmEnabledChange)
        {
            ModelState.AddModelError(nameof(model.ConfirmEnabledChange), "Confirm that this launch should create or promote the policy directly into enabled state.");
        }

        if (model.RequiresGroupReviewConfirmation && !model.ConfirmGroupReview)
        {
            ModelState.AddModelError(nameof(model.ConfirmGroupReview), "Confirm that the target and exclusion groups were reviewed before queueing.");
        }
    }
}
