using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Securityzator.Application.Blueprints;
using Securityzator.Application.Connections;
using Securityzator.Application.Portal;
using Securityzator.Application.Recommendations;
using Securityzator.Web.Infrastructure;
using Securityzator.Web.Models.Recommendations;

namespace Securityzator.Web.Controllers;

[Authorize]
public class RecommendationsController : Controller
{
    private readonly IAzureConnectionService _connectionService;
    private readonly IRecommendationService _recommendationService;
    private readonly IProductBlueprintService _blueprintService;

    public RecommendationsController(
        IAzureConnectionService connectionService,
        IRecommendationService recommendationService,
        IProductBlueprintService blueprintService)
    {
        _connectionService = connectionService;
        _recommendationService = recommendationService;
        _blueprintService = blueprintService;
    }

    public async Task<IActionResult> Index(
        Guid? connectionId,
        string? searchTerm,
        string? category,
        string? product,
        string? playbook,
        bool quickWinsOnly,
        CancellationToken cancellationToken)
    {
        var operatorId = User.GetOperatorId();
        var blueprint = await _blueprintService.GetPortalBlueprintAsync(cancellationToken);
        var templateLookup = blueprint.RemediationTemplates
            .ToDictionary(template => template.Key, StringComparer.OrdinalIgnoreCase);
        var connections = await _recommendationService.ListConnectionSummariesAsync(operatorId, cancellationToken);
        var coverageSummaries = await _recommendationService.ListCoverageSummariesAsync(operatorId, cancellationToken);
        var selectedConnectionId = connectionId ?? connections.FirstOrDefault()?.ConnectionId;
        RecommendationSnapshot? selectedSnapshot = null;
        RecommendationCoverageSummary? selectedCoverageSummary = null;
        IReadOnlyList<RecommendationListItemViewModel> filteredRecommendations = Array.Empty<RecommendationListItemViewModel>();
        IReadOnlyList<string> availableCategories = Array.Empty<string>();
        IReadOnlyList<string> availableProducts = Array.Empty<string>();
        IReadOnlyList<MappedPlaybookSummaryViewModel> mappedPlaybooks = Array.Empty<MappedPlaybookSummaryViewModel>();
        IReadOnlyList<string> declaredLicenseCapabilities = Array.Empty<string>();
        IReadOnlyList<string> declaredLicenseCapabilityLabels = Array.Empty<string>();

        if (selectedConnectionId.HasValue)
        {
            var selectedConnection = await _connectionService.GetForOperatorAsync(
                selectedConnectionId.Value,
                operatorId,
                cancellationToken);
            declaredLicenseCapabilities = selectedConnection?.DeclaredLicenseCapabilities ?? Array.Empty<string>();
            declaredLicenseCapabilityLabels = TenantLicenseCapabilityCatalog.ResolveLabels(declaredLicenseCapabilities);
            selectedSnapshot = await _recommendationService.GetLatestSnapshotAsync(
                selectedConnectionId.Value,
                operatorId,
                cancellationToken);
            selectedCoverageSummary = coverageSummaries.FirstOrDefault(summary => summary.ConnectionId == selectedConnectionId.Value);

            if (selectedSnapshot is not null)
            {
                availableCategories = selectedSnapshot.Recommendations
                    .Select(recommendation => recommendation.Category)
                    .Where(value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                availableProducts = selectedSnapshot.Recommendations
                    .Select(recommendation => recommendation.Product)
                    .Where(value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                mappedPlaybooks = BuildMappedPlaybooks(selectedSnapshot.Recommendations, templateLookup, declaredLicenseCapabilities);
                filteredRecommendations = ApplyFilters(
                    selectedSnapshot.Recommendations,
                    searchTerm,
                    category,
                    product,
                    playbook,
                    quickWinsOnly)
                    .Select(recommendation => ToListItem(recommendation, templateLookup, declaredLicenseCapabilities))
                    .ToArray();
            }
        }

        var model = new RecommendationsPageViewModel
        {
            OperatorDisplayName = User.Identity?.Name ?? "Operator",
            WorkspaceName = User.GetWorkspaceName(),
            Connections = connections,
            SelectedConnectionId = selectedConnectionId,
            SelectedSnapshot = selectedSnapshot,
            CoverageSummary = selectedCoverageSummary,
            FilteredRecommendations = filteredRecommendations,
            AvailableCategories = availableCategories,
            AvailableProducts = availableProducts,
            MappedPlaybooks = mappedPlaybooks,
            SelectedDeclaredLicenseCapabilityLabels = declaredLicenseCapabilityLabels,
            SearchTerm = searchTerm?.Trim() ?? string.Empty,
            CategoryFilter = category?.Trim() ?? string.Empty,
            ProductFilter = product?.Trim() ?? string.Empty,
            PlaybookFilter = playbook?.Trim() ?? string.Empty,
            QuickWinsOnly = quickWinsOnly,
            StatusMessage = TempData["StatusMessage"] as string,
            ErrorMessage = TempData["ErrorMessage"] as string
        };

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> BackfillMappings(Guid connectionId, CancellationToken cancellationToken)
    {
        var outcome = await _recommendationService.BackfillMappingsAsync(connectionId, User.GetOperatorId(), cancellationToken);

        if (outcome.Succeeded)
        {
            TempData["StatusMessage"] = outcome.Message;
        }
        else
        {
            TempData["ErrorMessage"] = outcome.Message;
        }

        return RedirectToAction(nameof(Index), new { connectionId });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Sync(Guid connectionId, CancellationToken cancellationToken)
    {
        var outcome = await _recommendationService.SyncAsync(connectionId, User.GetOperatorId(), cancellationToken);

        if (outcome.Succeeded)
        {
            TempData["StatusMessage"] = outcome.Message;
        }
        else
        {
            TempData["ErrorMessage"] = outcome.Message;
        }

        return RedirectToAction(nameof(Index), new { connectionId });
    }

    private static IReadOnlyList<MappedPlaybookSummaryViewModel> BuildMappedPlaybooks(
        IReadOnlyList<RecommendationRecord> recommendations,
        IReadOnlyDictionary<string, RemediationTemplate> templateLookup,
        IReadOnlyList<string> declaredLicenseCapabilities)
    {
        return recommendations
            .Where(recommendation => !string.IsNullOrWhiteSpace(recommendation.RemediationTemplateKey))
            .GroupBy(recommendation => recommendation.RemediationTemplateKey!, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var template = ResolveTemplate(group.Key, templateLookup);
                var requiredLicenseLabels = ResolveRequiredLicenseCapabilityLabels(template);
                var missingLicenseLabels = ResolveMissingLicenseCapabilityLabels(template, declaredLicenseCapabilities);
                return new MappedPlaybookSummaryViewModel
                {
                    TemplateKey = group.Key,
                    TemplateName = template?.Name ?? group.Key,
                    Summary = template?.Summary ?? "Mapped Secure Score controls route into this playbook.",
                    DeliveryMode = template?.DeliveryMode ?? "Mapped playbook",
                    SupportsQueueExecution = template?.SupportsQueueExecution ?? false,
                    ExecutionSurface = template?.ExecutionSurface ?? string.Empty,
                    TargetSurface = template?.Targeting.TargetSurface ?? string.Empty,
                    NextStage = template?.NextStage ?? string.Empty,
                    CurrentBlockers = template?.CurrentBlockers ?? Array.Empty<string>(),
                    RequiredLicenseCapabilityLabels = requiredLicenseLabels,
                    MissingLicenseCapabilityLabels = missingLicenseLabels,
                    LicenseRequirementState = ResolveLicenseRequirementState(template, declaredLicenseCapabilities),
                    RecommendationCount = group.Count(),
                    ExampleRecommendationTitles = group
                        .Select(recommendation => recommendation.Title)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .Take(3)
                        .ToArray()
                };
            })
            .OrderByDescending(playbook => playbook.SupportsQueueExecution)
            .ThenByDescending(playbook => playbook.RecommendationCount)
            .ThenBy(playbook => playbook.TemplateName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static RecommendationListItemViewModel ToListItem(
        RecommendationRecord recommendation,
        IReadOnlyDictionary<string, RemediationTemplate> templateLookup,
        IReadOnlyList<string> declaredLicenseCapabilities)
    {
        var template = ResolveTemplate(recommendation.RemediationTemplateKey, templateLookup);

        return new RecommendationListItemViewModel
        {
            Recommendation = recommendation,
            TemplateKey = recommendation.RemediationTemplateKey,
            TemplateName = template?.Name,
            TemplateDeliveryMode = template?.DeliveryMode,
            SupportsQueueExecution = template?.SupportsQueueExecution ?? false,
            TemplateExecutionSurface = template?.ExecutionSurface,
            TemplateTargetSurface = template?.Targeting.TargetSurface,
            TemplateNextStage = template?.NextStage,
            TemplateBlockers = template?.CurrentBlockers ?? Array.Empty<string>(),
            RequiredLicenseCapabilityLabels = ResolveRequiredLicenseCapabilityLabels(template),
            MissingLicenseCapabilityLabels = ResolveMissingLicenseCapabilityLabels(template, declaredLicenseCapabilities),
            LicenseRequirementState = ResolveLicenseRequirementState(template, declaredLicenseCapabilities)
        };
    }

    private static IReadOnlyList<RecommendationRecord> ApplyFilters(
        IReadOnlyList<RecommendationRecord> recommendations,
        string? searchTerm,
        string? category,
        string? product,
        string? playbook,
        bool quickWinsOnly)
    {
        var query = recommendations.AsEnumerable();

        if (!string.IsNullOrWhiteSpace(searchTerm))
        {
            var normalizedSearch = searchTerm.Trim();
            query = query.Where(recommendation =>
                recommendation.Title.Contains(normalizedSearch, StringComparison.OrdinalIgnoreCase)
                || recommendation.Category.Contains(normalizedSearch, StringComparison.OrdinalIgnoreCase)
                || recommendation.Product.Contains(normalizedSearch, StringComparison.OrdinalIgnoreCase)
                || recommendation.ControlId.Contains(normalizedSearch, StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(category))
        {
            query = query.Where(recommendation =>
                string.Equals(recommendation.Category, category.Trim(), StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(product))
        {
            query = query.Where(recommendation =>
                string.Equals(recommendation.Product, product.Trim(), StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(playbook))
        {
            query = query.Where(recommendation =>
                string.Equals(recommendation.RemediationTemplateKey, playbook.Trim(), StringComparison.OrdinalIgnoreCase));
        }

        if (quickWinsOnly)
        {
            query = query.Where(recommendation => !string.IsNullOrWhiteSpace(recommendation.RemediationTemplateKey));
        }

        return query.ToArray();
    }

    private static RemediationTemplate? ResolveTemplate(
        string? templateKey,
        IReadOnlyDictionary<string, RemediationTemplate> templateLookup)
    {
        if (string.IsNullOrWhiteSpace(templateKey))
        {
            return null;
        }

        return templateLookup.TryGetValue(templateKey, out var template)
            ? template
            : null;
    }

    private static IReadOnlyList<string> ResolveRequiredLicenseCapabilityLabels(RemediationTemplate? template)
    {
        return template is null
            ? Array.Empty<string>()
            : TenantLicenseCapabilityCatalog.ResolveLabels(template.RequiredLicenseCapabilities);
    }

    private static IReadOnlyList<string> ResolveMissingLicenseCapabilityLabels(
        RemediationTemplate? template,
        IReadOnlyList<string> declaredLicenseCapabilities)
    {
        if (template is null)
        {
            return Array.Empty<string>();
        }

        var declaredSet = new HashSet<string>(declaredLicenseCapabilities, StringComparer.OrdinalIgnoreCase);
        var missingKeys = template.RequiredLicenseCapabilities
            .Where(required => !declaredSet.Contains(required))
            .ToArray();

        return TenantLicenseCapabilityCatalog.ResolveLabels(missingKeys);
    }

    private static LicenseRequirementState ResolveLicenseRequirementState(
        RemediationTemplate? template,
        IReadOnlyList<string> declaredLicenseCapabilities)
    {
        if (template is null || template.RequiredLicenseCapabilities.Count == 0)
        {
            return LicenseRequirementState.NotApplicable;
        }

        if (declaredLicenseCapabilities.Count == 0)
        {
            return LicenseRequirementState.Unknown;
        }

        var declaredSet = new HashSet<string>(declaredLicenseCapabilities, StringComparer.OrdinalIgnoreCase);

        return template.RequiredLicenseCapabilities.All(declaredSet.Contains)
            ? LicenseRequirementState.Satisfied
            : LicenseRequirementState.Missing;
    }
}
