using Securityzator.Application.Recommendations;

namespace Securityzator.Web.Models.Recommendations;

public sealed class RecommendationsPageViewModel
{
    public required string OperatorDisplayName { get; init; }

    public required string WorkspaceName { get; init; }

    public required IReadOnlyList<ConnectionRecommendationSummary> Connections { get; init; }

    public Guid? SelectedConnectionId { get; init; }

    public RecommendationSnapshot? SelectedSnapshot { get; init; }

    public RecommendationCoverageSummary? CoverageSummary { get; init; }

    public required IReadOnlyList<RecommendationListItemViewModel> FilteredRecommendations { get; init; }

    public required IReadOnlyList<string> AvailableCategories { get; init; }

    public required IReadOnlyList<string> AvailableProducts { get; init; }

    public required IReadOnlyList<MappedPlaybookSummaryViewModel> MappedPlaybooks { get; init; }

    public IReadOnlyList<string> SelectedDeclaredLicenseCapabilityLabels { get; init; } = Array.Empty<string>();

    public string SearchTerm { get; init; } = string.Empty;

    public string CategoryFilter { get; init; } = string.Empty;

    public string ProductFilter { get; init; } = string.Empty;

    public string PlaybookFilter { get; init; } = string.Empty;

    public bool QuickWinsOnly { get; init; }

    public string? StatusMessage { get; init; }

    public string? ErrorMessage { get; init; }

    public bool HasConnections => Connections.Count > 0;

    public bool HasActiveFilters =>
        !string.IsNullOrWhiteSpace(SearchTerm)
        || !string.IsNullOrWhiteSpace(CategoryFilter)
        || !string.IsNullOrWhiteSpace(ProductFilter)
        || !string.IsNullOrWhiteSpace(PlaybookFilter)
        || QuickWinsOnly;

    public int TotalRecommendationCount => SelectedSnapshot?.Recommendations.Count ?? 0;

    public int FilteredRecommendationCount => FilteredRecommendations.Count;

    public int MappedRecommendationCount =>
        CoverageSummary?.MappedControls
        ?? SelectedSnapshot?.Recommendations.Count(recommendation =>
            !string.IsNullOrWhiteSpace(recommendation.RemediationTemplateKey))
        ?? 0;

    public int RunnableRecommendationCount =>
        CoverageSummary?.RunnableControls
        ?? FilteredRecommendations.Count(recommendation => recommendation.SupportsQueueExecution);

    public int BlockedRecommendationCount =>
        CoverageSummary?.MappedFamilyControls
        ?? FilteredRecommendations.Count(recommendation => recommendation.HasMappedTemplate && !recommendation.SupportsQueueExecution);

    public int UnmappedRecommendationCount => CoverageSummary?.UnmappedControls ?? 0;

    public int MappingDriftCount => CoverageSummary?.MappingDriftControls ?? 0;

    public int RunnablePlaybookCount =>
        MappedPlaybooks.Count(playbook => playbook.SupportsQueueExecution);

    public int BlockedPlaybookCount =>
        MappedPlaybooks.Count(playbook => !playbook.SupportsQueueExecution);

    public int LicenseBlockedRecommendationCount =>
        FilteredRecommendations.Count(recommendation => recommendation.LicenseRequirementState == Securityzator.Application.Portal.LicenseRequirementState.Missing);

    public int LicenseUnknownRecommendationCount =>
        FilteredRecommendations.Count(recommendation => recommendation.LicenseRequirementState == Securityzator.Application.Portal.LicenseRequirementState.Unknown);
}
