using Securityzator.Application.Blueprints;
using Securityzator.Application.Recommendations;

namespace Securityzator.Web.Models.Home;

public sealed class DashboardViewModel
{
    public required PortalBlueprint Blueprint { get; init; }

    public required string OperatorDisplayName { get; init; }

    public required string WorkspaceName { get; init; }

    public required int ConnectionCount { get; init; }

    public required int ValidatedConnectionCount { get; init; }

    public required int ConnectionValidationFailureCount { get; init; }

    public required int RecommendationReadyConnectionCount { get; init; }

    public required int SecretsNeedingRotationCount { get; init; }

    public required int SecretsPastRotationCount { get; init; }

    public required int ActiveJobCount { get; init; }

    public required int JobsNeedingAttentionCount { get; init; }

    public required IReadOnlyList<string> AttentionItems { get; init; }

    public required IReadOnlyList<RecommendationCoverageSummary> RecommendationCoverageSummaries { get; init; }

    public bool HasConnections => ConnectionCount > 0;

    public bool HasAttentionItems => AttentionItems.Count > 0;

    public bool HasCoverage => RecommendationCoverageSummaries.Any(summary => summary.HasSnapshot);

    public int TotalCachedRecommendationCount => RecommendationCoverageSummaries.Sum(summary => summary.TotalControls);

    public int TotalMappedRecommendationCount => RecommendationCoverageSummaries.Sum(summary => summary.MappedControls);

    public int TotalRunnableRecommendationCount => RecommendationCoverageSummaries.Sum(summary => summary.RunnableControls);

    public int TotalMappingDriftCount => RecommendationCoverageSummaries.Sum(summary => summary.MappingDriftControls);

    public int CoverageReadyConnectionCount => RecommendationCoverageSummaries.Count(summary => summary.HasSnapshot);
}
