namespace Securityzator.Application.Recommendations;

public sealed record RecommendationCoverageSummary(
    Guid ConnectionId,
    string ConnectionDisplayName,
    string TenantId,
    RecommendationSyncStatus SyncStatus,
    DateTimeOffset? LastSuccessUtc,
    int TotalControls,
    int MappedControls,
    int RunnableControls,
    int MappedFamilyControls,
    int UnmappedControls,
    int MissingTemplateControls,
    int MappingDriftControls,
    IReadOnlyList<RecommendationCoverageTemplateBucket> TopTemplateBuckets)
{
    public double MappedPercent => TotalControls == 0
        ? 0
        : Math.Round((double)MappedControls / TotalControls * 100, 2);

    public double RunnablePercent => TotalControls == 0
        ? 0
        : Math.Round((double)RunnableControls / TotalControls * 100, 2);

    public bool HasSnapshot => TotalControls > 0;

    public bool HasMappingDrift => MappingDriftControls > 0;
}
