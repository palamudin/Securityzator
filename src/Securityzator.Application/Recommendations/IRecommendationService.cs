namespace Securityzator.Application.Recommendations;

public interface IRecommendationService
{
    Task<IReadOnlyList<ConnectionRecommendationSummary>> ListConnectionSummariesAsync(
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<RecommendationCoverageSummary>> ListCoverageSummariesAsync(
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default);

    Task<RecommendationSnapshot?> GetLatestSnapshotAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default);

    Task<RecommendationSyncOutcome> SyncAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default);

    Task<RecommendationMappingBackfillOutcome> BackfillMappingsAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default);
}
