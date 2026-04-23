namespace Securityzator.Application.Recommendations;

public sealed record ConnectionRecommendationSummary(
    Guid ConnectionId,
    string ConnectionDisplayName,
    string TenantId,
    bool HasStoredSecret,
    RecommendationSyncStatus SyncStatus,
    DateTimeOffset? LastAttemptUtc,
    DateTimeOffset? LastSuccessUtc,
    int RecommendationCount,
    string? LastError);
