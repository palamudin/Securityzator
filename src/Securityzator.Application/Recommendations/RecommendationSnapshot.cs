namespace Securityzator.Application.Recommendations;

public sealed record RecommendationSnapshot(
    Guid ConnectionId,
    string ConnectionDisplayName,
    string TenantId,
    RecommendationSyncStatus SyncStatus,
    DateTimeOffset? LastAttemptUtc,
    DateTimeOffset? LastSuccessUtc,
    int RecommendationCount,
    string? LastError,
    IReadOnlyList<RecommendationRecord> Recommendations);
