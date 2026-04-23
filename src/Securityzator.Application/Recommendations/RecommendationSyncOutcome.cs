namespace Securityzator.Application.Recommendations;

public sealed record RecommendationSyncOutcome(
    Guid ConnectionId,
    string ConnectionDisplayName,
    RecommendationSyncStatus SyncStatus,
    bool Succeeded,
    string Message,
    DateTimeOffset AttemptedUtc,
    int RecommendationCount);
