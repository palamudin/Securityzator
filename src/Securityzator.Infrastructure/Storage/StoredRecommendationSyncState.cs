using Securityzator.Application.Recommendations;

namespace Securityzator.Infrastructure.Storage;

public sealed class StoredRecommendationSyncState
{
    public Guid ConnectionId { get; set; }

    public Guid OwnerOperatorId { get; set; }

    public RecommendationSyncStatus SyncStatus { get; set; } = RecommendationSyncStatus.NotStarted;

    public DateTimeOffset? LastAttemptUtc { get; set; }

    public DateTimeOffset? LastSuccessUtc { get; set; }

    public string? LastError { get; set; }

    public List<StoredRecommendationRecord> Recommendations { get; set; } = [];
}
