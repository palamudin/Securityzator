namespace Securityzator.Infrastructure.Storage;

public sealed class SecurityzatorStateDocument
{
    public List<StoredOperatorAccount> Operators { get; init; } = [];

    public List<StoredAzureConnectionProfile> Connections { get; init; } = [];

    public List<StoredRecommendationSyncState> RecommendationSyncStates { get; init; } = [];

    public List<StoredRemediationRun> RemediationRuns { get; init; } = [];

    public List<StoredRemediationJob> RemediationJobs { get; init; } = [];

    public List<StoredWorkerAgent> Workers { get; init; } = [];
}
