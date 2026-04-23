namespace Securityzator.Application.Recommendations;

public sealed record RecommendationMappingBackfillOutcome(
    Guid ConnectionId,
    string ConnectionDisplayName,
    bool Succeeded,
    int TotalRecommendationCount,
    int UpdatedRecommendationCount,
    int RemainingMappingDriftCount,
    string Message);
