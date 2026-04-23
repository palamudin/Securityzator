namespace Securityzator.Application.Portal;

public sealed record SecurityRecommendationPreview(
    int Rank,
    string Title,
    string Category,
    string Product,
    string Status,
    string Impact,
    string RemediationTemplateKey,
    IReadOnlyList<string> Aliases);
