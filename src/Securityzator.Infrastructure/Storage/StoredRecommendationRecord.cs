namespace Securityzator.Infrastructure.Storage;

public sealed class StoredRecommendationRecord
{
    public string ControlId { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    public string Category { get; set; } = string.Empty;

    public string Product { get; set; } = string.Empty;

    public int Rank { get; set; }

    public double MaxScore { get; set; }

    public string Tier { get; set; } = string.Empty;

    public string ImplementationCost { get; set; } = string.Empty;

    public string UserImpact { get; set; } = string.Empty;

    public string ActionType { get; set; } = string.Empty;

    public string Remediation { get; set; } = string.Empty;

    public string RemediationImpact { get; set; } = string.Empty;

    public bool IsDeprecated { get; set; }

    public List<string> Threats { get; set; } = [];

    public string? RemediationTemplateKey { get; set; }
}
