namespace Securityzator.Infrastructure.Graph;

internal sealed record GraphSecureScoreControlProfile(
    string ControlId,
    string Title,
    string Category,
    string Product,
    int Rank,
    double MaxScore,
    string Tier,
    string ImplementationCost,
    string UserImpact,
    string ActionType,
    string Remediation,
    string RemediationImpact,
    bool IsDeprecated,
    IReadOnlyList<string> Threats);
