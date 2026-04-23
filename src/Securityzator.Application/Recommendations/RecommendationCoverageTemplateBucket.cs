namespace Securityzator.Application.Recommendations;

public sealed record RecommendationCoverageTemplateBucket(
    string TemplateKey,
    string TemplateName,
    int ControlCount,
    bool SupportsQueueExecution);
