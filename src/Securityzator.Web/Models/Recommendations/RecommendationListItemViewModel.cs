using Securityzator.Application.Portal;
using Securityzator.Application.Recommendations;

namespace Securityzator.Web.Models.Recommendations;

public sealed class RecommendationListItemViewModel
{
    public required RecommendationRecord Recommendation { get; init; }

    public string? TemplateKey { get; init; }

    public string? TemplateName { get; init; }

    public string? TemplateDeliveryMode { get; init; }

    public bool SupportsQueueExecution { get; init; }

    public string? TemplateExecutionSurface { get; init; }

    public string? TemplateTargetSurface { get; init; }

    public string? TemplateNextStage { get; init; }

    public IReadOnlyList<string> TemplateBlockers { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> RequiredLicenseCapabilityLabels { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> MissingLicenseCapabilityLabels { get; init; } = Array.Empty<string>();

    public LicenseRequirementState LicenseRequirementState { get; init; }

    public bool HasMappedTemplate => !string.IsNullOrWhiteSpace(TemplateKey);

    public bool HasTemplateBlockers => TemplateBlockers.Count > 0;

    public bool HasLicenseRequirements => RequiredLicenseCapabilityLabels.Count > 0;

    public bool HasMissingLicenseCapabilities => MissingLicenseCapabilityLabels.Count > 0;
}
