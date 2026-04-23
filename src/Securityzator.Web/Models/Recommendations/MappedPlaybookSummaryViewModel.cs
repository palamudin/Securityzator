using Securityzator.Application.Portal;

namespace Securityzator.Web.Models.Recommendations;

public sealed class MappedPlaybookSummaryViewModel
{
    public required string TemplateKey { get; init; }

    public required string TemplateName { get; init; }

    public required string Summary { get; init; }

    public required string DeliveryMode { get; init; }

    public bool SupportsQueueExecution { get; init; }

    public string ExecutionSurface { get; init; } = string.Empty;

    public string TargetSurface { get; init; } = string.Empty;

    public string NextStage { get; init; } = string.Empty;

    public IReadOnlyList<string> CurrentBlockers { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> RequiredLicenseCapabilityLabels { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> MissingLicenseCapabilityLabels { get; init; } = Array.Empty<string>();

    public LicenseRequirementState LicenseRequirementState { get; init; }

    public int RecommendationCount { get; init; }

    public IReadOnlyList<string> ExampleRecommendationTitles { get; init; } = Array.Empty<string>();

    public bool HasBlockers => CurrentBlockers.Count > 0;

    public bool HasLicenseRequirements => RequiredLicenseCapabilityLabels.Count > 0;

    public bool HasMissingLicenseCapabilities => MissingLicenseCapabilityLabels.Count > 0;
}
