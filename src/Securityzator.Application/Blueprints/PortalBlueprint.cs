using Securityzator.Application.Portal;

namespace Securityzator.Application.Blueprints;

public sealed record PortalBlueprint(
    string PlatformSummary,
    string DeploymentSummary,
    IReadOnlyList<ModuleCard> Modules,
    IReadOnlyList<Milestone> Milestones,
    IReadOnlyList<AzureConnectionField> ConnectionFields,
    IReadOnlyList<SecurityRecommendationPreview> RecommendationCatalog,
    IReadOnlyList<RemediationTemplate> RemediationTemplates,
    IReadOnlyList<JobCapability> JobCapabilities);
