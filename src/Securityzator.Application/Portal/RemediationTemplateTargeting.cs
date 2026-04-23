namespace Securityzator.Application.Portal;

public sealed record RemediationTemplateTargeting(
    string TargetSurface,
    string Summary,
    bool SupportsIncludeGroupSelection,
    bool SupportsExcludeGroupSelection);
