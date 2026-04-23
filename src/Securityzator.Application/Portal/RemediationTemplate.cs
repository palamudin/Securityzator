using Securityzator.Application.Remediations;

namespace Securityzator.Application.Portal;

public sealed record RemediationTemplate(
    string Key,
    string Name,
    string Summary,
    string Methodology,
    string DeliveryMode,
    bool SupportsQueueExecution,
    IReadOnlyList<string> RequiredInputs,
    IReadOnlyList<string> Steps)
{
    public string ExecutionSurface { get; init; } = string.Empty;

    public string NextStage { get; init; } = string.Empty;

    public IReadOnlyList<string> CurrentBlockers { get; init; } = Array.Empty<string>();

    public RemediationTemplateTargeting Targeting { get; init; } =
        new("Tenant", "Targeting guidance has not been defined for this playbook yet.", false, false);

    public bool SupportsLaunchModeSelection { get; init; }

    public RemediationLaunchMode DefaultLaunchMode { get; init; } = RemediationLaunchMode.DirectApply;

    public IReadOnlyList<string> RequiredLicenseCapabilities { get; init; } = Array.Empty<string>();

    public bool HasBlockers => CurrentBlockers.Count > 0;
}
