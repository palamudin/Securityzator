namespace Securityzator.Web.Models.Remediations;

public sealed class RemediationConnectionOptionViewModel
{
    public Guid Id { get; init; }

    public string DisplayName { get; init; } = string.Empty;

    public string TenantId { get; init; } = string.Empty;

    public bool HasStoredSecret { get; init; }
}
