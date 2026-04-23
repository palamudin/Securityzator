namespace Securityzator.Application.Connections;

public sealed record UpdateAzureConnectionRequest(
    Guid ConnectionId,
    Guid OwnerOperatorId,
    string DisplayName,
    string TenantId,
    string ClientId,
    string? ClientSecret,
    string RedirectUri,
    string? AutomationCertificateThumbprint,
    string? AutomationCertificateStoreLocation,
    string? AutomationCertificateStoreName,
    IReadOnlyList<string>? DeclaredLicenseCapabilities);
