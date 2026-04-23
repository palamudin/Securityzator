using System.ComponentModel.DataAnnotations;
using Securityzator.Application.Connections;
using Securityzator.Application.Blueprints;

namespace Securityzator.Web.Models.Connections;

public sealed class ConnectionsPageViewModel
{
    private const string GuidPattern = "^[0-9a-fA-F]{8}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{4}\\-[0-9a-fA-F]{12}$";

    public PortalBlueprint? Blueprint { get; set; }

    public IReadOnlyList<AzureConnectionListItemViewModel> Connections { get; set; } = Array.Empty<AzureConnectionListItemViewModel>();

    public IReadOnlyList<TenantLicenseCapabilityOption> AvailableLicenseCapabilities { get; set; } = Array.Empty<TenantLicenseCapabilityOption>();

    public string OperatorDisplayName { get; set; } = string.Empty;

    public string WorkspaceName { get; set; } = string.Empty;

    public string? StatusMessage { get; set; }

    public string? ErrorMessage { get; set; }

    public Guid? Id { get; set; }

    public bool IsEditMode => Id.HasValue;

    [Required]
    [StringLength(80, MinimumLength = 3)]
    [Display(Name = "Connection name")]
    public string DisplayName { get; set; } = string.Empty;

    [Required]
    [RegularExpression(GuidPattern, ErrorMessage = "Enter a valid tenant GUID.")]
    [Display(Name = "Tenant ID")]
    public string TenantId { get; set; } = string.Empty;

    [Required]
    [RegularExpression(GuidPattern, ErrorMessage = "Enter a valid application GUID.")]
    [Display(Name = "Application ID")]
    public string ClientId { get; set; } = string.Empty;

    [Display(Name = "Client secret")]
    [DataType(DataType.Password)]
    [StringLength(256, MinimumLength = 6)]
    public string? ClientSecret { get; set; }

    [Display(Name = "Automation certificate thumbprint")]
    public string? AutomationCertificateThumbprint { get; set; }

    [Display(Name = "Certificate store location")]
    public string AutomationCertificateStoreLocation { get; set; } = "LocalMachine";

    [Display(Name = "Certificate store name")]
    public string AutomationCertificateStoreName { get; set; } = "My";

    [Required]
    [Url]
    [Display(Name = "Redirect URI")]
    public string RedirectUri { get; set; } = string.Empty;

    public List<string> SelectedLicenseCapabilities { get; set; } = [];
}
