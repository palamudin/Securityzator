using Securityzator.Application.Connections;

namespace Securityzator.Web.Models.Connections;

public sealed class AzureConnectionListItemViewModel
{
    public Guid Id { get; set; }

    public string DisplayName { get; set; } = string.Empty;

    public string TenantId { get; set; } = string.Empty;

    public string ClientId { get; set; } = string.Empty;

    public string RedirectUri { get; set; } = string.Empty;

    public bool HasStoredSecret { get; set; }

    public string AutomationCertificateThumbprint { get; set; } = string.Empty;

    public string AutomationCertificateStoreLocation { get; set; } = string.Empty;

    public string AutomationCertificateStoreName { get; set; } = string.Empty;

    public AutomationCertificateStatus AutomationCertificateStatus { get; set; }

    public string? AutomationCertificateSubject { get; set; }

    public DateTimeOffset? AutomationCertificateExpiresUtc { get; set; }

    public string? AutomationCertificateMessage { get; set; }

    public DateTimeOffset UpdatedUtc { get; set; }

    public DateTimeOffset SecretUpdatedUtc { get; set; }

    public AzureConnectionValidationStatus ValidationStatus { get; set; }

    public DateTimeOffset? LastValidationAttemptUtc { get; set; }

    public DateTimeOffset? LastValidationSuccessUtc { get; set; }

    public string? LastValidationError { get; set; }

    public bool CanReadGroups { get; set; }

    public bool CanReadConditionalAccess { get; set; }

    public bool CanReadRecommendations { get; set; }

    public bool CanReadManagedDevices { get; set; }

    public bool CanReadIntuneDeviceConfigurations { get; set; }

    public bool CanReadIntuneCompliancePolicies { get; set; }

    public int IntuneEnrolledDeviceCount { get; set; }

    public bool HasIntuneDeviceConfigurations { get; set; }

    public bool HasIntuneCompliancePolicies { get; set; }

    public string? IntuneAutomationMessage { get; set; }

    public bool CanManageEntraDailyUseHardening { get; set; }

    public string? EntraDailyUseAutomationMessage { get; set; }

    public bool CanManageTeamsMeetingPolicy { get; set; }

    public string? TeamsAutomationMessage { get; set; }

    public IReadOnlyList<string> DeclaredLicenseCapabilities { get; set; } = Array.Empty<string>();

    public IReadOnlyList<string> DeclaredLicenseCapabilityLabels { get; set; } = Array.Empty<string>();
}
