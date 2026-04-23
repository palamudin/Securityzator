namespace Securityzator.Application.Connections;

public static class TenantLicenseCapabilityCatalog
{
    public const string EntraIdP1 = "entra-id-p1";
    public const string EntraIdP2 = "entra-id-p2";
    public const string IntunePlan1 = "intune-plan-1";
    public const string DefenderForBusiness = "defender-for-business";
    public const string DefenderForOfficePlan1 = "defender-for-office-plan-1";
    public const string DefenderForCloudApps = "defender-for-cloud-apps";
    public const string DefenderForIdentity = "defender-for-identity";
    public const string InformationProtectionPlan2 = "information-protection-plan-2";

    private static readonly IReadOnlyList<TenantLicenseCapabilityOption> CapabilityOptions =
    [
        new(
            EntraIdP1,
            "Microsoft Entra ID P1",
            "Covers the base Conditional Access and core identity controls that show up in Business Premium and many enterprise bundles."),
        new(
            EntraIdP2,
            "Microsoft Entra ID P2",
            "Unlocks Identity Protection and the higher-end risk-based identity controls."),
        new(
            IntunePlan1,
            "Intune Plan 1",
            "Unlocks device management, compliance, and the first workable path for Intune-backed endpoint controls."),
        new(
            DefenderForBusiness,
            "Defender for Business / Defender for Endpoint P2",
            "Unlocks the endpoint protection families that later feed Defender and device-hardening controls. Either Defender for Business or Defender for Endpoint Plan 2 satisfies this capability in Securityzator's current model."),
        new(
            DefenderForOfficePlan1,
            "Defender for Office 365 Plan 1",
            "Unlocks the current Defender for Office anti-phish, spam, Safe Links, and Safe Attachments control sets."),
        new(
            DefenderForCloudApps,
            "Defender for Cloud Apps",
            "Unlocks shadow IT discovery, app governance, and connected-SaaS hardening families."),
        new(
            DefenderForIdentity,
            "Defender for Identity",
            "Unlocks identity sensor onboarding and the Active Directory / AD CS hardening families."),
        new(
            InformationProtectionPlan2,
            "Information Protection P2",
            "Unlocks advanced labeling, auto-labeling, and higher-end Purview information-protection paths.")
    ];

    private static readonly IReadOnlyDictionary<string, TenantLicenseCapabilityOption> CapabilityMap =
        CapabilityOptions.ToDictionary(option => option.Key, StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<TenantLicenseCapabilityOption> All => CapabilityOptions;

    public static IReadOnlyList<string> NormalizeSelected(IEnumerable<string>? selectedKeys)
    {
        if (selectedKeys is null)
        {
            return Array.Empty<string>();
        }

        return selectedKeys
            .Select(key => key?.Trim())
            .Where(key => !string.IsNullOrWhiteSpace(key) && CapabilityMap.ContainsKey(key))
            .Select(key => CapabilityMap[key!].Key)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static IReadOnlyList<string> ResolveLabels(IEnumerable<string>? keys)
    {
        return NormalizeSelected(keys)
            .Select(key => CapabilityMap[key].Label)
            .ToArray();
    }
}
