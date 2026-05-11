using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Securityzator.Infrastructure.Graph;

namespace Securityzator.Infrastructure.Intune;

public sealed class IntuneEndpointAutomationClient
{
    private const string CoreProtectionDisplayName = "SS-AUTO | Endpoint core protection baseline";
    private const string CoreProtectionDescription =
        "Securityzator-managed Intune baseline for core Microsoft Defender Antivirus and cloud protection settings.";
    private const string CoreProtectionHardeningDisplayName = "SS-AUTO | Endpoint core protection hardening";
    private const string CoreProtectionHardeningDescription =
        "Securityzator-managed Intune baseline for Defender network protection and tamper protection.";
    private const string FirewallAndSmartScreenDisplayName = "SS-AUTO | Endpoint firewall and SmartScreen baseline";
    private const string FirewallAndSmartScreenDescription =
        "Securityzator-managed Intune baseline for Microsoft Defender Firewall posture and Windows SmartScreen app/file protection.";
    private const string BrowserHardeningDisplayName = "SS-AUTO | Endpoint browser hardening baseline";
    private const string BrowserHardeningDescription =
        "Securityzator-managed Intune browser baseline for Google Chrome background-app behavior, AutoFill, password-manager, and third-party cookie posture.";
    private const string EdgeSmartScreenDisplayName = "SS-AUTO | Endpoint Edge SmartScreen baseline";
    private const string EdgeSmartScreenDescription =
        "Securityzator-managed Intune browser baseline for Microsoft Edge SmartScreen site, download, and potentially unwanted app protections.";
    private const string ExploitProtectionDisplayName = "SS-AUTO | Endpoint exploit protection baseline";
    private const string ExploitProtectionDescription =
        "Securityzator-managed Intune baseline for Windows system-level exploit protection settings including DEP, ASLR, Control Flow Guard, SEHOP, and heap termination on corruption.";
    private const string BitLockerBaselineDisplayName = "SS-AUTO | Endpoint BitLocker baseline";
    private const string BitLockerBaselineDescription =
        "Securityzator-managed Intune baseline for Windows device encryption and BitLocker startup authentication.";
    private const string CredentialAndElevationHardeningDisplayName = "SS-AUTO | Endpoint credential and elevation hardening";
    private const string CredentialAndElevationHardeningDescription =
        "Securityzator-managed Intune custom configuration baseline for credential isolation, WDigest disablement, credential storage restrictions, and UAC elevation hardening.";
    private const string RemoteAccessAndNetworkHardeningDisplayName = "SS-AUTO | Endpoint remote access and network hardening";
    private const string RemoteAccessAndNetworkHardeningDescription =
        "Securityzator-managed Intune custom configuration baseline for WinRM Basic authentication, Remote Assistance, network bridge, Internet Connection Sharing, SMBv1 server disablement, Remote Desktop TLS, and AutoPlay or AutoRun hardening.";
    private const string OsSecurityBaselineDisplayName = "SS-AUTO | Endpoint OS security baseline";
    private const string OsSecurityBaselineDescription =
        "Securityzator-managed Intune baseline for workstation-safe Windows local security and SMB hardening settings.";
    private const string AttackSurfaceReductionDisplayName = "SS-AUTO | Endpoint attack surface reduction baseline";
    private const string AttackSurfaceReductionDescription =
        "Securityzator-managed Intune baseline for first-wave Microsoft Defender attack surface reduction and ransomware protections.";
    private const string EnableVirtualizationBasedSecurityOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/DeviceGuard/EnableVirtualizationBasedSecurity";
    private const string CredentialGuardConfigurationOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/DeviceGuard/LsaCfgFlags";
    private const string DoNotStoreCredentialsForNetworkAuthenticationOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkAccess_DoNotAllowStorageOfPasswordsAndCredentialsForNetworkAuthentication";
    private const string RunAllAdministratorsInAdminApprovalModeOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_RunAllAdministratorsInAdminApprovalMode";
    private const string ElevationPromptForStandardUsersOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_BehaviorOfTheElevationPromptForStandardUsers";
    private const string SwitchToSecureDesktopForElevationOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_SwitchToTheSecureDesktopWhenPromptingForElevation";
    private const string OnlyElevateSignedAndValidatedExecutablesOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_OnlyElevateExecutableFilesThatAreSignedAndValidated";
    private const string ConfigureLsaProtectedProcessOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/LocalSecurityAuthority/ConfigureLsaProtectedProcess";
    private const string SafeDllSearchModeOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_SafeDllSearchMode";
    private const string EnumerateAdministratorsOnElevationOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/CredentialsUI/EnumerateAdministrators";
    private const string ApplyUacRestrictionsToLocalAccountsOnNetworkLogonOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ApplyUACRestrictionsToLocalAccountsOnNetworkLogon";
    private const string AlwaysInstallElevatedOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/ApplicationManagement/MSIAlwaysInstallWithElevatedPrivileges";
    private const string LegacyAlwaysInstallElevatedOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/ApplicationManagement/AlwaysInstallElevated";
    private const string WDigestAuthenticationOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/WDigestAuthentication";
    private const string ProhibitInstallationAndConfigurationOfNetworkBridgeOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/Connectivity/ProhibitInstallationAndConfigurationOfNetworkBridge";
    private const string RequireDomainUsersToElevateWhenSettingNetworkLocationOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/ADMX_NetworkConnections/NC_StdDomainUserSetLocation";
    private const string ProhibitInternetConnectionSharingOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/ADMX_NetworkConnections/NC_ShowSharedAccessUI";
    private const string ConfigureOfferRemoteAssistanceOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/RemoteAssistance/UnsolicitedRemoteAssistance";
    private const string ConfigureSolicitedRemoteAssistanceOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/RemoteAssistance/SolicitedRemoteAssistance";
    private const string AllowBasicAuthenticationWinRmClientOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/RemoteManagement/AllowBasicAuthentication_Client";
    private const string AllowBasicAuthenticationWinRmServiceOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/RemoteManagement/AllowBasicAuthentication_Service";
    private const string DisallowAutoplayForNonVolumeDevicesOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/Autoplay/DisallowAutoplayForNonVolumeDevices";
    private const string TurnOffAutoPlayAllDrivesOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/Autoplay/TurnOffAutoPlay";
    private const string SetDefaultAutoRunBehaviorOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/Autoplay/SetDefaultAutoRunBehavior";
    private const string ConfigureSmbV1ClientDriverOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ConfigureSMBV1ClientDriver";
    private const string ConfigureSmbV1ServerOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ConfigureSMBV1Server";
    private const string Ipv6SourceRoutingProtectionLevelOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPv6SourceRoutingProtectionLevel";
    private const string IpSourceRoutingProtectionLevelOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPSourceRoutingProtectionLevel";
    private const string RemoteDesktopSecurityLayerOmaUri =
        "./Device/Vendor/MSFT/Policy/Config/ADMX_TerminalServer/TS_SECURITY_LAYER_POLICY";
    private const string ExploitProtectionXmlFileName = "Securityzator-EndpointExploitProtection.xml";
    private const string ChromeBackgroundAppsDefinitionId = "4251950d-1abf-46b6-9eba-be6b3ab70b1c";
    private const string ChromeAutoFillAddressesDefinitionId = "f69abeca-36cd-4e7b-a1c3-8a6ab02c2338";
    private const string ChromeAutoFillCreditCardsDefinitionId = "7198ee47-7ba4-4c28-a519-8bcabac76c7f";
    private const string ChromePasswordManagerDefinitionId = "09077e39-3731-45fc-bd01-a4b5dd1776df";
    private const string ChromeThirdPartyCookiesDefinitionId = "640798da-28c3-4172-9b39-0625c293cadd";
    private const string EdgeConfigureSmartScreenDefinitionId = "f9de5937-2ff5-4c34-a5ec-d0d997787b68";
    private const string EdgePreventBypassSitesDefinitionId = "06b9c400-f1ed-4046-b8cb-02af3ae8e38d";
    private const string EdgeForceChecksDownloadsDefinitionId = "b04025c3-6b37-4e84-b68e-69f66f451b53";
    private const string EdgeBlockPotentiallyUnwantedAppsDefinitionId = "270e643f-a1dd-49eb-8365-8292e9d6c7f7";
    private static readonly IReadOnlyDictionary<string, bool> BrowserHardeningDefinitionStates =
        new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
        {
            [ChromeBackgroundAppsDefinitionId] = false,
            [ChromeAutoFillAddressesDefinitionId] = false,
            [ChromeAutoFillCreditCardsDefinitionId] = false,
            [ChromePasswordManagerDefinitionId] = false,
            [ChromeThirdPartyCookiesDefinitionId] = true
        };
    private static readonly IReadOnlyDictionary<string, bool> EdgeSmartScreenDefinitionStates =
        new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
        {
            [EdgeConfigureSmartScreenDefinitionId] = true,
            [EdgePreventBypassSitesDefinitionId] = true,
            [EdgeForceChecksDownloadsDefinitionId] = true,
            [EdgeBlockPotentiallyUnwantedAppsDefinitionId] = true
        };

    private readonly HttpClient _httpClient;
    private readonly IOptions<SecurityzatorGraphOptions> _options;

    public IntuneEndpointAutomationClient(
        HttpClient httpClient,
        IOptions<SecurityzatorGraphOptions> options)
    {
        _httpClient = httpClient;
        _options = options;
    }

    internal async Task<EndpointCoreProtectionBaselineResult> ApplyCoreProtectionBaselineAsync(
        string accessToken,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        ValidatePilotAssignment(includeGroupId, excludeGroupId, allUsersAssignment, "Endpoint core protection");

        var desiredSnapshot = CreateDesiredCoreProtectionSnapshot();
        var desiredHardeningSnapshot = CreateDesiredCoreProtectionHardeningSnapshot();
        var graphRoles = ParseGraphRoles(accessToken);
        var matchingConfigurations = await ListMatchingConfigurationsAsync(
            accessToken,
            CoreProtectionDisplayName,
            cancellationToken);
        var matchingHardeningConfigurations = await ListMatchingConfigurationsAsync(
            accessToken,
            CoreProtectionHardeningDisplayName,
            cancellationToken);

        if (matchingConfigurations.Count > 1)
        {
            throw new InvalidOperationException(
                $"Multiple Intune device configurations already use the managed name '{CoreProtectionDisplayName}'. Consolidate or remove the duplicates before Securityzator can manage this baseline safely.");
        }

        if (matchingHardeningConfigurations.Count > 1)
        {
            throw new InvalidOperationException(
                $"Multiple Intune device configurations already use the managed name '{CoreProtectionHardeningDisplayName}'. Consolidate or remove the duplicates before Securityzator can manage this baseline safely.");
        }

        var existingConfiguration = matchingConfigurations.SingleOrDefault();
        var existingHardeningConfiguration = matchingHardeningConfigurations.SingleOrDefault();
        EndpointCoreProtectionConfigurationSnapshot? before = null;
        EndpointCoreProtectionHardeningConfigurationSnapshot? hardeningBefore = null;
        var createdConfiguration = false;
        var updatedConfiguration = false;
        var updatedAssignments = false;
        var createdHardeningConfiguration = false;
        var updatedHardeningConfiguration = false;
        var updatedHardeningAssignments = false;
        string configurationId;
        string hardeningConfigurationId;

        if (existingConfiguration is null)
        {
            configurationId = await CreateConfigurationAsync(
                accessToken,
                graphRoles,
                CreateCoreProtectionPayload(),
                "Intune core protection configuration create failed",
                GetGraphBetaBaseUrl(),
                cancellationToken);
            createdConfiguration = true;
        }
        else
        {
            before = await GetConfigurationSnapshotAsync(existingConfiguration.Id, accessToken, graphRoles, cancellationToken);

            if (!string.Equals(before.ODataType, "#microsoft.graph.windows10GeneralConfiguration", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The managed Intune configuration name '{CoreProtectionDisplayName}' already exists as '{before.ODataType}'. Rename or remove that profile before Securityzator manages this baseline.");
            }

            configurationId = existingConfiguration.Id;

            if (!IsDesiredConfiguration(before, desiredSnapshot))
            {
                await UpdateConfigurationAsync(
                    configurationId,
                    accessToken,
                    graphRoles,
                    CreateCoreProtectionPayload(),
                    "Intune core protection configuration update failed",
                    GetGraphBetaBaseUrl(),
                    cancellationToken);
                updatedConfiguration = true;
            }
        }

        if (existingHardeningConfiguration is null)
        {
            hardeningConfigurationId = await CreateConfigurationAsync(
                accessToken,
                graphRoles,
                CreateCoreProtectionHardeningPayload(),
                "Intune core protection hardening create failed",
                GetGraphBetaBaseUrl(),
                cancellationToken);
            createdHardeningConfiguration = true;
        }
        else
        {
            hardeningBefore = await GetCoreProtectionHardeningConfigurationSnapshotAsync(
                existingHardeningConfiguration.Id,
                accessToken,
                graphRoles,
                cancellationToken);

            if (!string.Equals(hardeningBefore.ODataType, "#microsoft.graph.windows10EndpointProtectionConfiguration", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The managed Intune configuration name '{CoreProtectionHardeningDisplayName}' already exists as '{hardeningBefore.ODataType}'. Rename or remove that profile before Securityzator manages this baseline safely.");
            }

            hardeningConfigurationId = existingHardeningConfiguration.Id;

            if (!IsDesiredConfiguration(hardeningBefore, desiredHardeningSnapshot))
            {
                await UpdateConfigurationAsync(
                    hardeningConfigurationId,
                    accessToken,
                    graphRoles,
                    CreateCoreProtectionHardeningPayload(),
                    "Intune core protection hardening update failed",
                    GetGraphBetaBaseUrl(),
                    cancellationToken);
                updatedHardeningConfiguration = true;
            }
        }

        var currentAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);
        var assignmentsAlreadyAligned = AreAssignmentsAligned(currentAssignments, includeGroupId, excludeGroupId, allUsersAssignment);

        if (!assignmentsAlreadyAligned)
        {
            await AssignConfigurationAsync(configurationId, includeGroupId, excludeGroupId, accessToken, graphRoles, cancellationToken, allUsersAssignment);
            updatedAssignments = true;
        }

        var currentHardeningAssignments = await ListAssignmentsAsync(hardeningConfigurationId, accessToken, graphRoles, cancellationToken);
        var hardeningAssignmentsAlreadyAligned = AreAssignmentsAligned(currentHardeningAssignments, includeGroupId, excludeGroupId, allUsersAssignment);

        if (!hardeningAssignmentsAlreadyAligned)
        {
            await AssignConfigurationAsync(hardeningConfigurationId, includeGroupId, excludeGroupId, accessToken, graphRoles, cancellationToken, allUsersAssignment);
            updatedHardeningAssignments = true;
        }

        var after = await GetConfigurationSnapshotAsync(configurationId, accessToken, graphRoles, cancellationToken);
        var finalAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);
        var hardeningAfter = await GetCoreProtectionHardeningConfigurationSnapshotAsync(
            hardeningConfigurationId,
            accessToken,
            graphRoles,
            cancellationToken);
        var finalHardeningAssignments = await ListAssignmentsAsync(hardeningConfigurationId, accessToken, graphRoles, cancellationToken);

        if (!IsDesiredConfiguration(after, desiredSnapshot))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the Securityzator core protection baseline after the configuration update.");
        }

        if (!AreAssignmentsAligned(finalAssignments, includeGroupId, excludeGroupId, allUsersAssignment))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the requested include or exclusion group assignment after the baseline update.");
        }

        if (!IsDesiredConfiguration(hardeningAfter, desiredHardeningSnapshot))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the Securityzator core protection hardening baseline after the configuration update.");
        }

        if (!AreAssignmentsAligned(finalHardeningAssignments, includeGroupId, excludeGroupId, allUsersAssignment))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the requested include or exclusion group assignment after the core protection hardening update.");
        }

        var alreadyCompliant = !createdConfiguration
                               && !updatedConfiguration
                               && !updatedAssignments
                               && !createdHardeningConfiguration
                               && !updatedHardeningConfiguration
                               && !updatedHardeningAssignments;
        var notes = BuildCoreProtectionNotes(excludeGroupId);

        return new EndpointCoreProtectionBaselineResult(
            configurationId,
            hardeningConfigurationId,
            alreadyCompliant,
            createdConfiguration || createdHardeningConfiguration,
            updatedConfiguration || updatedHardeningConfiguration,
            updatedAssignments || updatedHardeningAssignments,
            before,
            after,
            finalAssignments,
            hardeningBefore,
            hardeningAfter,
            finalHardeningAssignments,
            notes);
    }

    internal async Task<EndpointFirewallAndSmartScreenBaselineResult> ApplyFirewallAndSmartScreenBaselineAsync(
        string accessToken,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        ValidatePilotAssignment(includeGroupId, excludeGroupId, allUsersAssignment, "Endpoint firewall and SmartScreen");

        var desiredSnapshot = CreateDesiredFirewallAndSmartScreenSnapshot();
        var graphRoles = ParseGraphRoles(accessToken);
        var matchingConfigurations = await ListMatchingConfigurationsAsync(
            accessToken,
            FirewallAndSmartScreenDisplayName,
            cancellationToken);
        var matchingEdgeConfigurations = await ListMatchingGroupPolicyConfigurationsAsync(
            accessToken,
            EdgeSmartScreenDisplayName,
            cancellationToken);

        if (matchingConfigurations.Count > 1)
        {
            throw new InvalidOperationException(
                $"Multiple Intune device configurations already use the managed name '{FirewallAndSmartScreenDisplayName}'. Consolidate or remove the duplicates before Securityzator can manage this baseline safely.");
        }

        if (matchingEdgeConfigurations.Count > 1)
        {
            throw new InvalidOperationException(
                $"Multiple Intune group policy configurations already use the managed name '{EdgeSmartScreenDisplayName}'. Consolidate or remove the duplicates before Securityzator can manage this baseline safely.");
        }

        var existingConfiguration = matchingConfigurations.SingleOrDefault();
        var existingEdgeConfiguration = matchingEdgeConfigurations.SingleOrDefault();
        EndpointFirewallAndSmartScreenConfigurationSnapshot? before = null;
        EndpointEdgeSmartScreenConfigurationSnapshot? edgeBefore = null;
        var createdMainConfiguration = false;
        var updatedMainConfiguration = false;
        var updatedMainAssignments = false;
        var createdEdgeConfiguration = false;
        var updatedEdgeConfiguration = false;
        var updatedEdgeAssignments = false;
        string configurationId;
        string edgeConfigurationId;

        if (existingConfiguration is null)
        {
            configurationId = await CreateConfigurationAsync(
                accessToken,
                graphRoles,
                CreateFirewallAndSmartScreenPayload(),
                "Intune firewall and SmartScreen configuration create failed",
                GetGraphBetaBaseUrl(),
                cancellationToken);
            createdMainConfiguration = true;
        }
        else
        {
            before = await GetFirewallAndSmartScreenConfigurationSnapshotAsync(
                existingConfiguration.Id,
                accessToken,
                graphRoles,
                cancellationToken);

            if (!string.Equals(before.ODataType, "#microsoft.graph.windows10EndpointProtectionConfiguration", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The managed Intune configuration name '{FirewallAndSmartScreenDisplayName}' already exists as '{before.ODataType}'. Rename or remove that profile before Securityzator manages this baseline safely.");
            }

            configurationId = existingConfiguration.Id;

            if (!IsDesiredConfiguration(before, desiredSnapshot))
            {
                await UpdateConfigurationAsync(
                    configurationId,
                    accessToken,
                    graphRoles,
                    CreateFirewallAndSmartScreenPayload(),
                    "Intune firewall and SmartScreen configuration update failed",
                    GetGraphBetaBaseUrl(),
                    cancellationToken);
                updatedMainConfiguration = true;
            }
        }

        if (existingEdgeConfiguration is null)
        {
            edgeConfigurationId = await CreateGroupPolicyConfigurationAsync(
                accessToken,
                graphRoles,
                EdgeSmartScreenDisplayName,
                EdgeSmartScreenDescription,
                cancellationToken);
            createdEdgeConfiguration = true;
            updatedEdgeConfiguration = await SyncEdgeSmartScreenDefinitionValuesAsync(
                edgeConfigurationId,
                Array.Empty<GroupPolicyDefinitionValueSnapshot>(),
                accessToken,
                graphRoles,
                cancellationToken);
        }
        else
        {
            edgeBefore = await GetEdgeSmartScreenConfigurationSnapshotAsync(
                existingEdgeConfiguration.Id,
                accessToken,
                graphRoles,
                cancellationToken);
            edgeConfigurationId = existingEdgeConfiguration.Id;

            if (!IsDesiredEdgeSmartScreenSnapshot(edgeBefore))
            {
                updatedEdgeConfiguration = await SyncEdgeSmartScreenDefinitionValuesAsync(
                    edgeConfigurationId,
                    edgeBefore.DefinitionValues,
                    accessToken,
                    graphRoles,
                    cancellationToken);
            }
        }

        var currentAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);
        var assignmentsAlreadyAligned = AreAssignmentsAligned(currentAssignments, includeGroupId, excludeGroupId, allUsersAssignment);

        if (!assignmentsAlreadyAligned)
        {
            await AssignConfigurationAsync(configurationId, includeGroupId, excludeGroupId, accessToken, graphRoles, cancellationToken, allUsersAssignment);
            updatedMainAssignments = true;
        }

        var currentEdgeAssignments = await ListGroupPolicyAssignmentsAsync(edgeConfigurationId, accessToken, graphRoles, cancellationToken);
        var edgeAssignmentsAlreadyAligned = AreAssignmentsAligned(currentEdgeAssignments, includeGroupId, excludeGroupId, allUsersAssignment);

        if (!edgeAssignmentsAlreadyAligned)
        {
            await AssignGroupPolicyConfigurationAsync(edgeConfigurationId, includeGroupId, excludeGroupId, accessToken, graphRoles, cancellationToken, allUsersAssignment);
            updatedEdgeAssignments = true;
        }

        var after = await GetFirewallAndSmartScreenConfigurationSnapshotAsync(
            configurationId,
            accessToken,
            graphRoles,
            cancellationToken);
        var finalAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);
        var edgeAfter = await GetEdgeSmartScreenConfigurationSnapshotAsync(
            edgeConfigurationId,
            accessToken,
            graphRoles,
            cancellationToken);
        var finalEdgeAssignments = await ListGroupPolicyAssignmentsAsync(edgeConfigurationId, accessToken, graphRoles, cancellationToken);

        if (!IsDesiredConfiguration(after, desiredSnapshot))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the Securityzator firewall and SmartScreen baseline after the configuration update.");
        }

        if (!AreAssignmentsAligned(finalAssignments, includeGroupId, excludeGroupId, allUsersAssignment))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the requested include or exclusion group assignment after the baseline update.");
        }

        if (!IsDesiredEdgeSmartScreenSnapshot(edgeAfter))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the Securityzator Edge SmartScreen companion baseline after the configuration update.");
        }

        if (!AreAssignmentsAligned(finalEdgeAssignments, includeGroupId, excludeGroupId, allUsersAssignment))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the requested include or exclusion group assignment after the Edge SmartScreen update.");
        }

        var createdConfiguration = createdMainConfiguration || createdEdgeConfiguration;
        var updatedConfiguration = updatedMainConfiguration || updatedEdgeConfiguration;
        var updatedAssignments = updatedMainAssignments || updatedEdgeAssignments;
        var alreadyCompliant = !createdConfiguration && !updatedConfiguration && !updatedAssignments;
        var notes = BuildFirewallAndSmartScreenNotes(excludeGroupId);

        return new EndpointFirewallAndSmartScreenBaselineResult(
            configurationId,
            edgeConfigurationId,
            alreadyCompliant,
            createdConfiguration,
            updatedConfiguration,
            updatedAssignments,
            before,
            after,
            finalAssignments,
            edgeBefore,
            edgeAfter,
            finalEdgeAssignments,
            notes);
    }

    internal async Task<EndpointExploitProtectionBaselineResult> ApplyExploitProtectionBaselineAsync(
        string accessToken,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        ValidatePilotAssignment(includeGroupId, excludeGroupId, allUsersAssignment, "Endpoint exploit protection");

        var desiredSnapshot = CreateDesiredExploitProtectionSnapshot();
        var graphRoles = ParseGraphRoles(accessToken);
        var matchingConfigurations = await ListMatchingConfigurationsAsync(
            accessToken,
            ExploitProtectionDisplayName,
            cancellationToken);

        if (matchingConfigurations.Count > 1)
        {
            throw new InvalidOperationException(
                $"Multiple Intune device configurations already use the managed name '{ExploitProtectionDisplayName}'. Consolidate or remove the duplicates before Securityzator can manage this baseline safely.");
        }

        var existingConfiguration = matchingConfigurations.SingleOrDefault();
        EndpointExploitProtectionConfigurationSnapshot? before = null;
        var createdConfiguration = false;
        var updatedConfiguration = false;
        var updatedAssignments = false;
        string configurationId;

        if (existingConfiguration is null)
        {
            configurationId = await CreateConfigurationAsync(
                accessToken,
                graphRoles,
                CreateExploitProtectionPayload(),
                "Intune exploit protection configuration create failed",
                GetGraphBetaBaseUrl(),
                cancellationToken);
            createdConfiguration = true;
        }
        else
        {
            before = await GetExploitProtectionConfigurationSnapshotAsync(
                existingConfiguration.Id,
                accessToken,
                graphRoles,
                cancellationToken);

            if (!string.Equals(before.ODataType, "#microsoft.graph.windows10EndpointProtectionConfiguration", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The managed Intune configuration name '{ExploitProtectionDisplayName}' already exists as '{before.ODataType}'. Rename or remove that profile before Securityzator manages this baseline safely.");
            }

            configurationId = existingConfiguration.Id;

            if (!IsDesiredConfiguration(before, desiredSnapshot))
            {
                await UpdateConfigurationAsync(
                    configurationId,
                    accessToken,
                    graphRoles,
                    CreateExploitProtectionPayload(),
                    "Intune exploit protection configuration update failed",
                    GetGraphBetaBaseUrl(),
                    cancellationToken);
                updatedConfiguration = true;
            }
        }

        var currentAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);
        var assignmentsAlreadyAligned = AreAssignmentsAligned(currentAssignments, includeGroupId, excludeGroupId, allUsersAssignment);

        if (!assignmentsAlreadyAligned)
        {
            await AssignConfigurationAsync(configurationId, includeGroupId, excludeGroupId, accessToken, graphRoles, cancellationToken, allUsersAssignment);
            updatedAssignments = true;
        }

        var after = await GetExploitProtectionConfigurationSnapshotAsync(
            configurationId,
            accessToken,
            graphRoles,
            cancellationToken);
        var finalAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);

        if (!IsDesiredConfiguration(after, desiredSnapshot))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the Securityzator exploit protection baseline after the configuration update.");
        }

        if (!AreAssignmentsAligned(finalAssignments, includeGroupId, excludeGroupId, allUsersAssignment))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the requested include or exclusion group assignment after the exploit protection baseline update.");
        }

        var alreadyCompliant = !createdConfiguration && !updatedConfiguration && !updatedAssignments;
        var notes = BuildExploitProtectionNotes(excludeGroupId);

        return new EndpointExploitProtectionBaselineResult(
            configurationId,
            alreadyCompliant,
            createdConfiguration,
            updatedConfiguration,
            updatedAssignments,
            before,
            after,
            finalAssignments,
            notes);
    }

    internal async Task<EndpointBitLockerBaselineResult> ApplyBitLockerBaselineAsync(
        string accessToken,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        ValidatePilotAssignment(includeGroupId, excludeGroupId, allUsersAssignment, "Endpoint BitLocker");

        var desiredSnapshot = CreateDesiredBitLockerSnapshot();
        var graphRoles = ParseGraphRoles(accessToken);
        var matchingConfigurations = await ListMatchingConfigurationsAsync(
            accessToken,
            BitLockerBaselineDisplayName,
            cancellationToken);

        if (matchingConfigurations.Count > 1)
        {
            throw new InvalidOperationException(
                $"Multiple Intune device configurations already use the managed name '{BitLockerBaselineDisplayName}'. Consolidate or remove the duplicates before Securityzator can manage this baseline safely.");
        }

        var existingConfiguration = matchingConfigurations.SingleOrDefault();
        EndpointBitLockerConfigurationSnapshot? before = null;
        var createdConfiguration = false;
        var updatedConfiguration = false;
        var updatedAssignments = false;
        string configurationId;

        if (existingConfiguration is null)
        {
            configurationId = await CreateConfigurationAsync(
                accessToken,
                graphRoles,
                CreateBitLockerPayload(),
                "Intune BitLocker configuration create failed",
                GetGraphBetaBaseUrl(),
                cancellationToken);
            createdConfiguration = true;
        }
        else
        {
            before = await GetBitLockerConfigurationSnapshotAsync(
                existingConfiguration.Id,
                accessToken,
                graphRoles,
                cancellationToken);

            if (!string.Equals(before.ODataType, "#microsoft.graph.windows10EndpointProtectionConfiguration", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The managed Intune configuration name '{BitLockerBaselineDisplayName}' already exists as '{before.ODataType}'. Rename or remove that profile before Securityzator manages this baseline safely.");
            }

            configurationId = existingConfiguration.Id;

            if (!IsDesiredConfiguration(before, desiredSnapshot))
            {
                await UpdateConfigurationAsync(
                    configurationId,
                    accessToken,
                    graphRoles,
                    CreateBitLockerPayload(),
                    "Intune BitLocker configuration update failed",
                    GetGraphBetaBaseUrl(),
                    cancellationToken);
                updatedConfiguration = true;
            }
        }

        var currentAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);
        var assignmentsAlreadyAligned = AreAssignmentsAligned(currentAssignments, includeGroupId, excludeGroupId, allUsersAssignment);

        if (!assignmentsAlreadyAligned)
        {
            await AssignConfigurationAsync(configurationId, includeGroupId, excludeGroupId, accessToken, graphRoles, cancellationToken, allUsersAssignment);
            updatedAssignments = true;
        }

        var after = await GetBitLockerConfigurationSnapshotAsync(
            configurationId,
            accessToken,
            graphRoles,
            cancellationToken);
        var finalAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);

        if (!IsDesiredConfiguration(after, desiredSnapshot))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the Securityzator BitLocker baseline after the configuration update.");
        }

        if (!AreAssignmentsAligned(finalAssignments, includeGroupId, excludeGroupId, allUsersAssignment))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the requested include or exclusion group assignment after the baseline update.");
        }

        var alreadyCompliant = !createdConfiguration && !updatedConfiguration && !updatedAssignments;
        var notes = BuildBitLockerNotes(excludeGroupId);

        return new EndpointBitLockerBaselineResult(
            configurationId,
            alreadyCompliant,
            createdConfiguration,
            updatedConfiguration,
            updatedAssignments,
            before,
            after,
            finalAssignments,
            notes);
    }

    internal async Task<EndpointCredentialAndElevationHardeningBaselineResult> ApplyCredentialAndElevationHardeningBaselineAsync(
        string accessToken,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        ValidatePilotAssignment(includeGroupId, excludeGroupId, allUsersAssignment, "Endpoint credential and elevation hardening");

        var desiredSnapshot = CreateDesiredCredentialAndElevationHardeningSnapshot();
        var graphRoles = ParseGraphRoles(accessToken);
        var matchingConfigurations = await ListMatchingConfigurationsAsync(
            accessToken,
            CredentialAndElevationHardeningDisplayName,
            cancellationToken);

        if (matchingConfigurations.Count > 1)
        {
            throw new InvalidOperationException(
                $"Multiple Intune device configurations already use the managed name '{CredentialAndElevationHardeningDisplayName}'. Consolidate or remove the duplicates before Securityzator can manage this baseline safely.");
        }

        var existingConfiguration = matchingConfigurations.SingleOrDefault();
        EndpointCredentialAndElevationConfigurationSnapshot? before = null;
        var createdConfiguration = false;
        var updatedConfiguration = false;
        var updatedAssignments = false;
        string configurationId;

        if (existingConfiguration is null)
        {
            configurationId = await CreateConfigurationAsync(
                accessToken,
                graphRoles,
                CreateCredentialAndElevationHardeningPayload(),
                "Intune credential and elevation hardening create failed",
                null,
                cancellationToken);
            createdConfiguration = true;
        }
        else
        {
            before = await GetCredentialAndElevationConfigurationSnapshotAsync(
                existingConfiguration.Id,
                accessToken,
                graphRoles,
                cancellationToken);

            if (!string.Equals(before.ODataType, "#microsoft.graph.windows10CustomConfiguration", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The managed Intune configuration name '{CredentialAndElevationHardeningDisplayName}' already exists as '{before.ODataType}'. Rename or remove that profile before Securityzator manages this baseline safely.");
            }

            configurationId = existingConfiguration.Id;

            if (!IsDesiredConfiguration(before, desiredSnapshot))
            {
                await UpdateConfigurationAsync(
                    configurationId,
                    accessToken,
                    graphRoles,
                    CreateCredentialAndElevationHardeningPayload(),
                    "Intune credential and elevation hardening update failed",
                    null,
                    cancellationToken);
                updatedConfiguration = true;
            }
        }

        var currentAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);
        var assignmentsAlreadyAligned = AreAssignmentsAligned(currentAssignments, includeGroupId, excludeGroupId, allUsersAssignment);

        if (!assignmentsAlreadyAligned)
        {
            await AssignConfigurationAsync(configurationId, includeGroupId, excludeGroupId, accessToken, graphRoles, cancellationToken, allUsersAssignment);
            updatedAssignments = true;
        }

        var after = await GetCredentialAndElevationConfigurationSnapshotAsync(
            configurationId,
            accessToken,
            graphRoles,
            cancellationToken);
        var finalAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);

        if (!IsDesiredConfiguration(after, desiredSnapshot))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the Securityzator credential and elevation hardening baseline after the configuration update.");
        }

        if (!AreAssignmentsAligned(finalAssignments, includeGroupId, excludeGroupId, allUsersAssignment))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the requested include or exclusion group assignment after the baseline update.");
        }

        var alreadyCompliant = !createdConfiguration && !updatedConfiguration && !updatedAssignments;
        var notes = BuildCredentialAndElevationHardeningNotes(excludeGroupId);

        return new EndpointCredentialAndElevationHardeningBaselineResult(
            configurationId,
            alreadyCompliant,
            createdConfiguration,
            updatedConfiguration,
            updatedAssignments,
            before,
            after,
            finalAssignments,
            notes);
    }

    internal async Task<EndpointRemoteAccessAndNetworkHardeningBaselineResult> ApplyRemoteAccessAndNetworkHardeningBaselineAsync(
        string accessToken,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        ValidatePilotAssignment(includeGroupId, excludeGroupId, allUsersAssignment, "Endpoint remote access and network hardening");

        var desiredSnapshot = CreateDesiredRemoteAccessAndNetworkHardeningSnapshot();
        var graphRoles = ParseGraphRoles(accessToken);
        var matchingConfigurations = await ListMatchingConfigurationsAsync(
            accessToken,
            RemoteAccessAndNetworkHardeningDisplayName,
            cancellationToken);

        if (matchingConfigurations.Count > 1)
        {
            throw new InvalidOperationException(
                $"Multiple Intune device configurations already use the managed name '{RemoteAccessAndNetworkHardeningDisplayName}'. Consolidate or remove the duplicates before Securityzator can manage this baseline safely.");
        }

        var existingConfiguration = matchingConfigurations.SingleOrDefault();
        EndpointRemoteAccessAndNetworkHardeningConfigurationSnapshot? before = null;
        var createdConfiguration = false;
        var updatedConfiguration = false;
        var updatedAssignments = false;
        string configurationId;

        if (existingConfiguration is null)
        {
            configurationId = await CreateConfigurationAsync(
                accessToken,
                graphRoles,
                CreateRemoteAccessAndNetworkHardeningPayload(),
                "Intune remote access and network hardening create failed",
                null,
                cancellationToken);
            createdConfiguration = true;
        }
        else
        {
            before = await GetRemoteAccessAndNetworkHardeningConfigurationSnapshotAsync(
                existingConfiguration.Id,
                accessToken,
                graphRoles,
                cancellationToken);

            if (!string.Equals(before.ODataType, "#microsoft.graph.windows10CustomConfiguration", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The managed Intune configuration name '{RemoteAccessAndNetworkHardeningDisplayName}' already exists as '{before.ODataType}'. Rename or remove that profile before Securityzator manages this baseline safely.");
            }

            configurationId = existingConfiguration.Id;

            if (!IsDesiredConfiguration(before, desiredSnapshot))
            {
                await UpdateConfigurationAsync(
                    configurationId,
                    accessToken,
                    graphRoles,
                    CreateRemoteAccessAndNetworkHardeningPayload(),
                    "Intune remote access and network hardening update failed",
                    null,
                    cancellationToken);
                updatedConfiguration = true;
            }
        }

        var currentAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);
        var assignmentsAlreadyAligned = AreAssignmentsAligned(currentAssignments, includeGroupId, excludeGroupId, allUsersAssignment);

        if (!assignmentsAlreadyAligned)
        {
            await AssignConfigurationAsync(configurationId, includeGroupId, excludeGroupId, accessToken, graphRoles, cancellationToken, allUsersAssignment);
            updatedAssignments = true;
        }

        var after = await GetRemoteAccessAndNetworkHardeningConfigurationSnapshotAsync(
            configurationId,
            accessToken,
            graphRoles,
            cancellationToken);
        var finalAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);

        if (!IsDesiredConfiguration(after, desiredSnapshot))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the Securityzator remote access and network hardening baseline after the configuration update.");
        }

        if (!AreAssignmentsAligned(finalAssignments, includeGroupId, excludeGroupId, allUsersAssignment))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the requested include or exclusion group assignment after the baseline update.");
        }

        var alreadyCompliant = !createdConfiguration && !updatedConfiguration && !updatedAssignments;
        var notes = BuildRemoteAccessAndNetworkHardeningNotes(excludeGroupId);

        return new EndpointRemoteAccessAndNetworkHardeningBaselineResult(
            configurationId,
            alreadyCompliant,
            createdConfiguration,
            updatedConfiguration,
            updatedAssignments,
            before,
            after,
            finalAssignments,
            notes);
    }

    internal async Task<EndpointBrowserHardeningBaselineResult> ApplyBrowserHardeningBaselineAsync(
        string accessToken,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        ValidatePilotAssignment(includeGroupId, excludeGroupId, allUsersAssignment, "Endpoint browser hardening");

        var graphRoles = ParseGraphRoles(accessToken);
        var matchingConfigurations = await ListMatchingGroupPolicyConfigurationsAsync(
            accessToken,
            BrowserHardeningDisplayName,
            cancellationToken);

        if (matchingConfigurations.Count > 1)
        {
            throw new InvalidOperationException(
                $"Multiple Intune group policy configurations already use the managed name '{BrowserHardeningDisplayName}'. Consolidate or remove the duplicates before Securityzator can manage this baseline safely.");
        }

        var existingConfiguration = matchingConfigurations.SingleOrDefault();
        EndpointBrowserHardeningConfigurationSnapshot? before = null;
        var createdConfiguration = false;
        var updatedConfiguration = false;
        var updatedAssignments = false;
        string configurationId;

        if (existingConfiguration is null)
        {
            configurationId = await CreateGroupPolicyConfigurationAsync(
                accessToken,
                graphRoles,
                BrowserHardeningDisplayName,
                BrowserHardeningDescription,
                cancellationToken);
            createdConfiguration = true;
            updatedConfiguration = await SyncBrowserHardeningDefinitionValuesAsync(
                configurationId,
                Array.Empty<GroupPolicyDefinitionValueSnapshot>(),
                accessToken,
                graphRoles,
                cancellationToken);
        }
        else
        {
            before = await GetBrowserHardeningConfigurationSnapshotAsync(
                existingConfiguration.Id,
                accessToken,
                graphRoles,
                cancellationToken);
            configurationId = existingConfiguration.Id;

            if (!IsDesiredBrowserHardeningSnapshot(before))
            {
                updatedConfiguration = await SyncBrowserHardeningDefinitionValuesAsync(
                    configurationId,
                    before.DefinitionValues,
                    accessToken,
                    graphRoles,
                    cancellationToken);
            }
        }

        var currentAssignments = await ListGroupPolicyAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);
        var assignmentsAlreadyAligned = AreAssignmentsAligned(currentAssignments, includeGroupId, excludeGroupId, allUsersAssignment);

        if (!assignmentsAlreadyAligned)
        {
            await AssignGroupPolicyConfigurationAsync(configurationId, includeGroupId, excludeGroupId, accessToken, graphRoles, cancellationToken, allUsersAssignment);
            updatedAssignments = true;
        }

        var after = await GetBrowserHardeningConfigurationSnapshotAsync(configurationId, accessToken, graphRoles, cancellationToken);
        var finalAssignments = await ListGroupPolicyAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);

        if (!IsDesiredBrowserHardeningSnapshot(after))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the Securityzator browser hardening baseline after the configuration update.");
        }

        if (!AreAssignmentsAligned(finalAssignments, includeGroupId, excludeGroupId, allUsersAssignment))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the requested include or exclusion group assignment after the browser hardening update.");
        }

        var alreadyCompliant = !createdConfiguration && !updatedConfiguration && !updatedAssignments;
        var notes = BuildBrowserHardeningNotes(excludeGroupId);

        return new EndpointBrowserHardeningBaselineResult(
            configurationId,
            alreadyCompliant,
            createdConfiguration,
            updatedConfiguration,
            updatedAssignments,
            before,
            after,
            finalAssignments,
            notes);
    }

    internal async Task<EndpointSensorAndAgentHealthAssessmentResult> AssessEndpointSensorAndAgentHealthAsync(
        string accessToken,
        string includeGroupId,
        IReadOnlyCollection<string> includeUserIds,
        IReadOnlyCollection<string> includeDeviceIds,
        IReadOnlyCollection<string> excludeUserIds,
        IReadOnlyCollection<string> excludeDeviceIds,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        var graphRoles = ParseGraphRoles(accessToken);
        var onboardingPolicies = await ListEndpointDetectionAndResponsePoliciesAsync(accessToken, graphRoles, cancellationToken);
        var managedDevices = await ListManagedWindowsDevicesAsync(accessToken, graphRoles, cancellationToken);
        var scopedDevices = managedDevices
            .Where(device => IsScopedDevice(device, includeUserIds, includeDeviceIds, excludeUserIds, excludeDeviceIds))
            .OrderBy(device => device.DeviceName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(device => device.ManagedDeviceId, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var onboardingPolicyAssessments = new List<EndpointEdrOnboardingPolicyAssessment>(onboardingPolicies.Count);

        foreach (var policy in onboardingPolicies)
        {
            var assignments = await ListConfigurationPolicyAssignmentsAsync(
                policy.PolicyId,
                accessToken,
                graphRoles,
                cancellationToken);
            var targetsPilotScope = assignments.Any(target => TargetsPilotScope(target, includeGroupId));
            var hasBroadAssignment = assignments.Any(IsBroadAssignmentTarget);

            onboardingPolicyAssessments.Add(new EndpointEdrOnboardingPolicyAssessment(
                policy.PolicyId,
                policy.Name,
                policy.TemplateFamily,
                policy.TemplateDisplayName,
                policy.IsAssigned,
                targetsPilotScope,
                hasBroadAssignment,
                assignments));
        }

        var findings = new List<ManagedWindowsDeviceHealthAssessment>(scopedDevices.Length);
        var nowUtc = DateTimeOffset.UtcNow;

        foreach (var device in scopedDevices)
        {
            var protectionState = await GetManagedDeviceWindowsProtectionStateAsync(
                device.ManagedDeviceId,
                accessToken,
                graphRoles,
                cancellationToken);
            var issues = new List<string>();

            if (protectionState is null)
            {
                issues.Add("No Windows protection state was returned for this managed device.");
            }
            else
            {
                if (!protectionState.MalwareProtectionEnabled || !protectionState.RealTimeProtectionEnabled)
                {
                    issues.Add("Microsoft Defender protection is not fully enabled.");
                }

                if (!protectionState.NetworkInspectionSystemEnabled)
                {
                    issues.Add("Network inspection is not enabled.");
                }

                if (protectionState.SignatureUpdateOverdue)
                {
                    issues.Add("Microsoft Defender signatures are overdue.");
                }

                if (string.IsNullOrWhiteSpace(protectionState.EngineVersion)
                    || string.IsNullOrWhiteSpace(protectionState.AntiMalwareVersion))
                {
                    issues.Add("Microsoft Defender core component version data was not returned.");
                }

                if (protectionState.LastReportedDateTime is null)
                {
                    issues.Add("Microsoft Defender telemetry has not reported a recent protection timestamp.");
                }
                else if (nowUtc - protectionState.LastReportedDateTime.Value > TimeSpan.FromHours(24))
                {
                    issues.Add("Microsoft Defender telemetry is stale.");
                }

                if (protectionState.RebootRequired)
                {
                    issues.Add("A device reboot is required before protection health is fully current.");
                }

                if (!string.IsNullOrWhiteSpace(protectionState.ProductStatus)
                    && !string.Equals(protectionState.ProductStatus, "noStatusFlagsSet", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add($"Microsoft Defender product status reported '{protectionState.ProductStatus}'.");
                }
            }

            if (device.LastSyncDateTime is null)
            {
                issues.Add("The device has not reported an Intune sync timestamp.");
            }
            else if (nowUtc - device.LastSyncDateTime.Value > TimeSpan.FromHours(24))
            {
                issues.Add("The device has not synced to Intune in the last 24 hours.");
            }

            findings.Add(new ManagedWindowsDeviceHealthAssessment(
                device.ManagedDeviceId,
                device.DeviceName,
                device.UserId,
                device.AzureAdDeviceId,
                device.LastSyncDateTime,
                protectionState,
                issues));
        }

        var healthyDeviceCount = findings.Count(item => item.IsHealthy);
        var hasHealthyTelemetry = healthyDeviceCount > 0;
        var scopedOnboardingPolicyCount = onboardingPolicyAssessments.Count(policy => policy.TargetsPilotScope || policy.HasBroadAssignment);
        var wslPluginReadiness = BuildWslPluginReadinessAssessment(
            hasHealthyTelemetry,
            scopedOnboardingPolicyCount,
            findings.Count);
        var notes = BuildEndpointSensorAndAgentHealthNotes(
            excludeGroupId,
            findings.Count,
            onboardingPolicyAssessments.Count,
            scopedOnboardingPolicyCount,
            hasHealthyTelemetry,
            wslPluginReadiness);

        return new EndpointSensorAndAgentHealthAssessmentResult(
            findings.Count,
            healthyDeviceCount,
            findings.Count - healthyDeviceCount,
            findings.Count > 0 && healthyDeviceCount == findings.Count,
            findings,
            onboardingPolicyAssessments,
            wslPluginReadiness,
            notes);
    }

    internal async Task<EndpointBitLockerDeploymentAssessmentResult> AssessBitLockerDeploymentStateAsync(
        string accessToken,
        IReadOnlyCollection<string> includeUserIds,
        IReadOnlyCollection<string> includeDeviceIds,
        IReadOnlyCollection<string> excludeUserIds,
        IReadOnlyCollection<string> excludeDeviceIds,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        var graphRoles = ParseGraphRoles(accessToken);
        var managedWindowsDevices = await ListManagedWindowsDevicesAsync(accessToken, graphRoles, cancellationToken);
        var encryptionStates = await ListManagedDeviceEncryptionStatesAsync(accessToken, graphRoles, cancellationToken);
        var encryptionStateLookup = encryptionStates
            .Where(state => !string.IsNullOrWhiteSpace(state.ManagedDeviceId))
            .ToDictionary(state => state.ManagedDeviceId, StringComparer.OrdinalIgnoreCase);
        var scopedDevices = managedWindowsDevices
            .Where(device => IsScopedDevice(device, includeUserIds, includeDeviceIds, excludeUserIds, excludeDeviceIds))
            .OrderBy(device => device.DeviceName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var nowUtc = DateTimeOffset.UtcNow;
        var findings = new List<ManagedWindowsBitLockerAssessment>(scopedDevices.Length);

        foreach (var device in scopedDevices)
        {
            encryptionStateLookup.TryGetValue(device.ManagedDeviceId, out var encryptionState);
            var issues = new List<string>();

            if (encryptionState is null)
            {
                issues.Add("Intune has not reported BitLocker encryption telemetry for this device yet.");
            }
            else
            {
                if (!string.Equals(encryptionState.EncryptionState, "encrypted", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add($"BitLocker encryption state is '{encryptionState.EncryptionState}'.");
                }

                if (!string.Equals(encryptionState.EncryptionPolicySettingState, "compliant", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(encryptionState.EncryptionPolicySettingState, "remediated", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add($"BitLocker policy setting state is '{encryptionState.EncryptionPolicySettingState}'.");
                }

                if (!string.Equals(encryptionState.EncryptionReadinessState, "ready", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add($"BitLocker encryption readiness is '{encryptionState.EncryptionReadinessState}'.");
                }

                if (!string.IsNullOrWhiteSpace(encryptionState.AdvancedBitLockerStates)
                    && !string.Equals(encryptionState.AdvancedBitLockerStates, "success", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add($"Advanced BitLocker state is '{encryptionState.AdvancedBitLockerStates}'.");
                }

                if (encryptionState.PolicyNames.Count == 0)
                {
                    issues.Add("No BitLocker policy assignment has reported for this device yet.");
                }
                else if (!encryptionState.PolicyNames.Contains(BitLockerBaselineDisplayName, StringComparer.OrdinalIgnoreCase))
                {
                    issues.Add($"Reported BitLocker policy assignment does not yet include '{BitLockerBaselineDisplayName}'.");
                }
            }

            if (device.LastSyncDateTime is null)
            {
                issues.Add("The device has not reported an Intune sync timestamp.");
            }
            else if (nowUtc - device.LastSyncDateTime.Value > TimeSpan.FromHours(24))
            {
                issues.Add("The device has not synced to Intune in the last 24 hours.");
            }

            findings.Add(new ManagedWindowsBitLockerAssessment(
                device.ManagedDeviceId,
                device.DeviceName,
                device.UserId,
                device.AzureAdDeviceId,
                device.LastSyncDateTime,
                encryptionState,
                issues));
        }

        var healthyDeviceCount = findings.Count(item => item.IsHealthy);
        var notes = BuildBitLockerDeploymentAssessmentNotes(excludeGroupId, findings.Count);

        return new EndpointBitLockerDeploymentAssessmentResult(
            findings.Count,
            healthyDeviceCount,
            findings.Count - healthyDeviceCount,
            findings.Count > 0 && healthyDeviceCount == findings.Count,
            findings,
            notes);
    }

    internal async Task<EndpointBrowserAndAdobePolicySurfaceAssessmentResult> AssessBrowserAndAdobePolicySurfaceAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var graphRoles = ParseGraphRoles(accessToken);
        var groupPolicyDefinitions = await ListGroupPolicyDefinitionsAsync(accessToken, graphRoles, cancellationToken);
        var uploadedDefinitionFiles = await ListGroupPolicyUploadedDefinitionFilesAsync(accessToken, graphRoles, cancellationToken);

        var chromeOutdatedPluginDefinitions = groupPolicyDefinitions
            .Where(definition =>
                definition.DisplayName.Contains("Allow running plugins that are outdated", StringComparison.OrdinalIgnoreCase)
                || definition.DisplayName.Contains("outdated", StringComparison.OrdinalIgnoreCase)
                    && definition.DisplayName.Contains("plugin", StringComparison.OrdinalIgnoreCase))
            .OrderBy(definition => definition.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var adobeUploadedDefinitionFiles = uploadedDefinitionFiles
            .Where(file =>
                file.DisplayName.Contains("adobe", StringComparison.OrdinalIgnoreCase)
                || file.DisplayName.Contains("acrobat", StringComparison.OrdinalIgnoreCase)
                || file.DisplayName.Contains("reader", StringComparison.OrdinalIgnoreCase)
                || file.FileName.Contains("adobe", StringComparison.OrdinalIgnoreCase)
                || file.FileName.Contains("acrobat", StringComparison.OrdinalIgnoreCase)
                || file.FileName.Contains("reader", StringComparison.OrdinalIgnoreCase))
            .OrderBy(file => file.FileName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var adobeJavascriptOrFlashDefinitions = groupPolicyDefinitions
            .Where(definition =>
                (definition.DisplayName.Contains("adobe", StringComparison.OrdinalIgnoreCase)
                 || definition.DisplayName.Contains("acrobat", StringComparison.OrdinalIgnoreCase)
                 || definition.DisplayName.Contains("reader", StringComparison.OrdinalIgnoreCase)
                 || definition.CategoryPath.Contains("adobe", StringComparison.OrdinalIgnoreCase)
                 || definition.CategoryPath.Contains("acrobat", StringComparison.OrdinalIgnoreCase)
                 || definition.CategoryPath.Contains("reader", StringComparison.OrdinalIgnoreCase))
                && (definition.DisplayName.Contains("javascript", StringComparison.OrdinalIgnoreCase)
                    || definition.DisplayName.Contains("flash", StringComparison.OrdinalIgnoreCase)))
            .OrderBy(definition => definition.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var findings = new List<EndpointBrowserAndAdobePolicySurfaceFinding>(2);

        findings.Add(chromeOutdatedPluginDefinitions.Length == 0
            ? new EndpointBrowserAndAdobePolicySurfaceFinding(
                "Chrome outdated plug-in policy surface",
                false,
                "Intune did not expose a durable Chrome group policy definition for 'Allow running plugins that are outdated' on this tenant.",
                Array.Empty<string>())
            : new EndpointBrowserAndAdobePolicySurfaceFinding(
                "Chrome outdated plug-in policy surface",
                true,
                "Intune exposed a Chrome group policy definition for the outdated plug-in control.",
                chromeOutdatedPluginDefinitions
                    .Select(definition => $"{definition.DisplayName} ({definition.Id})")
                    .ToArray()));

        if (adobeUploadedDefinitionFiles.Length == 0)
        {
            findings.Add(new EndpointBrowserAndAdobePolicySurfaceFinding(
                "Adobe Acrobat or Reader policy surface",
                false,
                "No Adobe Acrobat or Reader ADMX definition files are uploaded in Intune, so Adobe JavaScript and Flash controls are not currently automatable from the app-only lane.",
                Array.Empty<string>()));
        }
        else if (adobeJavascriptOrFlashDefinitions.Length == 0)
        {
            findings.Add(new EndpointBrowserAndAdobePolicySurfaceFinding(
                "Adobe Acrobat or Reader policy surface",
                false,
                "Adobe definition files are present, but no Adobe JavaScript or Flash group policy definitions surfaced for automation.",
                adobeUploadedDefinitionFiles
                    .Select(file => $"{file.FileName} ({file.Status})")
                    .ToArray()));
        }
        else
        {
            findings.Add(new EndpointBrowserAndAdobePolicySurfaceFinding(
                "Adobe Acrobat or Reader policy surface",
                true,
                "Adobe ADMX-backed policy definitions for JavaScript or Flash are present in Intune.",
                adobeJavascriptOrFlashDefinitions
                    .Select(definition => $"{definition.DisplayName} ({definition.Id})")
                    .ToArray()));
        }

        var readySurfaceCount = findings.Count(finding => finding.IsReady);
        var notes = BuildBrowserAndAdobePolicySurfaceNotes(
            chromeOutdatedPluginDefinitions.Length,
            adobeUploadedDefinitionFiles.Length,
            adobeJavascriptOrFlashDefinitions.Length);

        return new EndpointBrowserAndAdobePolicySurfaceAssessmentResult(
            findings.Count,
            readySurfaceCount,
            findings.Count - readySurfaceCount,
            findings.All(finding => finding.IsReady),
            findings,
            notes);
    }

    internal async Task<EndpointAttackSurfaceReductionBaselineResult> ApplyAttackSurfaceReductionBaselineAsync(
        string accessToken,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        ValidatePilotAssignment(includeGroupId, excludeGroupId, allUsersAssignment, "Endpoint attack surface reduction");

        var desiredSnapshot = CreateDesiredAttackSurfaceReductionSnapshot();
        var graphRoles = ParseGraphRoles(accessToken);
        var matchingConfigurations = await ListMatchingConfigurationsAsync(
            accessToken,
            AttackSurfaceReductionDisplayName,
            cancellationToken);

        if (matchingConfigurations.Count > 1)
        {
            throw new InvalidOperationException(
                $"Multiple Intune device configurations already use the managed name '{AttackSurfaceReductionDisplayName}'. Consolidate or remove the duplicates before Securityzator can manage this baseline safely.");
        }

        var existingConfiguration = matchingConfigurations.SingleOrDefault();
        EndpointAttackSurfaceReductionConfigurationSnapshot? before = null;
        var createdConfiguration = false;
        var updatedConfiguration = false;
        var updatedAssignments = false;
        string configurationId;

        if (existingConfiguration is null)
        {
            configurationId = await CreateConfigurationAsync(
                accessToken,
                graphRoles,
                CreateAttackSurfaceReductionPayload(),
                "Intune endpoint attack surface reduction create failed",
                GetGraphBetaBaseUrl(),
                cancellationToken);
            createdConfiguration = true;
        }
        else
        {
            before = await GetAttackSurfaceReductionConfigurationSnapshotAsync(
                existingConfiguration.Id,
                accessToken,
                graphRoles,
                cancellationToken);

            if (!string.Equals(before.ODataType, "#microsoft.graph.windows10EndpointProtectionConfiguration", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The managed Intune configuration name '{AttackSurfaceReductionDisplayName}' already exists as '{before.ODataType}'. Rename or remove that profile before Securityzator manages this baseline.");
            }

            configurationId = existingConfiguration.Id;

            if (!IsDesiredConfiguration(before, desiredSnapshot))
            {
                await UpdateConfigurationAsync(
                    configurationId,
                    accessToken,
                    graphRoles,
                    CreateAttackSurfaceReductionPayload(),
                    "Intune endpoint attack surface reduction update failed",
                    GetGraphBetaBaseUrl(),
                    cancellationToken);
                updatedConfiguration = true;
            }
        }

        var currentAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);
        var assignmentsAlreadyAligned = AreAssignmentsAligned(currentAssignments, includeGroupId, excludeGroupId, allUsersAssignment);

        if (!assignmentsAlreadyAligned)
        {
            await AssignConfigurationAsync(configurationId, includeGroupId, excludeGroupId, accessToken, graphRoles, cancellationToken, allUsersAssignment);
            updatedAssignments = true;
        }

        var after = await GetAttackSurfaceReductionConfigurationSnapshotAsync(configurationId, accessToken, graphRoles, cancellationToken);
        var finalAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);

        if (!IsDesiredConfiguration(after, desiredSnapshot))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the Securityzator endpoint attack surface reduction baseline after the configuration update.");
        }

        if (!AreAssignmentsAligned(finalAssignments, includeGroupId, excludeGroupId, allUsersAssignment))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the requested include or exclusion group assignment after the attack surface reduction update.");
        }

        var alreadyCompliant = !createdConfiguration && !updatedConfiguration && !updatedAssignments;
        var notes = BuildAttackSurfaceReductionNotes(excludeGroupId);

        return new EndpointAttackSurfaceReductionBaselineResult(
            configurationId,
            alreadyCompliant,
            createdConfiguration,
            updatedConfiguration,
            updatedAssignments,
            before,
            after,
            finalAssignments,
            notes);
    }

    internal async Task<EndpointOsSecurityBaselineResult> ApplyOsSecurityBaselineAsync(
        string accessToken,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false,
        CancellationToken cancellationToken = default)
    {
        ValidatePilotAssignment(includeGroupId, excludeGroupId, allUsersAssignment, "Endpoint OS security baseline");

        var desiredSnapshot = CreateDesiredOsSecurityBaselineSnapshot();
        var graphRoles = ParseGraphRoles(accessToken);
        var matchingConfigurations = await ListMatchingConfigurationsAsync(
            accessToken,
            OsSecurityBaselineDisplayName,
            cancellationToken);

        if (matchingConfigurations.Count > 1)
        {
            throw new InvalidOperationException(
                $"Multiple Intune device configurations already use the managed name '{OsSecurityBaselineDisplayName}'. Consolidate or remove the duplicates before Securityzator can manage this baseline safely.");
        }

        var existingConfiguration = matchingConfigurations.SingleOrDefault();
        EndpointOsSecurityConfigurationSnapshot? before = null;
        var createdConfiguration = false;
        var updatedConfiguration = false;
        var updatedAssignments = false;
        string configurationId;

        if (existingConfiguration is null)
        {
            configurationId = await CreateConfigurationAsync(
                accessToken,
                graphRoles,
                CreateOsSecurityBaselinePayload(),
                "Intune endpoint OS security baseline create failed",
                GetGraphBetaBaseUrl(),
                cancellationToken);
            createdConfiguration = true;
        }
        else
        {
            before = await GetOsSecurityConfigurationSnapshotAsync(
                existingConfiguration.Id,
                accessToken,
                graphRoles,
                cancellationToken);

            if (!string.Equals(before.ODataType, "#microsoft.graph.windows10EndpointProtectionConfiguration", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The managed Intune configuration name '{OsSecurityBaselineDisplayName}' already exists as '{before.ODataType}'. Rename or remove that profile before Securityzator manages this baseline safely.");
            }

            configurationId = existingConfiguration.Id;

            if (!IsDesiredConfiguration(before, desiredSnapshot))
            {
                await UpdateConfigurationAsync(
                    configurationId,
                    accessToken,
                    graphRoles,
                    CreateOsSecurityBaselinePayload(),
                    "Intune endpoint OS security baseline update failed",
                    GetGraphBetaBaseUrl(),
                    cancellationToken);
                updatedConfiguration = true;
            }
        }

        var currentAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);
        var assignmentsAlreadyAligned = AreAssignmentsAligned(currentAssignments, includeGroupId, excludeGroupId, allUsersAssignment);

        if (!assignmentsAlreadyAligned)
        {
            await AssignConfigurationAsync(configurationId, includeGroupId, excludeGroupId, accessToken, graphRoles, cancellationToken, allUsersAssignment);
            updatedAssignments = true;
        }

        var after = await GetOsSecurityConfigurationSnapshotAsync(configurationId, accessToken, graphRoles, cancellationToken);
        var finalAssignments = await ListAssignmentsAsync(configurationId, accessToken, graphRoles, cancellationToken);

        if (!IsDesiredConfiguration(after, desiredSnapshot))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the Securityzator endpoint OS security baseline after the configuration update.");
        }

        if (!AreAssignmentsAligned(finalAssignments, includeGroupId, excludeGroupId, allUsersAssignment))
        {
            throw new InvalidOperationException(
                "Intune readback did not match the requested include or exclusion group assignment after the endpoint OS security baseline update.");
        }

        var alreadyCompliant = !createdConfiguration && !updatedConfiguration && !updatedAssignments;
        var notes = BuildOsSecurityNotes(excludeGroupId);

        return new EndpointOsSecurityBaselineResult(
            configurationId,
            alreadyCompliant,
            createdConfiguration,
            updatedConfiguration,
            updatedAssignments,
            before,
            after,
            finalAssignments,
            notes);
    }

    private async Task<IReadOnlyList<DeviceConfigurationSummary>> ListMatchingConfigurationsAsync(
        string accessToken,
        string displayName,
        CancellationToken cancellationToken)
    {
        var matches = new List<DeviceConfigurationSummary>();
        var nextRequestUrl =
            $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/deviceManagement/deviceConfigurations?$top=200&$select=id,displayName";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            using var response = await SendAuthorizedAsync(
                HttpMethod.Get,
                nextRequestUrl,
                accessToken,
                null,
                Array.Empty<string>(),
                cancellationToken);

            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                throw new GraphServiceException(BuildErrorMessage(
                    "Intune device-configuration lookup failed",
                    response.StatusCode,
                    responseBody,
                    Array.Empty<string>()));
            }

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var valuesElement)
                && valuesElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in valuesElement.EnumerateArray())
                {
                    var candidateDisplayName = GetString(item, "displayName");
                    if (!string.Equals(candidateDisplayName, displayName, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    matches.Add(new DeviceConfigurationSummary(
                        GetString(item, "id"),
                        candidateDisplayName));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return matches;
    }

    private async Task<IReadOnlyList<DeviceConfigurationSummary>> ListMatchingGroupPolicyConfigurationsAsync(
        string accessToken,
        string displayName,
        CancellationToken cancellationToken)
    {
        var matches = new List<DeviceConfigurationSummary>();
        var nextRequestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/groupPolicyConfigurations?$top=200&$select=id,displayName";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            using var response = await SendAuthorizedAsync(
                HttpMethod.Get,
                nextRequestUrl,
                accessToken,
                null,
                Array.Empty<string>(),
                cancellationToken);

            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                throw new GraphServiceException(BuildErrorMessage(
                    "Intune group policy-configuration lookup failed",
                    response.StatusCode,
                    responseBody,
                    Array.Empty<string>()));
            }

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var valuesElement)
                && valuesElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in valuesElement.EnumerateArray())
                {
                    var candidateDisplayName = GetString(item, "displayName");
                    if (!string.Equals(candidateDisplayName, displayName, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    matches.Add(new DeviceConfigurationSummary(
                        GetString(item, "id"),
                        candidateDisplayName));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return matches;
    }

    private async Task<string> CreateGroupPolicyConfigurationAsync(
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        string displayName,
        string description,
        CancellationToken cancellationToken)
    {
        var requestUrl = $"{GetGraphBetaBaseUrl()}/deviceManagement/groupPolicyConfigurations";
        var payload = new Dictionary<string, object?>
        {
            ["@odata.type"] = "#microsoft.graph.groupPolicyConfiguration",
            ["displayName"] = displayName,
            ["description"] = description,
            ["roleScopeTagIds"] = new[] { "0" },
            ["policyConfigurationIngestionType"] = "builtIn"
        };

        using var response = await SendAuthorizedAsync(
            HttpMethod.Post,
            requestUrl,
            accessToken,
            payload,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune browser hardening group policy configuration create failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }

        using var document = JsonDocument.Parse(responseBody);
        var configurationId = GetString(document.RootElement, "id");

        if (string.IsNullOrWhiteSpace(configurationId))
        {
            throw new GraphServiceException("Intune group policy configuration create succeeded but did not return an ID.");
        }

        return configurationId;
    }

    private async Task<string> CreateConfigurationAsync(
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        Dictionary<string, object?> payload,
        string errorPrefix,
        string? graphBaseUrl,
        CancellationToken cancellationToken)
    {
        var requestUrl = $"{ResolveGraphBaseUrl(graphBaseUrl)}/deviceManagement/deviceConfigurations";

        using var response = await SendAuthorizedAsync(
            HttpMethod.Post,
            requestUrl,
            accessToken,
            payload,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                errorPrefix,
                response.StatusCode,
                responseBody,
                graphRoles));
        }

        using var document = JsonDocument.Parse(responseBody);
        var configurationId = GetString(document.RootElement, "id");

        if (string.IsNullOrWhiteSpace(configurationId))
        {
            throw new GraphServiceException("Intune create succeeded but did not return a device configuration ID.");
        }

        return configurationId;
    }

    private async Task UpdateConfigurationAsync(
        string configurationId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        Dictionary<string, object?> payload,
        string errorPrefix,
        string? graphBaseUrl,
        CancellationToken cancellationToken)
    {
        var requestUrl =
            $"{ResolveGraphBaseUrl(graphBaseUrl)}/deviceManagement/deviceConfigurations/{Uri.EscapeDataString(configurationId)}";

        using var response = await SendAuthorizedAsync(
            HttpMethod.Patch,
            requestUrl,
            accessToken,
            payload,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                errorPrefix,
                response.StatusCode,
                responseBody,
                graphRoles));
        }
    }

    private async Task<IReadOnlyList<GroupPolicyDefinitionValueSnapshot>> ListGroupPolicyDefinitionValuesAsync(
        string configurationId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var values = new List<GroupPolicyDefinitionValueSnapshot>();
        var nextRequestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/groupPolicyConfigurations/{Uri.EscapeDataString(configurationId)}/definitionValues?$top=200&$expand=definition";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            using var response = await SendAuthorizedAsync(
                HttpMethod.Get,
                nextRequestUrl,
                accessToken,
                null,
                graphRoles,
                cancellationToken);
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                throw new GraphServiceException(BuildErrorMessage(
                    "Intune browser hardening definition-value lookup failed",
                    response.StatusCode,
                    responseBody,
                    graphRoles));
            }

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var valuesElement)
                && valuesElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in valuesElement.EnumerateArray())
                {
                    var definitionId = string.Empty;
                    var definitionDisplayName = string.Empty;

                    if (item.TryGetProperty("definition", out var definitionElement)
                        && definitionElement.ValueKind == JsonValueKind.Object)
                    {
                        definitionId = GetString(definitionElement, "id");
                        definitionDisplayName = GetString(definitionElement, "displayName");
                    }

                    values.Add(new GroupPolicyDefinitionValueSnapshot(
                        GetString(item, "id"),
                        definitionId,
                        definitionDisplayName,
                        GetBoolean(item, "enabled"),
                        GetString(item, "configurationType")));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return values;
    }

    private async Task<IReadOnlyList<GroupPolicyDefinitionCatalogItem>> ListGroupPolicyDefinitionsAsync(
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var definitions = new List<GroupPolicyDefinitionCatalogItem>();
        var nextRequestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/groupPolicyDefinitions?$top=200&$select=id,displayName,categoryPath";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            using var response = await SendAuthorizedAsync(
                HttpMethod.Get,
                nextRequestUrl,
                accessToken,
                null,
                graphRoles,
                cancellationToken);
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                throw new GraphServiceException(BuildErrorMessage(
                    "Intune group policy definition lookup failed",
                    response.StatusCode,
                    responseBody,
                    graphRoles));
            }

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var valuesElement)
                && valuesElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in valuesElement.EnumerateArray())
                {
                    definitions.Add(new GroupPolicyDefinitionCatalogItem(
                        GetString(item, "id"),
                        GetString(item, "displayName"),
                        GetString(item, "categoryPath")));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return definitions;
    }

    private async Task<IReadOnlyList<GroupPolicyUploadedDefinitionFileCatalogItem>> ListGroupPolicyUploadedDefinitionFilesAsync(
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var files = new List<GroupPolicyUploadedDefinitionFileCatalogItem>();
        var nextRequestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/groupPolicyUploadedDefinitionFiles?$top=100&$select=id,displayName,fileName,status,lastModifiedDateTime";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            using var response = await SendAuthorizedAsync(
                HttpMethod.Get,
                nextRequestUrl,
                accessToken,
                null,
                graphRoles,
                cancellationToken);
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                throw new GraphServiceException(BuildErrorMessage(
                    "Intune uploaded definition-file lookup failed",
                    response.StatusCode,
                    responseBody,
                    graphRoles));
            }

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var valuesElement)
                && valuesElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in valuesElement.EnumerateArray())
                {
                    files.Add(new GroupPolicyUploadedDefinitionFileCatalogItem(
                        GetString(item, "id"),
                        GetString(item, "displayName"),
                        GetString(item, "fileName"),
                        GetString(item, "status"),
                        GetDateTimeOffset(item, "lastModifiedDateTime")));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return files;
    }

    private async Task CreateGroupPolicyDefinitionValueAsync(
        string configurationId,
        string definitionId,
        bool enabled,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var requestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/groupPolicyConfigurations/{Uri.EscapeDataString(configurationId)}/definitionValues";
        var payload = new Dictionary<string, object?>
        {
            ["@odata.type"] = "#microsoft.graph.groupPolicyDefinitionValue",
            ["enabled"] = enabled,
            ["configurationType"] = "policy",
            ["definition@odata.bind"] = $"{GetGraphBetaBaseUrl()}/deviceManagement/groupPolicyDefinitions('{definitionId}')"
        };

        using var response = await SendAuthorizedAsync(
            HttpMethod.Post,
            requestUrl,
            accessToken,
            payload,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune browser hardening definition-value create failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }
    }

    private async Task DeleteGroupPolicyDefinitionValueAsync(
        string configurationId,
        string definitionValueId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var requestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/groupPolicyConfigurations/{Uri.EscapeDataString(configurationId)}/definitionValues/{Uri.EscapeDataString(definitionValueId)}";

        using var response = await SendAuthorizedAsync(
            HttpMethod.Delete,
            requestUrl,
            accessToken,
            null,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune browser hardening definition-value delete failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }
    }

    private async Task<bool> SyncBrowserHardeningDefinitionValuesAsync(
        string configurationId,
        IReadOnlyList<GroupPolicyDefinitionValueSnapshot> currentValues,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        return await SyncGroupPolicyDefinitionValuesAsync(
            configurationId,
            currentValues,
            BrowserHardeningDefinitionStates,
            accessToken,
            graphRoles,
            cancellationToken);
    }

    private async Task<bool> SyncEdgeSmartScreenDefinitionValuesAsync(
        string configurationId,
        IReadOnlyList<GroupPolicyDefinitionValueSnapshot> currentValues,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        return await SyncGroupPolicyDefinitionValuesAsync(
            configurationId,
            currentValues,
            EdgeSmartScreenDefinitionStates,
            accessToken,
            graphRoles,
            cancellationToken);
    }

    private async Task<bool> SyncGroupPolicyDefinitionValuesAsync(
        string configurationId,
        IReadOnlyList<GroupPolicyDefinitionValueSnapshot> currentValues,
        IReadOnlyDictionary<string, bool> desiredDefinitionStates,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var changed = false;
        var remainingDesiredStates = new Dictionary<string, bool>(desiredDefinitionStates, StringComparer.OrdinalIgnoreCase);

        foreach (var currentValue in currentValues)
        {
            if (!remainingDesiredStates.TryGetValue(currentValue.DefinitionId, out var desiredEnabled)
                || currentValue.Enabled != desiredEnabled
                || !string.Equals(currentValue.ConfigurationType, "policy", StringComparison.OrdinalIgnoreCase))
            {
                await DeleteGroupPolicyDefinitionValueAsync(
                    configurationId,
                    currentValue.Id,
                    accessToken,
                    graphRoles,
                    cancellationToken);
                changed = true;
                continue;
            }

            remainingDesiredStates.Remove(currentValue.DefinitionId);
        }

        foreach (var desiredState in remainingDesiredStates)
        {
            await CreateGroupPolicyDefinitionValueAsync(
                configurationId,
                desiredState.Key,
                desiredState.Value,
                accessToken,
                graphRoles,
                cancellationToken);
            changed = true;
        }

        return changed;
    }

    private async Task<EndpointBrowserHardeningConfigurationSnapshot> GetBrowserHardeningConfigurationSnapshotAsync(
        string configurationId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var requestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/groupPolicyConfigurations/{Uri.EscapeDataString(configurationId)}";

        using var response = await SendAuthorizedAsync(
            HttpMethod.Get,
            requestUrl,
            accessToken,
            null,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune browser hardening configuration lookup failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }

        using var payload = JsonDocument.Parse(responseBody);
        var definitionValues = await ListGroupPolicyDefinitionValuesAsync(
            configurationId,
            accessToken,
            graphRoles,
            cancellationToken);

        return new EndpointBrowserHardeningConfigurationSnapshot(
            GetString(payload.RootElement, "id"),
            GetString(payload.RootElement, "displayName"),
            GetString(payload.RootElement, "description"),
            GetString(payload.RootElement, "policyConfigurationIngestionType"),
            definitionValues,
            GetGroupPolicyDefinitionState(definitionValues, ChromeBackgroundAppsDefinitionId),
            GetGroupPolicyDefinitionState(definitionValues, ChromeAutoFillAddressesDefinitionId),
            GetGroupPolicyDefinitionState(definitionValues, ChromeAutoFillCreditCardsDefinitionId),
            GetGroupPolicyDefinitionState(definitionValues, ChromePasswordManagerDefinitionId),
            GetGroupPolicyDefinitionState(definitionValues, ChromeThirdPartyCookiesDefinitionId));
    }

    private async Task<EndpointEdgeSmartScreenConfigurationSnapshot> GetEdgeSmartScreenConfigurationSnapshotAsync(
        string configurationId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var requestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/groupPolicyConfigurations/{Uri.EscapeDataString(configurationId)}";

        using var response = await SendAuthorizedAsync(
            HttpMethod.Get,
            requestUrl,
            accessToken,
            null,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune Edge SmartScreen configuration lookup failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }

        using var payload = JsonDocument.Parse(responseBody);
        var definitionValues = await ListGroupPolicyDefinitionValuesAsync(
            configurationId,
            accessToken,
            graphRoles,
            cancellationToken);

        return new EndpointEdgeSmartScreenConfigurationSnapshot(
            GetString(payload.RootElement, "id"),
            GetString(payload.RootElement, "displayName"),
            GetString(payload.RootElement, "description"),
            GetString(payload.RootElement, "policyConfigurationIngestionType"),
            definitionValues,
            GetGroupPolicyDefinitionState(definitionValues, EdgeConfigureSmartScreenDefinitionId),
            GetGroupPolicyDefinitionState(definitionValues, EdgePreventBypassSitesDefinitionId),
            GetGroupPolicyDefinitionState(definitionValues, EdgeForceChecksDownloadsDefinitionId),
            GetGroupPolicyDefinitionState(definitionValues, EdgeBlockPotentiallyUnwantedAppsDefinitionId));
    }

    private async Task<IReadOnlyList<ManagedWindowsDeviceSummary>> ListManagedWindowsDevicesAsync(
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var devices = new List<ManagedWindowsDeviceSummary>();
        var nextRequestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/managedDevices?$top=200&$select=id,deviceName,operatingSystem,userId,azureADDeviceId,azureActiveDirectoryDeviceId,managementState,managementAgent,lastSyncDateTime";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            using var response = await SendAuthorizedAsync(
                HttpMethod.Get,
                nextRequestUrl,
                accessToken,
                null,
                graphRoles,
                cancellationToken);
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                throw new GraphServiceException(BuildErrorMessage(
                    "Intune managed device lookup failed",
                    response.StatusCode,
                    responseBody,
                    graphRoles));
            }

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var valuesElement)
                && valuesElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in valuesElement.EnumerateArray())
                {
                    var operatingSystem = GetString(item, "operatingSystem");
                    if (!string.Equals(operatingSystem, "Windows", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    devices.Add(new ManagedWindowsDeviceSummary(
                        GetString(item, "id"),
                        GetString(item, "deviceName"),
                        operatingSystem,
                        GetString(item, "userId"),
                        GetString(item, "azureADDeviceId"),
                        GetString(item, "azureActiveDirectoryDeviceId"),
                        GetString(item, "managementState"),
                        GetString(item, "managementAgent"),
                        GetDateTimeOffset(item, "lastSyncDateTime")));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return devices;
    }

    private async Task<IReadOnlyList<EndpointDetectionAndResponsePolicySummary>> ListEndpointDetectionAndResponsePoliciesAsync(
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var policies = new List<EndpointDetectionAndResponsePolicySummary>();
        var nextRequestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/configurationPolicies?$top=200&$select=id,name,description,platforms,technologies,isAssigned,templateReference";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            using var response = await SendAuthorizedAsync(
                HttpMethod.Get,
                nextRequestUrl,
                accessToken,
                null,
                graphRoles,
                cancellationToken);
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                throw new GraphServiceException(BuildErrorMessage(
                    "Intune endpoint detection and response policy lookup failed",
                    response.StatusCode,
                    responseBody,
                    graphRoles));
            }

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var valuesElement)
                && valuesElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in valuesElement.EnumerateArray())
                {
                    if (!item.TryGetProperty("templateReference", out var templateReferenceElement)
                        || templateReferenceElement.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    var templateFamily = GetString(templateReferenceElement, "templateFamily");
                    var templateDisplayName = GetString(templateReferenceElement, "templateDisplayName");

                    if (!string.Equals(templateFamily, "endpointSecurityEndpointDetectionAndResponse", StringComparison.OrdinalIgnoreCase)
                        && !templateDisplayName.Contains("Endpoint detection and response", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    policies.Add(new EndpointDetectionAndResponsePolicySummary(
                        GetString(item, "id"),
                        GetString(item, "name"),
                        GetString(item, "description"),
                        GetString(item, "platforms"),
                        GetString(item, "technologies"),
                        GetBoolean(item, "isAssigned"),
                        templateFamily,
                        templateDisplayName));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return policies;
    }

    private async Task<IReadOnlyList<ConfigurationPolicyAssignmentTargetSummary>> ListConfigurationPolicyAssignmentsAsync(
        string policyId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var assignments = new List<ConfigurationPolicyAssignmentTargetSummary>();
        var nextRequestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/configurationPolicies/{Uri.EscapeDataString(policyId)}/assignments?$top=200";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            using var response = await SendAuthorizedAsync(
                HttpMethod.Get,
                nextRequestUrl,
                accessToken,
                null,
                graphRoles,
                cancellationToken);
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                throw new GraphServiceException(BuildErrorMessage(
                    "Intune endpoint detection and response assignment lookup failed",
                    response.StatusCode,
                    responseBody,
                    graphRoles));
            }

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var valuesElement)
                && valuesElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in valuesElement.EnumerateArray())
                {
                    if (!item.TryGetProperty("target", out var targetElement)
                        || targetElement.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    var targetId = GetString(targetElement, "entraObjectId");
                    if (string.IsNullOrWhiteSpace(targetId))
                    {
                        targetId = GetString(targetElement, "groupId");
                    }

                    assignments.Add(new ConfigurationPolicyAssignmentTargetSummary(
                        GetString(targetElement, "@odata.type"),
                        targetId));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return assignments;
    }

    private async Task<ManagedWindowsProtectionStateSnapshot?> GetManagedDeviceWindowsProtectionStateAsync(
        string managedDeviceId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var requestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/managedDevices/{Uri.EscapeDataString(managedDeviceId)}/windowsProtectionState";

        using var response = await SendAuthorizedAsync(
            HttpMethod.Get,
            requestUrl,
            accessToken,
            null,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune Windows protection-state lookup failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }

        using var payload = JsonDocument.Parse(responseBody);
        return new ManagedWindowsProtectionStateSnapshot(
            GetString(payload.RootElement, "id"),
            GetBoolean(payload.RootElement, "malwareProtectionEnabled"),
            GetString(payload.RootElement, "deviceState"),
            GetBoolean(payload.RootElement, "realTimeProtectionEnabled"),
            GetBoolean(payload.RootElement, "networkInspectionSystemEnabled"),
            GetBoolean(payload.RootElement, "quickScanOverdue"),
            GetBoolean(payload.RootElement, "fullScanOverdue"),
            GetBoolean(payload.RootElement, "signatureUpdateOverdue"),
            GetBoolean(payload.RootElement, "rebootRequired"),
            GetString(payload.RootElement, "engineVersion"),
            GetString(payload.RootElement, "signatureVersion"),
            GetString(payload.RootElement, "antiMalwareVersion"),
            GetDateTimeOffset(payload.RootElement, "lastReportedDateTime"),
            GetString(payload.RootElement, "productStatus"),
            GetBoolean(payload.RootElement, "tamperProtectionEnabled"));
    }

    private async Task<IReadOnlyList<ManagedDeviceEncryptionStateSnapshot>> ListManagedDeviceEncryptionStatesAsync(
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var encryptionStates = new List<ManagedDeviceEncryptionStateSnapshot>();
        var nextRequestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/managedDeviceEncryptionStates?$top=200";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            using var response = await SendAuthorizedAsync(
                HttpMethod.Get,
                nextRequestUrl,
                accessToken,
                null,
                graphRoles,
                cancellationToken);
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                throw new GraphServiceException(BuildErrorMessage(
                    "Intune managed device encryption-state lookup failed",
                    response.StatusCode,
                    responseBody,
                    graphRoles));
            }

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var valuesElement)
                && valuesElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in valuesElement.EnumerateArray())
                {
                    var policyNames = Array.Empty<string>();

                    if (item.TryGetProperty("policyDetails", out var policyDetailsElement)
                        && policyDetailsElement.ValueKind == JsonValueKind.Array)
                    {
                        policyNames = policyDetailsElement
                            .EnumerateArray()
                            .Select(policy => GetString(policy, "policyName"))
                            .Where(name => !string.IsNullOrWhiteSpace(name))
                            .Distinct(StringComparer.OrdinalIgnoreCase)
                            .ToArray();
                    }

                    encryptionStates.Add(new ManagedDeviceEncryptionStateSnapshot(
                        GetString(item, "id"),
                        GetString(item, "userPrincipalName"),
                        GetString(item, "deviceName"),
                        GetString(item, "deviceType"),
                        GetString(item, "osVersion"),
                        GetString(item, "tpmSpecificationVersion"),
                        GetString(item, "encryptionReadinessState"),
                        GetString(item, "encryptionState"),
                        GetString(item, "encryptionPolicySettingState"),
                        GetString(item, "advancedBitLockerStates"),
                        policyNames));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return encryptionStates;
    }

    private static bool IsScopedDevice(
        ManagedWindowsDeviceSummary device,
        IReadOnlyCollection<string> includeUserIds,
        IReadOnlyCollection<string> includeDeviceIds,
        IReadOnlyCollection<string> excludeUserIds,
        IReadOnlyCollection<string> excludeDeviceIds)
    {
        var isIncluded =
            includeUserIds.Contains(device.UserId, StringComparer.OrdinalIgnoreCase)
            || includeDeviceIds.Contains(device.AzureAdDeviceId, StringComparer.OrdinalIgnoreCase)
            || includeDeviceIds.Contains(device.AzureActiveDirectoryDeviceId, StringComparer.OrdinalIgnoreCase);

        if (!isIncluded)
        {
            return false;
        }

        var isExcluded =
            excludeUserIds.Contains(device.UserId, StringComparer.OrdinalIgnoreCase)
            || excludeDeviceIds.Contains(device.AzureAdDeviceId, StringComparer.OrdinalIgnoreCase)
            || excludeDeviceIds.Contains(device.AzureActiveDirectoryDeviceId, StringComparer.OrdinalIgnoreCase);

        return !isExcluded;
    }

    private static bool TargetsPilotScope(
        ConfigurationPolicyAssignmentTargetSummary assignment,
        string includeGroupId)
    {
        if (IsBroadAssignmentTarget(assignment))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(includeGroupId)
               && !IsExclusionAssignmentTarget(assignment.TargetODataType)
               && string.Equals(assignment.EntraObjectId, includeGroupId, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsBroadAssignmentTarget(ConfigurationPolicyAssignmentTargetSummary assignment)
    {
        return assignment.TargetODataType.Contains("allDevicesAssignmentTarget", StringComparison.OrdinalIgnoreCase)
               || assignment.TargetODataType.Contains("allLicensedUsersAssignmentTarget", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsExclusionAssignmentTarget(string targetODataType)
    {
        return targetODataType.Contains("exclusion", StringComparison.OrdinalIgnoreCase);
    }

    private async Task<IReadOnlyList<EndpointAssignmentTargetSnapshot>> ListGroupPolicyAssignmentsAsync(
        string configurationId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var assignments = new List<EndpointAssignmentTargetSnapshot>();
        var nextRequestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/groupPolicyConfigurations/{Uri.EscapeDataString(configurationId)}/assignments?$top=200";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            using var response = await SendAuthorizedAsync(
                HttpMethod.Get,
                nextRequestUrl,
                accessToken,
                null,
                graphRoles,
                cancellationToken);
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                throw new GraphServiceException(BuildErrorMessage(
                    "Intune browser hardening assignment lookup failed",
                    response.StatusCode,
                    responseBody,
                    graphRoles));
            }

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var valuesElement)
                && valuesElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in valuesElement.EnumerateArray())
                {
                    if (!item.TryGetProperty("target", out var targetElement)
                        || targetElement.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    assignments.Add(new EndpointAssignmentTargetSnapshot(
                        GetString(targetElement, "@odata.type"),
                        GetString(targetElement, "groupId")));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return assignments;
    }

    private async Task AssignGroupPolicyConfigurationAsync(
        string configurationId,
        string includeGroupId,
        string? excludeGroupId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken,
        bool allUsersAssignment = false)
    {
        var requestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/groupPolicyConfigurations/{Uri.EscapeDataString(configurationId)}/assign";

        var includeTarget = allUsersAssignment
            ? new Dictionary<string, object?> { ["@odata.type"] = "#microsoft.graph.allDevicesAssignmentTarget" }
            : new Dictionary<string, object?> { ["@odata.type"] = "#microsoft.graph.groupAssignmentTarget", ["groupId"] = includeGroupId };

        var assignments = new List<Dictionary<string, object?>>
        {
            new()
            {
                ["@odata.type"] = "#microsoft.graph.groupPolicyConfigurationAssignment",
                ["target"] = includeTarget
            }
        };

        if (!string.IsNullOrWhiteSpace(excludeGroupId))
        {
            assignments.Add(new Dictionary<string, object?>
            {
                ["@odata.type"] = "#microsoft.graph.groupPolicyConfigurationAssignment",
                ["target"] = new Dictionary<string, object?>
                {
                    ["@odata.type"] = "#microsoft.graph.exclusionGroupAssignmentTarget",
                    ["groupId"] = excludeGroupId
                }
            });
        }

        var payload = new Dictionary<string, object?>
        {
            ["assignments"] = assignments
        };

        using var response = await SendAuthorizedAsync(
            HttpMethod.Post,
            requestUrl,
            accessToken,
            payload,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune group policy configuration assignment update failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }
    }

    private async Task AssignConfigurationAsync(
        string configurationId,
        string includeGroupId,
        string? excludeGroupId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken,
        bool allUsersAssignment = false)
    {
        var requestUrl =
            $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/deviceManagement/deviceConfigurations/{Uri.EscapeDataString(configurationId)}/assign";

        var includeTarget = allUsersAssignment
            ? new Dictionary<string, object?> { ["@odata.type"] = "#microsoft.graph.allDevicesAssignmentTarget" }
            : new Dictionary<string, object?> { ["@odata.type"] = "#microsoft.graph.groupAssignmentTarget", ["groupId"] = includeGroupId };

        var assignments = new List<Dictionary<string, object?>>
        {
            new()
            {
                ["@odata.type"] = "#microsoft.graph.deviceConfigurationAssignment",
                ["id"] = Guid.NewGuid().ToString(),
                ["target"] = includeTarget
            }
        };

        if (!string.IsNullOrWhiteSpace(excludeGroupId))
        {
            assignments.Add(new Dictionary<string, object?>
            {
                ["@odata.type"] = "#microsoft.graph.deviceConfigurationAssignment",
                ["id"] = Guid.NewGuid().ToString(),
                ["target"] = new Dictionary<string, object?>
                {
                    ["@odata.type"] = "#microsoft.graph.exclusionGroupAssignmentTarget",
                    ["groupId"] = excludeGroupId
                }
            });
        }

        var payload = new Dictionary<string, object?>
        {
            ["assignments"] = assignments
        };

        using var response = await SendAuthorizedAsync(
            HttpMethod.Post,
            requestUrl,
            accessToken,
            payload,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune configuration assignment update failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }
    }

    private async Task<EndpointCoreProtectionConfigurationSnapshot> GetConfigurationSnapshotAsync(
        string configurationId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var requestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/deviceConfigurations/{Uri.EscapeDataString(configurationId)}";

        using var response = await SendAuthorizedAsync(
            HttpMethod.Get,
            requestUrl,
            accessToken,
            null,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune core protection configuration readback failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }

        using var payload = JsonDocument.Parse(responseBody);
        return new EndpointCoreProtectionConfigurationSnapshot(
            GetString(payload.RootElement, "@odata.type"),
            GetString(payload.RootElement, "id"),
            GetString(payload.RootElement, "displayName"),
            GetString(payload.RootElement, "description"),
            GetBoolean(payload.RootElement, "defenderRequireRealTimeMonitoring"),
            GetBoolean(payload.RootElement, "defenderRequireBehaviorMonitoring"),
            GetBoolean(payload.RootElement, "defenderRequireNetworkInspectionSystem"),
            GetBoolean(payload.RootElement, "defenderScanDownloads"),
            GetBoolean(payload.RootElement, "defenderScanScriptsLoadedInInternetExplorer"),
            GetBoolean(payload.RootElement, "defenderBlockEndUserAccess"),
            GetInt32(payload.RootElement, "defenderSignatureUpdateIntervalInHours"),
            GetInt32(payload.RootElement, "defenderScanMaxCpu"),
            GetBoolean(payload.RootElement, "defenderScanArchiveFiles"),
            GetBoolean(payload.RootElement, "defenderScanIncomingMail"),
            GetBoolean(payload.RootElement, "defenderScanRemovableDrivesDuringFullScan"),
            GetBoolean(payload.RootElement, "defenderScanMappedNetworkDrivesDuringFullScan"),
            GetBoolean(payload.RootElement, "defenderScanNetworkFiles"),
            GetBoolean(payload.RootElement, "defenderRequireCloudProtection"),
            GetString(payload.RootElement, "defenderCloudBlockLevel"),
            GetString(payload.RootElement, "defenderPromptForSampleSubmission"),
            GetString(payload.RootElement, "defenderScheduledQuickScanTime"),
            GetString(payload.RootElement, "defenderScanType"),
            GetString(payload.RootElement, "defenderMonitorFileActivity"),
            GetString(payload.RootElement, "defenderPotentiallyUnwantedAppAction"),
            GetString(payload.RootElement, "defenderPotentiallyUnwantedAppActionSetting"));
    }

    private async Task<EndpointAttackSurfaceReductionConfigurationSnapshot> GetAttackSurfaceReductionConfigurationSnapshotAsync(
        string configurationId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var requestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/deviceConfigurations/{Uri.EscapeDataString(configurationId)}";

        using var response = await SendAuthorizedAsync(
            HttpMethod.Get,
            requestUrl,
            accessToken,
            null,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune attack surface reduction readback failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }

        using var payload = JsonDocument.Parse(responseBody);
        return new EndpointAttackSurfaceReductionConfigurationSnapshot(
            GetString(payload.RootElement, "@odata.type"),
            GetString(payload.RootElement, "id"),
            GetString(payload.RootElement, "displayName"),
            GetString(payload.RootElement, "description"),
            GetString(payload.RootElement, "defenderAdobeReaderLaunchChildProcess"),
            GetString(payload.RootElement, "defenderOfficeAppsExecutableContentCreationOrLaunchType"),
            GetString(payload.RootElement, "defenderOfficeAppsExecutableContentCreationOrLaunch"),
            GetString(payload.RootElement, "defenderOfficeAppsLaunchChildProcessType"),
            GetString(payload.RootElement, "defenderOfficeAppsLaunchChildProcess"),
            GetString(payload.RootElement, "defenderOfficeAppsOtherProcessInjectionType"),
            GetString(payload.RootElement, "defenderOfficeAppsOtherProcessInjection"),
            GetString(payload.RootElement, "defenderOfficeCommunicationAppsLaunchChildProcess"),
            GetString(payload.RootElement, "defenderOfficeMacroCodeAllowWin32ImportsType"),
            GetString(payload.RootElement, "defenderOfficeMacroCodeAllowWin32Imports"),
            GetString(payload.RootElement, "defenderScriptObfuscatedMacroCodeType"),
            GetString(payload.RootElement, "defenderScriptObfuscatedMacroCode"),
            GetString(payload.RootElement, "defenderScriptDownloadedPayloadExecutionType"),
            GetString(payload.RootElement, "defenderScriptDownloadedPayloadExecution"),
            GetString(payload.RootElement, "defenderEmailContentExecutionType"),
            GetString(payload.RootElement, "defenderEmailContentExecution"),
            GetString(payload.RootElement, "defenderPreventCredentialStealingType"),
            GetString(payload.RootElement, "defenderProcessCreationType"),
            GetString(payload.RootElement, "defenderProcessCreation"),
            GetString(payload.RootElement, "defenderUntrustedUSBProcessType"),
            GetString(payload.RootElement, "defenderUntrustedUSBProcess"),
            GetString(payload.RootElement, "defenderUntrustedExecutableType"),
            GetString(payload.RootElement, "defenderUntrustedExecutable"),
            GetString(payload.RootElement, "defenderAdvancedRansomewareProtectionType"),
            GetString(payload.RootElement, "defenderGuardMyFoldersType"),
            GetString(payload.RootElement, "defenderBlockPersistenceThroughWmiType"));
    }

    private async Task<EndpointCoreProtectionHardeningConfigurationSnapshot> GetCoreProtectionHardeningConfigurationSnapshotAsync(
        string configurationId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var requestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/deviceConfigurations/{Uri.EscapeDataString(configurationId)}";

        using var response = await SendAuthorizedAsync(
            HttpMethod.Get,
            requestUrl,
            accessToken,
            null,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune core protection hardening readback failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }

        using var payload = JsonDocument.Parse(responseBody);
        return new EndpointCoreProtectionHardeningConfigurationSnapshot(
            GetString(payload.RootElement, "@odata.type"),
            GetString(payload.RootElement, "id"),
            GetString(payload.RootElement, "displayName"),
            GetString(payload.RootElement, "description"),
            GetString(payload.RootElement, "windowsDefenderTamperProtection"),
            GetString(payload.RootElement, "defenderNetworkProtectionType"));
    }

    private async Task<EndpointFirewallAndSmartScreenConfigurationSnapshot> GetFirewallAndSmartScreenConfigurationSnapshotAsync(
        string configurationId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var requestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/deviceConfigurations/{Uri.EscapeDataString(configurationId)}";

        using var response = await SendAuthorizedAsync(
            HttpMethod.Get,
            requestUrl,
            accessToken,
            null,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune firewall and SmartScreen baseline readback failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }

        using var payload = JsonDocument.Parse(responseBody);
        return new EndpointFirewallAndSmartScreenConfigurationSnapshot(
            GetString(payload.RootElement, "@odata.type"),
            GetString(payload.RootElement, "id"),
            GetString(payload.RootElement, "displayName"),
            GetString(payload.RootElement, "description"),
            GetNestedString(payload.RootElement, "firewallProfileDomain", "firewallEnabled"),
            GetNestedBoolean(payload.RootElement, "firewallProfileDomain", "inboundNotificationsBlocked"),
            GetNestedBoolean(payload.RootElement, "firewallProfileDomain", "incomingTrafficBlocked"),
            GetNestedString(payload.RootElement, "firewallProfilePrivate", "firewallEnabled"),
            GetNestedBoolean(payload.RootElement, "firewallProfilePrivate", "inboundNotificationsBlocked"),
            GetNestedBoolean(payload.RootElement, "firewallProfilePrivate", "incomingTrafficBlocked"),
            GetNestedString(payload.RootElement, "firewallProfilePublic", "firewallEnabled"),
            GetNestedBoolean(payload.RootElement, "firewallProfilePublic", "inboundNotificationsBlocked"),
            GetNestedBoolean(payload.RootElement, "firewallProfilePublic", "incomingTrafficBlocked"),
            GetNestedBoolean(payload.RootElement, "firewallProfilePublic", "policyRulesFromGroupPolicyMerged"),
            GetNestedBoolean(payload.RootElement, "firewallProfilePublic", "connectionSecurityRulesFromGroupPolicyMerged"),
            GetBoolean(payload.RootElement, "smartScreenEnableInShell"),
            GetBoolean(payload.RootElement, "smartScreenBlockOverrideForFiles"));
    }

    private async Task<EndpointExploitProtectionConfigurationSnapshot> GetExploitProtectionConfigurationSnapshotAsync(
        string configurationId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var requestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/deviceConfigurations/{Uri.EscapeDataString(configurationId)}";

        using var response = await SendAuthorizedAsync(
            HttpMethod.Get,
            requestUrl,
            accessToken,
            null,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune exploit protection baseline readback failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }

        using var payload = JsonDocument.Parse(responseBody);
        return new EndpointExploitProtectionConfigurationSnapshot(
            GetString(payload.RootElement, "@odata.type"),
            GetString(payload.RootElement, "id"),
            GetString(payload.RootElement, "displayName"),
            GetString(payload.RootElement, "description"),
            GetString(payload.RootElement, "defenderExploitProtectionXml"),
            GetString(payload.RootElement, "defenderExploitProtectionXmlFileName"),
            GetBoolean(payload.RootElement, "defenderSecurityCenterBlockExploitProtectionOverride"));
    }

    private async Task<EndpointOsSecurityConfigurationSnapshot> GetOsSecurityConfigurationSnapshotAsync(
        string configurationId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var requestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/deviceConfigurations/{Uri.EscapeDataString(configurationId)}";

        using var response = await SendAuthorizedAsync(
            HttpMethod.Get,
            requestUrl,
            accessToken,
            null,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune endpoint OS security baseline readback failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }

        using var payload = JsonDocument.Parse(responseBody);
        return new EndpointOsSecurityConfigurationSnapshot(
            GetString(payload.RootElement, "@odata.type"),
            GetString(payload.RootElement, "id"),
            GetString(payload.RootElement, "displayName"),
            GetString(payload.RootElement, "description"),
            GetBoolean(payload.RootElement, "localSecurityOptionsDisableAdministratorAccount"),
            GetBoolean(payload.RootElement, "localSecurityOptionsDisableGuestAccount"),
            GetInt32(payload.RootElement, "localSecurityOptionsMachineInactivityLimit"),
            GetInt32(payload.RootElement, "localSecurityOptionsMachineInactivityLimitInMinutes"),
            GetBoolean(payload.RootElement, "localSecurityOptionsBlockRemoteLogonWithBlankPassword"),
            GetBoolean(payload.RootElement, "localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange"),
            GetBoolean(payload.RootElement, "localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares"),
            GetBoolean(payload.RootElement, "localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts"),
            GetBoolean(payload.RootElement, "localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares"),
            GetBoolean(payload.RootElement, "localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers"),
            GetBoolean(payload.RootElement, "localSecurityOptionsClientDigitallySignCommunicationsAlways"),
            GetString(payload.RootElement, "lanManagerAuthenticationLevel"));
    }

    private async Task<EndpointBitLockerConfigurationSnapshot> GetBitLockerConfigurationSnapshotAsync(
        string configurationId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var requestUrl =
            $"{GetGraphBetaBaseUrl()}/deviceManagement/deviceConfigurations/{Uri.EscapeDataString(configurationId)}";

        using var response = await SendAuthorizedAsync(
            HttpMethod.Get,
            requestUrl,
            accessToken,
            null,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune BitLocker baseline readback failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }

        using var payload = JsonDocument.Parse(responseBody);
        return new EndpointBitLockerConfigurationSnapshot(
            GetString(payload.RootElement, "@odata.type"),
            GetString(payload.RootElement, "id"),
            GetString(payload.RootElement, "displayName"),
            GetString(payload.RootElement, "description"),
            GetBoolean(payload.RootElement, "bitLockerEncryptDevice"),
            GetNestedString(payload.RootElement, "bitLockerSystemDrivePolicy", "encryptionMethod"),
            GetNestedBoolean(payload.RootElement, "bitLockerSystemDrivePolicy", "startupAuthenticationRequired"),
            GetNestedBoolean(payload.RootElement, "bitLockerSystemDrivePolicy", "startupAuthenticationBlockWithoutTpmChip"),
            GetNestedString(payload.RootElement, "bitLockerSystemDrivePolicy", "startupAuthenticationTpmUsage"),
            GetNestedString(payload.RootElement, "bitLockerSystemDrivePolicy", "startupAuthenticationTpmPinUsage"),
            GetNestedString(payload.RootElement, "bitLockerSystemDrivePolicy", "startupAuthenticationTpmKeyUsage"),
            GetNestedString(payload.RootElement, "bitLockerSystemDrivePolicy", "startupAuthenticationTpmPinAndKeyUsage"),
            GetNestedInt32(payload.RootElement, "bitLockerSystemDrivePolicy", "minimumPinLength"));
    }

    private async Task<EndpointCredentialAndElevationConfigurationSnapshot> GetCredentialAndElevationConfigurationSnapshotAsync(
        string configurationId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var requestUrl =
            $"{ResolveGraphBaseUrl(null)}/deviceManagement/deviceConfigurations/{Uri.EscapeDataString(configurationId)}";

        using var response = await SendAuthorizedAsync(
            HttpMethod.Get,
            requestUrl,
            accessToken,
            null,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune credential and elevation hardening readback failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }

        using var payload = JsonDocument.Parse(responseBody);
        return new EndpointCredentialAndElevationConfigurationSnapshot(
            GetString(payload.RootElement, "@odata.type"),
            GetString(payload.RootElement, "id"),
            GetString(payload.RootElement, "displayName"),
            GetString(payload.RootElement, "description"),
            GetOmaSettingInt32(payload.RootElement, EnableVirtualizationBasedSecurityOmaUri),
            GetOmaSettingInt32(payload.RootElement, CredentialGuardConfigurationOmaUri),
            GetOmaSettingInt32(payload.RootElement, DoNotStoreCredentialsForNetworkAuthenticationOmaUri),
            GetOmaSettingInt32(payload.RootElement, RunAllAdministratorsInAdminApprovalModeOmaUri),
            GetOmaSettingInt32(payload.RootElement, ElevationPromptForStandardUsersOmaUri),
            GetOmaSettingInt32(payload.RootElement, SwitchToSecureDesktopForElevationOmaUri),
            GetOmaSettingInt32(payload.RootElement, OnlyElevateSignedAndValidatedExecutablesOmaUri),
            GetOmaSettingInt32(payload.RootElement, ConfigureLsaProtectedProcessOmaUri),
            GetOmaSettingString(payload.RootElement, SafeDllSearchModeOmaUri),
            GetOmaSettingString(payload.RootElement, EnumerateAdministratorsOnElevationOmaUri),
            GetOmaSettingString(payload.RootElement, ApplyUacRestrictionsToLocalAccountsOnNetworkLogonOmaUri),
            GetFirstAvailableOmaSettingInt32(
                payload.RootElement,
                AlwaysInstallElevatedOmaUri,
                LegacyAlwaysInstallElevatedOmaUri),
            HasOmaSetting(payload.RootElement, AlwaysInstallElevatedOmaUri),
            HasOmaSetting(payload.RootElement, LegacyAlwaysInstallElevatedOmaUri),
            GetOmaSettingString(payload.RootElement, WDigestAuthenticationOmaUri));
    }

    private async Task<EndpointRemoteAccessAndNetworkHardeningConfigurationSnapshot> GetRemoteAccessAndNetworkHardeningConfigurationSnapshotAsync(
        string configurationId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var requestUrl =
            $"{ResolveGraphBaseUrl(null)}/deviceManagement/deviceConfigurations/{Uri.EscapeDataString(configurationId)}";

        using var response = await SendAuthorizedAsync(
            HttpMethod.Get,
            requestUrl,
            accessToken,
            null,
            graphRoles,
            cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(
                "Intune remote access and network hardening readback failed",
                response.StatusCode,
                responseBody,
                graphRoles));
        }

        using var payload = JsonDocument.Parse(responseBody);
        return new EndpointRemoteAccessAndNetworkHardeningConfigurationSnapshot(
            GetString(payload.RootElement, "@odata.type"),
            GetString(payload.RootElement, "id"),
            GetString(payload.RootElement, "displayName"),
            GetString(payload.RootElement, "description"),
            GetOmaSettingString(payload.RootElement, ProhibitInstallationAndConfigurationOfNetworkBridgeOmaUri),
            GetOmaSettingString(payload.RootElement, RequireDomainUsersToElevateWhenSettingNetworkLocationOmaUri),
            GetOmaSettingString(payload.RootElement, ProhibitInternetConnectionSharingOmaUri),
            GetOmaSettingString(payload.RootElement, ConfigureOfferRemoteAssistanceOmaUri),
            GetOmaSettingString(payload.RootElement, ConfigureSolicitedRemoteAssistanceOmaUri),
            GetOmaSettingString(payload.RootElement, AllowBasicAuthenticationWinRmClientOmaUri),
            GetOmaSettingString(payload.RootElement, AllowBasicAuthenticationWinRmServiceOmaUri),
            GetOmaSettingString(payload.RootElement, DisallowAutoplayForNonVolumeDevicesOmaUri),
            GetOmaSettingString(payload.RootElement, TurnOffAutoPlayAllDrivesOmaUri),
            GetOmaSettingString(payload.RootElement, SetDefaultAutoRunBehaviorOmaUri),
            GetOmaSettingString(payload.RootElement, ConfigureSmbV1ClientDriverOmaUri),
            GetOmaSettingString(payload.RootElement, ConfigureSmbV1ServerOmaUri),
            GetOmaSettingString(payload.RootElement, Ipv6SourceRoutingProtectionLevelOmaUri),
            GetOmaSettingString(payload.RootElement, IpSourceRoutingProtectionLevelOmaUri),
            GetOmaSettingString(payload.RootElement, RemoteDesktopSecurityLayerOmaUri));
    }

    private async Task<IReadOnlyList<EndpointAssignmentTargetSnapshot>> ListAssignmentsAsync(
        string configurationId,
        string accessToken,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        var assignments = new List<EndpointAssignmentTargetSnapshot>();
        var nextRequestUrl =
            $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/deviceManagement/deviceConfigurations/{Uri.EscapeDataString(configurationId)}/assignments?$top=100";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            using var response = await SendAuthorizedAsync(
                HttpMethod.Get,
                nextRequestUrl,
                accessToken,
                null,
                graphRoles,
                cancellationToken);
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                throw new GraphServiceException(BuildErrorMessage(
                    "Intune core protection assignment readback failed",
                    response.StatusCode,
                    responseBody,
                    graphRoles));
            }

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var valuesElement)
                && valuesElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in valuesElement.EnumerateArray())
                {
                    if (!item.TryGetProperty("target", out var targetElement)
                        || targetElement.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    var targetType = GetString(targetElement, "@odata.type");
                    var targetId = GetString(targetElement, "groupId");

                    if (string.IsNullOrWhiteSpace(targetId))
                    {
                        targetId = GetString(targetElement, "entraObjectId");
                    }

                    assignments.Add(new EndpointAssignmentTargetSnapshot(
                        targetType,
                        targetId));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return assignments;
    }

    private static Dictionary<string, object?> CreateCoreProtectionPayload()
    {
        return new Dictionary<string, object?>
        {
            ["@odata.type"] = "#microsoft.graph.windows10GeneralConfiguration",
            ["displayName"] = CoreProtectionDisplayName,
            ["description"] = CoreProtectionDescription,
            ["defenderRequireRealTimeMonitoring"] = true,
            ["defenderRequireBehaviorMonitoring"] = true,
            ["defenderRequireNetworkInspectionSystem"] = true,
            ["defenderScanDownloads"] = true,
            ["defenderScanScriptsLoadedInInternetExplorer"] = true,
            ["defenderBlockEndUserAccess"] = false,
            ["defenderSignatureUpdateIntervalInHours"] = 8,
            ["defenderScanMaxCpu"] = 50,
            ["defenderScanArchiveFiles"] = true,
            ["defenderScanIncomingMail"] = true,
            ["defenderScanRemovableDrivesDuringFullScan"] = true,
            ["defenderScanMappedNetworkDrivesDuringFullScan"] = true,
            ["defenderScanNetworkFiles"] = true,
            ["defenderRequireCloudProtection"] = true,
            ["defenderCloudBlockLevel"] = "high",
            ["defenderPromptForSampleSubmission"] = "promptBeforeSendingPersonalData",
            ["defenderScheduledQuickScanTime"] = "02:00:00.0000000",
            ["defenderScanType"] = "quick",
            ["defenderMonitorFileActivity"] = "monitorAllFiles",
            ["defenderPotentiallyUnwantedAppAction"] = "block",
            ["defenderPotentiallyUnwantedAppActionSetting"] = "enable"
        };
    }

    private static Dictionary<string, object?> CreateBitLockerPayload()
    {
        return new Dictionary<string, object?>
        {
            ["@odata.type"] = "#microsoft.graph.windows10EndpointProtectionConfiguration",
            ["displayName"] = BitLockerBaselineDisplayName,
            ["description"] = BitLockerBaselineDescription,
            ["bitLockerEncryptDevice"] = true,
            ["bitLockerSystemDrivePolicy"] = new Dictionary<string, object?>
            {
                ["encryptionMethod"] = "xtsAes256",
                ["startupAuthenticationRequired"] = true,
                ["startupAuthenticationBlockWithoutTpmChip"] = false,
                ["startupAuthenticationTpmUsage"] = "required",
                ["startupAuthenticationTpmPinUsage"] = "required",
                ["startupAuthenticationTpmKeyUsage"] = "blocked",
                ["startupAuthenticationTpmPinAndKeyUsage"] = "blocked",
                ["minimumPinLength"] = 6
            }
        };
    }

    private static Dictionary<string, object?> CreateCredentialAndElevationHardeningPayload()
    {
        return new Dictionary<string, object?>
        {
            ["@odata.type"] = "#microsoft.graph.windows10CustomConfiguration",
            ["displayName"] = CredentialAndElevationHardeningDisplayName,
            ["description"] = CredentialAndElevationHardeningDescription,
            ["omaSettings"] = new object[]
            {
                CreateIntegerOmaSetting(
                    "Turn on virtualization-based security",
                    EnableVirtualizationBasedSecurityOmaUri,
                    1),
                CreateIntegerOmaSetting(
                    "Configure Credential Guard without UEFI lock",
                    CredentialGuardConfigurationOmaUri,
                    2),
                CreateIntegerOmaSetting(
                    "Block credential storage for network authentication",
                    DoNotStoreCredentialsForNetworkAuthenticationOmaUri,
                    1),
                CreateIntegerOmaSetting(
                    "Run all administrators in Admin Approval Mode",
                    RunAllAdministratorsInAdminApprovalModeOmaUri,
                    1),
                CreateIntegerOmaSetting(
                    "Automatically deny elevation requests for standard users",
                    ElevationPromptForStandardUsersOmaUri,
                    0),
                CreateIntegerOmaSetting(
                    "Switch to the secure desktop for elevation prompts",
                    SwitchToSecureDesktopForElevationOmaUri,
                    1),
                CreateIntegerOmaSetting(
                    "Only elevate executables that are signed and validated",
                    OnlyElevateSignedAndValidatedExecutablesOmaUri,
                    1),
                CreateIntegerOmaSetting(
                    "Run LSASS as a protected process without UEFI lock",
                    ConfigureLsaProtectedProcessOmaUri,
                    2),
                CreateStringOmaSetting(
                    "Enable Safe DLL search mode",
                    SafeDllSearchModeOmaUri,
                    "<enabled/>"),
                CreateStringOmaSetting(
                    "Do not enumerate administrator accounts on elevation",
                    EnumerateAdministratorsOnElevationOmaUri,
                    "<disabled/>"),
                CreateStringOmaSetting(
                    "Apply UAC restrictions to local accounts on network logons",
                    ApplyUacRestrictionsToLocalAccountsOnNetworkLogonOmaUri,
                    "<enabled/>"),
                CreateIntegerOmaSetting(
                    "Do not always install Windows Installer packages with elevated privileges",
                    AlwaysInstallElevatedOmaUri,
                    0),
                CreateStringOmaSetting(
                    "Disable WDigest authentication",
                    WDigestAuthenticationOmaUri,
                    "<disabled/>")
            }
        };
    }

    private static Dictionary<string, object?> CreateRemoteAccessAndNetworkHardeningPayload()
    {
        return new Dictionary<string, object?>
        {
            ["@odata.type"] = "#microsoft.graph.windows10CustomConfiguration",
            ["displayName"] = RemoteAccessAndNetworkHardeningDisplayName,
            ["description"] = RemoteAccessAndNetworkHardeningDescription,
            ["omaSettings"] = new object[]
            {
                CreateStringOmaSetting(
                    "Prohibit installation and configuration of Network Bridge",
                    ProhibitInstallationAndConfigurationOfNetworkBridgeOmaUri,
                    "<enabled/>"),
                CreateStringOmaSetting(
                    "Require domain users to elevate when setting a network location",
                    RequireDomainUsersToElevateWhenSettingNetworkLocationOmaUri,
                    "<enabled/>"),
                CreateStringOmaSetting(
                    "Prohibit use of Internet Connection Sharing on your DNS domain network",
                    ProhibitInternetConnectionSharingOmaUri,
                    "<enabled/>"),
                CreateStringOmaSetting(
                    "Disable Configure Offer Remote Assistance",
                    ConfigureOfferRemoteAssistanceOmaUri,
                    "<disabled/>"),
                CreateStringOmaSetting(
                    "Disable Solicited Remote Assistance",
                    ConfigureSolicitedRemoteAssistanceOmaUri,
                    "<disabled/>"),
                CreateStringOmaSetting(
                    "Disable WinRM Client Basic authentication",
                    AllowBasicAuthenticationWinRmClientOmaUri,
                    "<disabled/>"),
                CreateStringOmaSetting(
                    "Disable WinRM Service Basic authentication",
                    AllowBasicAuthenticationWinRmServiceOmaUri,
                    "<disabled/>"),
                CreateStringOmaSetting(
                    "Disable AutoPlay for non-volume devices",
                    DisallowAutoplayForNonVolumeDevicesOmaUri,
                    "<enabled/>"),
                CreateStringOmaSetting(
                    "Turn off AutoPlay on all drives",
                    TurnOffAutoPlayAllDrivesOmaUri,
                    "<enabled/><data id=\"Autorun_Box\" value=\"255\"/>"),
                CreateStringOmaSetting(
                    "Do not execute AutoRun commands",
                    SetDefaultAutoRunBehaviorOmaUri,
                    "<enabled/><data id=\"NoAutorun_Dropdown\" value=\"1\"/>"),
                CreateStringOmaSetting(
                    "Disable SMBv1 client driver",
                    ConfigureSmbV1ClientDriverOmaUri,
                    "<enabled/><data id=\"Pol_SecGuide_SMB1ClientDriver\" value=\"4\"/>"),
                CreateStringOmaSetting(
                    "Disable SMBv1 server",
                    ConfigureSmbV1ServerOmaUri,
                    "<disabled/>"),
                CreateStringOmaSetting(
                    "Set IPv6 source routing to highest protection",
                    Ipv6SourceRoutingProtectionLevelOmaUri,
                    "<enabled/><data id=\"DisableIPSourceRoutingIPv6\" value=\"2\"/>"),
                CreateStringOmaSetting(
                    "Disable IP source routing",
                    IpSourceRoutingProtectionLevelOmaUri,
                    "<enabled/><data id=\"DisableIPSourceRouting\" value=\"2\"/>"),
                CreateStringOmaSetting(
                    "Require TLS for Remote Desktop connections",
                    RemoteDesktopSecurityLayerOmaUri,
                    "<enabled/><data id=\"TS_SECURITY_LAYER\" value=\"2\"/>")
            }
        };
    }

    private static Dictionary<string, object?> CreateCoreProtectionHardeningPayload()
    {
        return new Dictionary<string, object?>
        {
            ["@odata.type"] = "#microsoft.graph.windows10EndpointProtectionConfiguration",
            ["displayName"] = CoreProtectionHardeningDisplayName,
            ["description"] = CoreProtectionHardeningDescription,
            ["windowsDefenderTamperProtection"] = "enable",
            ["defenderNetworkProtectionType"] = "enable"
        };
    }

    private static Dictionary<string, object?> CreateFirewallAndSmartScreenPayload()
    {
        return new Dictionary<string, object?>
        {
            ["@odata.type"] = "#microsoft.graph.windows10EndpointProtectionConfiguration",
            ["displayName"] = FirewallAndSmartScreenDisplayName,
            ["description"] = FirewallAndSmartScreenDescription,
            ["firewallProfileDomain"] = new Dictionary<string, object?>
            {
                ["firewallEnabled"] = "allowed",
                ["incomingTrafficBlocked"] = true,
                ["inboundNotificationsBlocked"] = true
            },
            ["firewallProfilePrivate"] = new Dictionary<string, object?>
            {
                ["firewallEnabled"] = "allowed",
                ["incomingTrafficBlocked"] = true,
                ["inboundNotificationsBlocked"] = true
            },
            ["firewallProfilePublic"] = new Dictionary<string, object?>
            {
                ["firewallEnabled"] = "allowed",
                ["incomingTrafficBlocked"] = true,
                ["inboundNotificationsBlocked"] = true,
                ["policyRulesFromGroupPolicyMerged"] = false,
                ["connectionSecurityRulesFromGroupPolicyMerged"] = false
            },
            ["smartScreenEnableInShell"] = true,
            ["smartScreenBlockOverrideForFiles"] = false
        };
    }

    private static Dictionary<string, object?> CreateExploitProtectionPayload()
    {
        return new Dictionary<string, object?>
        {
            ["@odata.type"] = "#microsoft.graph.windows10EndpointProtectionConfiguration",
            ["displayName"] = ExploitProtectionDisplayName,
            ["description"] = ExploitProtectionDescription,
            ["defenderExploitProtectionXml"] = ToBase64Utf8(GetExploitProtectionXml()),
            ["defenderExploitProtectionXmlFileName"] = ExploitProtectionXmlFileName,
            ["defenderSecurityCenterBlockExploitProtectionOverride"] = true
        };
    }

    private static Dictionary<string, object?> CreateOsSecurityBaselinePayload()
    {
        return new Dictionary<string, object?>
        {
            ["@odata.type"] = "#microsoft.graph.windows10EndpointProtectionConfiguration",
            ["displayName"] = OsSecurityBaselineDisplayName,
            ["description"] = OsSecurityBaselineDescription,
            ["localSecurityOptionsDisableAdministratorAccount"] = true,
            ["localSecurityOptionsDisableGuestAccount"] = true,
            ["localSecurityOptionsMachineInactivityLimit"] = 15,
            ["localSecurityOptionsMachineInactivityLimitInMinutes"] = 15,
            ["localSecurityOptionsBlockRemoteLogonWithBlankPassword"] = true,
            ["localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange"] = true,
            ["localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares"] = true,
            ["localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts"] = true,
            ["localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares"] = false,
            ["localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers"] = false,
            ["localSecurityOptionsClientDigitallySignCommunicationsAlways"] = true,
            ["lanManagerAuthenticationLevel"] = "lmNtlmV2AndNotLmOrNtm"
        };
    }

    private static Dictionary<string, object?> CreateAttackSurfaceReductionPayload()
    {
        return new Dictionary<string, object?>
        {
            ["@odata.type"] = "#microsoft.graph.windows10EndpointProtectionConfiguration",
            ["displayName"] = AttackSurfaceReductionDisplayName,
            ["description"] = AttackSurfaceReductionDescription,
            ["defenderAdobeReaderLaunchChildProcess"] = "enable",
            ["defenderOfficeAppsExecutableContentCreationOrLaunchType"] = "block",
            ["defenderOfficeAppsExecutableContentCreationOrLaunch"] = "enable",
            ["defenderOfficeAppsLaunchChildProcessType"] = "block",
            ["defenderOfficeAppsLaunchChildProcess"] = "enable",
            ["defenderOfficeAppsOtherProcessInjectionType"] = "block",
            ["defenderOfficeAppsOtherProcessInjection"] = "enable",
            ["defenderOfficeCommunicationAppsLaunchChildProcess"] = "enable",
            ["defenderOfficeMacroCodeAllowWin32ImportsType"] = "block",
            ["defenderOfficeMacroCodeAllowWin32Imports"] = "enable",
            ["defenderScriptObfuscatedMacroCodeType"] = "block",
            ["defenderScriptObfuscatedMacroCode"] = "enable",
            ["defenderScriptDownloadedPayloadExecutionType"] = "block",
            ["defenderScriptDownloadedPayloadExecution"] = "enable",
            ["defenderEmailContentExecutionType"] = "block",
            ["defenderEmailContentExecution"] = "enable",
            ["defenderPreventCredentialStealingType"] = "enable",
            ["defenderProcessCreationType"] = "block",
            ["defenderProcessCreation"] = "enable",
            ["defenderUntrustedUSBProcessType"] = "block",
            ["defenderUntrustedUSBProcess"] = "enable",
            ["defenderUntrustedExecutableType"] = "block",
            ["defenderUntrustedExecutable"] = "enable",
            ["defenderAdvancedRansomewareProtectionType"] = "enable",
            ["defenderGuardMyFoldersType"] = "enable",
            ["defenderBlockPersistenceThroughWmiType"] = "block"
        };
    }

    private static EndpointCoreProtectionConfigurationSnapshot CreateDesiredCoreProtectionSnapshot()
    {
        return new EndpointCoreProtectionConfigurationSnapshot(
            "#microsoft.graph.windows10GeneralConfiguration",
            string.Empty,
            CoreProtectionDisplayName,
            CoreProtectionDescription,
            true,
            true,
            true,
            true,
            true,
            false,
            8,
            50,
            true,
            true,
            true,
            true,
            true,
            true,
            "high",
            "promptBeforeSendingPersonalData",
            "02:00:00.0000000",
            "quick",
            "monitorAllFiles",
            "block",
            "enable");
    }

    private static EndpointBitLockerConfigurationSnapshot CreateDesiredBitLockerSnapshot()
    {
        return new EndpointBitLockerConfigurationSnapshot(
            "#microsoft.graph.windows10EndpointProtectionConfiguration",
            string.Empty,
            BitLockerBaselineDisplayName,
            BitLockerBaselineDescription,
            true,
            "xtsAes256",
            true,
            false,
            "required",
            "required",
            "blocked",
            "blocked",
            6);
    }

    private static EndpointCredentialAndElevationConfigurationSnapshot CreateDesiredCredentialAndElevationHardeningSnapshot()
    {
        return new EndpointCredentialAndElevationConfigurationSnapshot(
            "#microsoft.graph.windows10CustomConfiguration",
            string.Empty,
            CredentialAndElevationHardeningDisplayName,
            CredentialAndElevationHardeningDescription,
            1,
            2,
            1,
            1,
            0,
            1,
            1,
            2,
            "<enabled/>",
            "<disabled/>",
            "<enabled/>",
            0,
            true,
            false,
            "<disabled/>");
    }

    private static EndpointRemoteAccessAndNetworkHardeningConfigurationSnapshot CreateDesiredRemoteAccessAndNetworkHardeningSnapshot()
    {
        return new EndpointRemoteAccessAndNetworkHardeningConfigurationSnapshot(
            "#microsoft.graph.windows10CustomConfiguration",
            string.Empty,
            RemoteAccessAndNetworkHardeningDisplayName,
            RemoteAccessAndNetworkHardeningDescription,
            "<enabled/>",
            "<enabled/>",
            "<enabled/>",
            "<disabled/>",
            "<disabled/>",
            "<disabled/>",
            "<disabled/>",
            "<enabled/>",
            "<enabled/><data id=\"Autorun_Box\" value=\"255\"/>",
            "<enabled/><data id=\"NoAutorun_Dropdown\" value=\"1\"/>",
            "<enabled/><data id=\"Pol_SecGuide_SMB1ClientDriver\" value=\"4\"/>",
            "<disabled/>",
            "<enabled/><data id=\"DisableIPSourceRoutingIPv6\" value=\"2\"/>",
            "<enabled/><data id=\"DisableIPSourceRouting\" value=\"2\"/>",
            "<enabled/><data id=\"TS_SECURITY_LAYER\" value=\"2\"/>");
    }

    private static EndpointCoreProtectionHardeningConfigurationSnapshot CreateDesiredCoreProtectionHardeningSnapshot()
    {
        return new EndpointCoreProtectionHardeningConfigurationSnapshot(
            "#microsoft.graph.windows10EndpointProtectionConfiguration",
            string.Empty,
            CoreProtectionHardeningDisplayName,
            CoreProtectionHardeningDescription,
            "enable",
            "enable");
    }

    private static EndpointFirewallAndSmartScreenConfigurationSnapshot CreateDesiredFirewallAndSmartScreenSnapshot()
    {
        return new EndpointFirewallAndSmartScreenConfigurationSnapshot(
            "#microsoft.graph.windows10EndpointProtectionConfiguration",
            string.Empty,
            FirewallAndSmartScreenDisplayName,
            FirewallAndSmartScreenDescription,
            "allowed",
            true,
            true,
            "allowed",
            true,
            true,
            "allowed",
            true,
            true,
            false,
            false,
            true,
            false);
    }

    private static EndpointExploitProtectionConfigurationSnapshot CreateDesiredExploitProtectionSnapshot()
    {
        return new EndpointExploitProtectionConfigurationSnapshot(
            "#microsoft.graph.windows10EndpointProtectionConfiguration",
            string.Empty,
            ExploitProtectionDisplayName,
            ExploitProtectionDescription,
            ToBase64Utf8(GetExploitProtectionXml()),
            ExploitProtectionXmlFileName,
            true);
    }

    private static EndpointOsSecurityConfigurationSnapshot CreateDesiredOsSecurityBaselineSnapshot()
    {
        return new EndpointOsSecurityConfigurationSnapshot(
            "#microsoft.graph.windows10EndpointProtectionConfiguration",
            string.Empty,
            OsSecurityBaselineDisplayName,
            OsSecurityBaselineDescription,
            true,
            true,
            15,
            15,
            true,
            true,
            true,
            true,
            false,
            false,
            true,
            "lmNtlmV2AndNotLmOrNtm");
    }

    private static EndpointAttackSurfaceReductionConfigurationSnapshot CreateDesiredAttackSurfaceReductionSnapshot()
    {
        return new EndpointAttackSurfaceReductionConfigurationSnapshot(
            "#microsoft.graph.windows10EndpointProtectionConfiguration",
            string.Empty,
            AttackSurfaceReductionDisplayName,
            AttackSurfaceReductionDescription,
            "enable",
            "block",
            "enable",
            "block",
            "enable",
            "block",
            "enable",
            "enable",
            "block",
            "enable",
            "block",
            "enable",
            "block",
            "enable",
            "block",
            "enable",
            "enable",
            "block",
            "enable",
            "block",
            "enable",
            "block",
            "enable",
            "enable",
            "enable",
            "block");
    }

    private static bool IsDesiredConfiguration(
        EndpointCoreProtectionConfigurationSnapshot actual,
        EndpointCoreProtectionConfigurationSnapshot desired)
    {
        return string.Equals(actual.DisplayName, desired.DisplayName, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.Description, desired.Description, StringComparison.Ordinal)
               && actual.DefenderRequireRealTimeMonitoring == desired.DefenderRequireRealTimeMonitoring
               && actual.DefenderRequireBehaviorMonitoring == desired.DefenderRequireBehaviorMonitoring
               && actual.DefenderRequireNetworkInspectionSystem == desired.DefenderRequireNetworkInspectionSystem
               && actual.DefenderScanDownloads == desired.DefenderScanDownloads
               && actual.DefenderScanScriptsLoadedInInternetExplorer == desired.DefenderScanScriptsLoadedInInternetExplorer
               && actual.DefenderBlockEndUserAccess == desired.DefenderBlockEndUserAccess
               && actual.DefenderSignatureUpdateIntervalInHours == desired.DefenderSignatureUpdateIntervalInHours
               && actual.DefenderScanMaxCpu == desired.DefenderScanMaxCpu
               && actual.DefenderScanArchiveFiles == desired.DefenderScanArchiveFiles
               && actual.DefenderScanIncomingMail == desired.DefenderScanIncomingMail
               && actual.DefenderScanRemovableDrivesDuringFullScan == desired.DefenderScanRemovableDrivesDuringFullScan
               && actual.DefenderScanMappedNetworkDrivesDuringFullScan == desired.DefenderScanMappedNetworkDrivesDuringFullScan
               && actual.DefenderScanNetworkFiles == desired.DefenderScanNetworkFiles
               && actual.DefenderRequireCloudProtection == desired.DefenderRequireCloudProtection
               && string.Equals(actual.DefenderCloudBlockLevel, desired.DefenderCloudBlockLevel, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderPromptForSampleSubmission, desired.DefenderPromptForSampleSubmission, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderScheduledQuickScanTime, desired.DefenderScheduledQuickScanTime, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderScanType, desired.DefenderScanType, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderMonitorFileActivity, desired.DefenderMonitorFileActivity, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderPotentiallyUnwantedAppAction, desired.DefenderPotentiallyUnwantedAppAction, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDesiredConfiguration(
        EndpointBitLockerConfigurationSnapshot actual,
        EndpointBitLockerConfigurationSnapshot desired)
    {
        return string.Equals(actual.DisplayName, desired.DisplayName, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.Description, desired.Description, StringComparison.Ordinal)
               && actual.BitLockerEncryptDevice == desired.BitLockerEncryptDevice
               && string.Equals(actual.EncryptionMethod, desired.EncryptionMethod, StringComparison.OrdinalIgnoreCase)
               && actual.StartupAuthenticationRequired == desired.StartupAuthenticationRequired
               && actual.StartupAuthenticationBlockWithoutTpmChip == desired.StartupAuthenticationBlockWithoutTpmChip
               && string.Equals(actual.StartupAuthenticationTpmUsage, desired.StartupAuthenticationTpmUsage, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.StartupAuthenticationTpmPinUsage, desired.StartupAuthenticationTpmPinUsage, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.StartupAuthenticationTpmKeyUsage, desired.StartupAuthenticationTpmKeyUsage, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.StartupAuthenticationTpmPinAndKeyUsage, desired.StartupAuthenticationTpmPinAndKeyUsage, StringComparison.OrdinalIgnoreCase)
               && actual.MinimumPinLength == desired.MinimumPinLength;
    }

    private static bool IsDesiredConfiguration(
        EndpointCredentialAndElevationConfigurationSnapshot actual,
        EndpointCredentialAndElevationConfigurationSnapshot desired)
    {
        return string.Equals(actual.DisplayName, desired.DisplayName, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.Description, desired.Description, StringComparison.Ordinal)
               && actual.EnableVirtualizationBasedSecurity == desired.EnableVirtualizationBasedSecurity
               && actual.CredentialGuardConfiguration == desired.CredentialGuardConfiguration
               && actual.BlockCredentialStorageForNetworkAuthentication == desired.BlockCredentialStorageForNetworkAuthentication
               && actual.RunAllAdministratorsInAdminApprovalMode == desired.RunAllAdministratorsInAdminApprovalMode
               && actual.ElevationPromptForStandardUsers == desired.ElevationPromptForStandardUsers
               && actual.SwitchToSecureDesktopForElevation == desired.SwitchToSecureDesktopForElevation
               && actual.OnlyElevateSignedAndValidatedExecutables == desired.OnlyElevateSignedAndValidatedExecutables
               && actual.ConfigureLsaProtectedProcess == desired.ConfigureLsaProtectedProcess
               && OmaValueEquals(actual.SafeDllSearchMode, desired.SafeDllSearchMode)
               && OmaValueEquals(actual.EnumerateAdministratorsOnElevation, desired.EnumerateAdministratorsOnElevation)
               && OmaValueEquals(actual.ApplyUacRestrictionsToLocalAccountsOnNetworkLogon, desired.ApplyUacRestrictionsToLocalAccountsOnNetworkLogon)
               && actual.AlwaysInstallElevated == desired.AlwaysInstallElevated
               && actual.HasExpectedAlwaysInstallElevatedSetting == desired.HasExpectedAlwaysInstallElevatedSetting
               && actual.HasLegacyAlwaysInstallElevatedSetting == desired.HasLegacyAlwaysInstallElevatedSetting
               && OmaValueEquals(actual.WDigestAuthentication, desired.WDigestAuthentication);
    }

    private static bool IsDesiredConfiguration(
        EndpointRemoteAccessAndNetworkHardeningConfigurationSnapshot actual,
        EndpointRemoteAccessAndNetworkHardeningConfigurationSnapshot desired)
    {
        return string.Equals(actual.DisplayName, desired.DisplayName, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.Description, desired.Description, StringComparison.Ordinal)
               && OmaValueEquals(actual.ProhibitInstallationAndConfigurationOfNetworkBridge, desired.ProhibitInstallationAndConfigurationOfNetworkBridge)
               && OmaValueEquals(actual.RequireDomainUsersToElevateWhenSettingNetworkLocation, desired.RequireDomainUsersToElevateWhenSettingNetworkLocation)
               && OmaValueEquals(actual.ProhibitInternetConnectionSharing, desired.ProhibitInternetConnectionSharing)
               && OmaValueEquals(actual.ConfigureOfferRemoteAssistance, desired.ConfigureOfferRemoteAssistance)
               && OmaValueEquals(actual.ConfigureSolicitedRemoteAssistance, desired.ConfigureSolicitedRemoteAssistance)
               && OmaValueEquals(actual.AllowBasicAuthenticationWinRmClient, desired.AllowBasicAuthenticationWinRmClient)
               && OmaValueEquals(actual.AllowBasicAuthenticationWinRmService, desired.AllowBasicAuthenticationWinRmService)
               && OmaValueEquals(actual.DisallowAutoplayForNonVolumeDevices, desired.DisallowAutoplayForNonVolumeDevices)
               && OmaValueEquals(actual.TurnOffAutoPlayAllDrives, desired.TurnOffAutoPlayAllDrives)
               && OmaValueEquals(actual.SetDefaultAutoRunBehavior, desired.SetDefaultAutoRunBehavior)
               && OmaValueEquals(actual.ConfigureSmbV1ClientDriver, desired.ConfigureSmbV1ClientDriver)
               && OmaValueEquals(actual.ConfigureSmbV1Server, desired.ConfigureSmbV1Server)
               && OmaValueEquals(actual.Ipv6SourceRoutingProtectionLevel, desired.Ipv6SourceRoutingProtectionLevel)
               && OmaValueEquals(actual.IpSourceRoutingProtectionLevel, desired.IpSourceRoutingProtectionLevel)
               && OmaValueEquals(actual.RemoteDesktopSecurityLayer, desired.RemoteDesktopSecurityLayer);
    }

    private static bool IsDesiredConfiguration(
        EndpointCoreProtectionHardeningConfigurationSnapshot actual,
        EndpointCoreProtectionHardeningConfigurationSnapshot desired)
    {
        return string.Equals(actual.DisplayName, desired.DisplayName, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.Description, desired.Description, StringComparison.Ordinal)
               && string.Equals(actual.WindowsDefenderTamperProtection, desired.WindowsDefenderTamperProtection, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderNetworkProtectionType, desired.DefenderNetworkProtectionType, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDesiredConfiguration(
        EndpointFirewallAndSmartScreenConfigurationSnapshot actual,
        EndpointFirewallAndSmartScreenConfigurationSnapshot desired)
    {
        return string.Equals(actual.DisplayName, desired.DisplayName, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.Description, desired.Description, StringComparison.Ordinal)
               && string.Equals(actual.DomainFirewallEnabled, desired.DomainFirewallEnabled, StringComparison.OrdinalIgnoreCase)
               && actual.DomainInboundNotificationsBlocked == desired.DomainInboundNotificationsBlocked
               && actual.DomainIncomingTrafficBlocked == desired.DomainIncomingTrafficBlocked
               && string.Equals(actual.PrivateFirewallEnabled, desired.PrivateFirewallEnabled, StringComparison.OrdinalIgnoreCase)
               && actual.PrivateInboundNotificationsBlocked == desired.PrivateInboundNotificationsBlocked
               && actual.PrivateIncomingTrafficBlocked == desired.PrivateIncomingTrafficBlocked
               && string.Equals(actual.PublicFirewallEnabled, desired.PublicFirewallEnabled, StringComparison.OrdinalIgnoreCase)
               && actual.PublicInboundNotificationsBlocked == desired.PublicInboundNotificationsBlocked
               && actual.PublicIncomingTrafficBlocked == desired.PublicIncomingTrafficBlocked
               && actual.PublicPolicyRulesFromGroupPolicyMerged == desired.PublicPolicyRulesFromGroupPolicyMerged
               && actual.PublicConnectionSecurityRulesFromGroupPolicyMerged == desired.PublicConnectionSecurityRulesFromGroupPolicyMerged
               && actual.SmartScreenEnableInShell == desired.SmartScreenEnableInShell
               && actual.SmartScreenBlockOverrideForFiles == desired.SmartScreenBlockOverrideForFiles;
    }

    private static bool IsDesiredConfiguration(
        EndpointExploitProtectionConfigurationSnapshot actual,
        EndpointExploitProtectionConfigurationSnapshot desired)
    {
        return string.Equals(actual.DisplayName, desired.DisplayName, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.Description, desired.Description, StringComparison.Ordinal)
               && BinaryUtf8Equals(actual.DefenderExploitProtectionXml, desired.DefenderExploitProtectionXml)
               && string.Equals(actual.DefenderExploitProtectionXmlFileName, desired.DefenderExploitProtectionXmlFileName, StringComparison.OrdinalIgnoreCase)
               && actual.DefenderSecurityCenterBlockExploitProtectionOverride == desired.DefenderSecurityCenterBlockExploitProtectionOverride;
    }

    private static bool IsDesiredConfiguration(
        EndpointOsSecurityConfigurationSnapshot actual,
        EndpointOsSecurityConfigurationSnapshot desired)
    {
        var inactivityLimitMatches =
            actual.LocalSecurityOptionsMachineInactivityLimit == desired.LocalSecurityOptionsMachineInactivityLimit
            || actual.LocalSecurityOptionsMachineInactivityLimitInMinutes == desired.LocalSecurityOptionsMachineInactivityLimitInMinutes;

        return string.Equals(actual.DisplayName, desired.DisplayName, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.Description, desired.Description, StringComparison.Ordinal)
               && actual.LocalSecurityOptionsDisableAdministratorAccount == desired.LocalSecurityOptionsDisableAdministratorAccount
               && actual.LocalSecurityOptionsDisableGuestAccount == desired.LocalSecurityOptionsDisableGuestAccount
               && inactivityLimitMatches
               && actual.LocalSecurityOptionsBlockRemoteLogonWithBlankPassword == desired.LocalSecurityOptionsBlockRemoteLogonWithBlankPassword
               && actual.LocalSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange == desired.LocalSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange
               && actual.LocalSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares == desired.LocalSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares
               && actual.LocalSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts == desired.LocalSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts
               && actual.LocalSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares == desired.LocalSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares
               && actual.LocalSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers == desired.LocalSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers
               && actual.LocalSecurityOptionsClientDigitallySignCommunicationsAlways == desired.LocalSecurityOptionsClientDigitallySignCommunicationsAlways
               && string.Equals(actual.LanManagerAuthenticationLevel, desired.LanManagerAuthenticationLevel, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDesiredConfiguration(
        EndpointAttackSurfaceReductionConfigurationSnapshot actual,
        EndpointAttackSurfaceReductionConfigurationSnapshot desired)
    {
        return string.Equals(actual.DisplayName, desired.DisplayName, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.Description, desired.Description, StringComparison.Ordinal)
               && string.Equals(actual.DefenderAdobeReaderLaunchChildProcess, desired.DefenderAdobeReaderLaunchChildProcess, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderOfficeAppsExecutableContentCreationOrLaunchType, desired.DefenderOfficeAppsExecutableContentCreationOrLaunchType, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderOfficeAppsExecutableContentCreationOrLaunch, desired.DefenderOfficeAppsExecutableContentCreationOrLaunch, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderOfficeAppsLaunchChildProcessType, desired.DefenderOfficeAppsLaunchChildProcessType, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderOfficeAppsLaunchChildProcess, desired.DefenderOfficeAppsLaunchChildProcess, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderOfficeAppsOtherProcessInjectionType, desired.DefenderOfficeAppsOtherProcessInjectionType, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderOfficeAppsOtherProcessInjection, desired.DefenderOfficeAppsOtherProcessInjection, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderOfficeCommunicationAppsLaunchChildProcess, desired.DefenderOfficeCommunicationAppsLaunchChildProcess, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderOfficeMacroCodeAllowWin32ImportsType, desired.DefenderOfficeMacroCodeAllowWin32ImportsType, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderOfficeMacroCodeAllowWin32Imports, desired.DefenderOfficeMacroCodeAllowWin32Imports, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderScriptObfuscatedMacroCodeType, desired.DefenderScriptObfuscatedMacroCodeType, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderScriptObfuscatedMacroCode, desired.DefenderScriptObfuscatedMacroCode, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderScriptDownloadedPayloadExecutionType, desired.DefenderScriptDownloadedPayloadExecutionType, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderScriptDownloadedPayloadExecution, desired.DefenderScriptDownloadedPayloadExecution, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderEmailContentExecutionType, desired.DefenderEmailContentExecutionType, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderEmailContentExecution, desired.DefenderEmailContentExecution, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderPreventCredentialStealingType, desired.DefenderPreventCredentialStealingType, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderProcessCreationType, desired.DefenderProcessCreationType, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderProcessCreation, desired.DefenderProcessCreation, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderUntrustedUSBProcessType, desired.DefenderUntrustedUSBProcessType, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderUntrustedUSBProcess, desired.DefenderUntrustedUSBProcess, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderUntrustedExecutableType, desired.DefenderUntrustedExecutableType, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderUntrustedExecutable, desired.DefenderUntrustedExecutable, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderAdvancedRansomewareProtectionType, desired.DefenderAdvancedRansomewareProtectionType, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderGuardMyFoldersType, desired.DefenderGuardMyFoldersType, StringComparison.OrdinalIgnoreCase)
               && string.Equals(actual.DefenderBlockPersistenceThroughWmiType, desired.DefenderBlockPersistenceThroughWmiType, StringComparison.OrdinalIgnoreCase);
    }

    private static bool AreAssignmentsAligned(
        IReadOnlyList<EndpointAssignmentTargetSnapshot> assignments,
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment = false)
    {
        if (assignments.Count == 0)
        {
            return false;
        }

        var normalizedExclude = string.IsNullOrWhiteSpace(excludeGroupId)
            ? null
            : excludeGroupId.Trim();

        if (allUsersAssignment)
        {
            var allDevicesMatches = assignments.Where(static a => a.IsAllDevicesTarget).ToArray();
            var excludeMatches = assignments.Where(static a => a.IsExcludeGroup).ToArray();
            var unexpectedAssignments = assignments.Where(a => !a.IsAllDevicesTarget && !a.IsExcludeGroup).ToArray();

            if (unexpectedAssignments.Length > 0 || allDevicesMatches.Length != 1)
            {
                return false;
            }

            if (normalizedExclude is null)
            {
                return excludeMatches.Length == 0;
            }

            return excludeMatches.Length == 1
                   && string.Equals(excludeMatches[0].TargetId, normalizedExclude, StringComparison.OrdinalIgnoreCase);
        }

        var normalizedInclude = includeGroupId.Trim();
        var includeMatches = assignments.Where(static assignment => assignment.IsIncludeGroup).ToArray();
        var groupExcludeMatches = assignments.Where(static assignment => assignment.IsExcludeGroup).ToArray();
        var unexpectedGroupAssignments = assignments.Where(assignment =>
            !assignment.IsIncludeGroup && !assignment.IsExcludeGroup).ToArray();

        if (unexpectedGroupAssignments.Length > 0)
        {
            return false;
        }

        if (includeMatches.Length != 1
            || !string.Equals(includeMatches[0].TargetId, normalizedInclude, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (normalizedExclude is null)
        {
            return groupExcludeMatches.Length == 0;
        }

        return groupExcludeMatches.Length == 1
               && string.Equals(groupExcludeMatches[0].TargetId, normalizedExclude, StringComparison.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<string> BuildCoreProtectionNotes(string? excludeGroupId)
    {
        var notes = new List<string>
        {
            "This Intune baseline package now manages two Securityzator profiles: the Windows general configuration for Defender Antivirus, cloud protection, scheduled quick scans, script and network-file scanning, and PUA blocking, plus an endpoint-protection hardening profile for tamper protection and network protection.",
            "EDR in block mode, update-governance controls, and Defender cloud-service connectivity remain explicit follow-up items because they still need a different Intune, Defender, or rollout surface than this first endpoint package."
        };

        if (!string.IsNullOrWhiteSpace(excludeGroupId))
        {
            notes.Add($"An exclusion group is applied for staged rollout safety: {excludeGroupId.Trim()}.");
        }

        return notes;
    }

    private static IReadOnlyList<string> BuildAttackSurfaceReductionNotes(string? excludeGroupId)
    {
        var notes = new List<string>
        {
            "This pilot ASR baseline covers Office child-process or executable-content rules, script or macro abuse rules, email-executable blocking, untrusted USB or prevalence-based execution blocking, WMI persistence blocking, ransomware protection, and LSASS credential-theft protection.",
            "The remaining Secure Score items for Flash, Adobe JavaScript, ActiveX, Safe Mode reboot blocking, webshell protection, and some server-specific ASR controls still need a different endpoint or browser management surface before Securityzator should automate them."
        };

        if (!string.IsNullOrWhiteSpace(excludeGroupId))
        {
            notes.Add($"An exclusion group is applied for staged rollout safety: {excludeGroupId.Trim()}.");
        }

        return notes;
    }

    private static IReadOnlyList<string> BuildFirewallAndSmartScreenNotes(string? excludeGroupId)
    {
        var notes = new List<string>
        {
            "This package now pairs the Windows endpoint-protection profile with a companion Microsoft Edge group policy profile so Microsoft Defender Firewall posture, Windows SmartScreen app/file checking, Edge site/download checks, and Edge potentially unwanted app blocking stay aligned in the same pilot rollout.",
            "Broader browser hardening still belongs in the dedicated browser baseline, and Adobe-specific browser or reader controls remain separate follow-up work."
        };

        if (!string.IsNullOrWhiteSpace(excludeGroupId))
        {
            notes.Add($"An exclusion group is applied for staged rollout safety: {excludeGroupId.Trim()}.");
        }

        return notes;
    }

    private static IReadOnlyList<string> BuildExploitProtectionNotes(string? excludeGroupId)
    {
        var notes = new List<string>
        {
            "This Intune exploit protection baseline applies a Securityzator-managed system-level exploit protection XML that enables DEP, ASLR, Control Flow Guard, SEHOP, and heap termination on corruption, while blocking user override from Windows Security.",
            "System-level exploit protection settings require a reboot before every mitigation is fully active, so staged rollout and pilot validation still matter even after the Intune profile is in place.",
            "Adobe-, Chrome-, WSL-, and sensor-specific controls remain separate follow-up work because they need application-specific policy surfaces, onboarding state, or broader runtime validation beyond this first exploit-protection slice."
        };

        if (!string.IsNullOrWhiteSpace(excludeGroupId))
        {
            notes.Add($"An exclusion group is applied for staged rollout safety: {excludeGroupId.Trim()}.");
        }

        return notes;
    }

    private static IReadOnlyList<string> BuildBitLockerNotes(string? excludeGroupId)
    {
        var notes = new List<string>
        {
            "This Intune BitLocker baseline requires device encryption, enforces additional startup authentication with TPM plus PIN, and sets the minimum startup PIN length to six characters for the pilot scope.",
            "Securityzator now follows the profile assignment with a BitLocker rollout-health assessment against Intune managed-device encryption telemetry so encryption state, assignment state, and readiness are visible in the run history.",
            "Recovery escrow confirmation and hands-on remediation for firmware, TPM, or compatibility blockers still need device-level follow-up beyond this first rollout-health slice."
        };

        if (!string.IsNullOrWhiteSpace(excludeGroupId))
        {
            notes.Add($"An exclusion group is applied for staged rollout safety: {excludeGroupId.Trim()}.");
        }

        return notes;
    }

    private static IReadOnlyList<string> BuildBitLockerDeploymentAssessmentNotes(string? excludeGroupId, int scopedDeviceCount)
    {
        var notes = new List<string>
        {
            "The BitLocker rollout-health check uses Microsoft Graph beta managedDeviceEncryptionStates telemetry to confirm encryption state, reported policy assignment, readiness, and advanced BitLocker status for the selected pilot scope.",
            "Recovery key escrow confirmation and hardware or firmware remediation still need device-side follow-up when Intune reports readiness or compatibility blockers."
        };

        if (scopedDeviceCount == 0)
        {
            notes.Add("No Windows managed devices matched the selected pilot scope for BitLocker rollout-health validation.");
        }

        if (!string.IsNullOrWhiteSpace(excludeGroupId))
        {
            notes.Add($"An exclusion group is applied for staged rollout safety: {excludeGroupId.Trim()}.");
        }

        return notes;
    }

    private static IReadOnlyList<string> BuildBrowserAndAdobePolicySurfaceNotes(
        int chromeDefinitionCount,
        int adobeUploadedDefinitionFileCount,
        int adobeJavascriptOrFlashDefinitionCount)
    {
        return
        [
            "This readiness check uses Microsoft Graph beta groupPolicyDefinitions and groupPolicyUploadedDefinitionFiles to confirm whether Intune exposes the policy surface Securityzator would need for the remaining Chrome outdated plug-in and Adobe JavaScript or Flash controls.",
            chromeDefinitionCount == 0
                ? "The outdated Chrome plug-in control did not surface as a durable Intune policy definition on this tenant, so Securityzator keeps it out of the direct baseline path."
                : "A Chrome policy definition for the outdated plug-in control is present, so that path can be evaluated for a later durable baseline.",
            adobeUploadedDefinitionFileCount == 0
                ? "No Adobe ADMX upload is present in Intune, so Adobe JavaScript and Flash controls are not yet available to the current automation path."
                : adobeJavascriptOrFlashDefinitionCount == 0
                    ? "Adobe ADMX files exist, but the JavaScript and Flash policy definitions did not surface cleanly for automation on this tenant."
                    : "Adobe JavaScript and Flash policy definitions are present in Intune and can be considered for a future dedicated Adobe baseline."
        ];
    }

    private static IReadOnlyList<string> BuildCredentialAndElevationHardeningNotes(string? excludeGroupId)
    {
        var notes = new List<string>
        {
            "This Intune custom baseline turns on virtualization-based security and Credential Guard, runs LSASS as a protected process without UEFI lock, disables WDigest authentication, blocks the local storage of passwords and credentials for network authentication, keeps Admin Approval Mode enabled, forces elevation prompts onto the secure desktop, automatically denies elevation requests for standard users, enables Safe DLL search mode, hides local administrator accounts during elevation prompts, applies UAC restrictions to local accounts on network logons, and keeps Windows Installer from running with elevated privileges by default.",
            "WinRM Basic authentication, Remote Assistance, and several adjacent credential or remote-management controls remain explicit follow-up work because they still need broader CSP coverage, ADMX-backed handling, or a different endpoint-management surface."
        };

        if (!string.IsNullOrWhiteSpace(excludeGroupId))
        {
            notes.Add($"An exclusion group is applied for staged rollout safety: {excludeGroupId.Trim()}.");
        }

        return notes;
    }

    private static IReadOnlyList<string> BuildRemoteAccessAndNetworkHardeningNotes(string? excludeGroupId)
    {
        var notes = new List<string>
        {
            "This Intune custom baseline disables WinRM Basic authentication for both the client and service, disables Offer and Solicited Remote Assistance, blocks Network Bridge configuration, forces domain users to elevate before changing a network location, blocks Internet Connection Sharing on the domain network, disables AutoPlay for non-volume devices, turns off AutoPlay for all drives, blocks AutoRun command execution, retires the SMBv1 client and server, applies highest-protection IPv4 and IPv6 source-routing posture, and requires TLS for Remote Desktop connections.",
            "Broader browser-adjacent, Adobe, and other compatibility-sensitive network or endpoint-surface controls remain explicit follow-up work because they still need additional CSP coverage or another management surface."
        };

        if (!string.IsNullOrWhiteSpace(excludeGroupId))
        {
            notes.Add($"An exclusion group is applied for staged rollout safety: {excludeGroupId.Trim()}.");
        }

        return notes;
    }

    private static IReadOnlyList<string> BuildOsSecurityNotes(string? excludeGroupId)
    {
        var notes = new List<string>
        {
            "This Intune OS baseline covers workstation-safe local security and SMB hardening settings such as disabling the built-in Administrator and Guest accounts, limiting blank-password remote logons, enforcing the NTLMv2-only LAN Manager level, disabling LM hash storage, requiring SMB client signing, blocking plaintext SMB passwords, and restricting anonymous enumeration.",
            "Password-age, account-lockout, LDAP, Remote Registry, NTLM disablement, share-governance, Secure Boot, and other server-sensitive or infrastructure-sensitive items remain explicit follow-up work because they need a broader endpoint or server configuration rollout model than this first OS baseline."
        };

        if (!string.IsNullOrWhiteSpace(excludeGroupId))
        {
            notes.Add($"An exclusion group is applied for staged rollout safety: {excludeGroupId.Trim()}.");
        }

        return notes;
    }

    private static void ValidatePilotAssignment(
        string includeGroupId,
        string? excludeGroupId,
        bool allUsersAssignment,
        string baselineName)
    {
        if (!allUsersAssignment && !Guid.TryParse(includeGroupId, out _))
        {
            throw new InvalidOperationException($"{baselineName} needs either a valid include group object ID or the all-devices assignment option.");
        }

        if (!string.IsNullOrWhiteSpace(excludeGroupId) && !Guid.TryParse(excludeGroupId, out _))
        {
            throw new InvalidOperationException($"{baselineName} received an invalid exclusion group object ID.");
        }

        if (!allUsersAssignment && string.Equals(includeGroupId, excludeGroupId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"{baselineName} cannot use the same group for include and exclusion.");
        }
    }

    private async Task<HttpResponseMessage> SendAuthorizedAsync(
        HttpMethod method,
        string requestUrl,
        string accessToken,
        object? jsonBody,
        IReadOnlyCollection<string> graphRoles,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, requestUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        if (jsonBody is not null)
        {
            var serialized = JsonSerializer.Serialize(jsonBody);
            request.Content = new StringContent(serialized, Encoding.UTF8, "application/json");
        }

        var response = await _httpClient.SendAsync(request, cancellationToken);

        if (!response.IsSuccessStatusCode
            && GraphApiVersionResolver.ShouldRetryWithBeta(_options.Value, response.StatusCode, requestUrl))
        {
            response.Dispose();

            var betaUrl = GraphApiVersionResolver.ToBetaUrl(_options.Value, requestUrl);
            using var betaRequest = new HttpRequestMessage(method, betaUrl);
            betaRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            betaRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            if (jsonBody is not null)
            {
                var serialized = JsonSerializer.Serialize(jsonBody);
                betaRequest.Content = new StringContent(serialized, Encoding.UTF8, "application/json");
            }

            response = await _httpClient.SendAsync(betaRequest, cancellationToken);
        }

        if (response.StatusCode == HttpStatusCode.Forbidden
            && !graphRoles.Contains("DeviceManagementConfiguration.ReadWrite.All", StringComparer.OrdinalIgnoreCase)
            && method != HttpMethod.Get)
        {
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
            response.Dispose();
            throw new GraphServiceException(BuildErrorMessage(
                "Intune write access is blocked",
                HttpStatusCode.Forbidden,
                responseBody,
                graphRoles));
        }

        return response;
    }

    private string GetGraphBetaBaseUrl()
    {
        return ResolveGraphBaseUrl(_options.Value.GraphBetaBaseUrl);
    }

    private string ResolveGraphBaseUrl(string? graphBaseUrl)
    {
        return string.IsNullOrWhiteSpace(graphBaseUrl)
            ? _options.Value.GraphBaseUrl.TrimEnd('/')
            : graphBaseUrl.Trim().TrimEnd('/');
    }

    private static IReadOnlyCollection<string> ParseGraphRoles(string accessToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return Array.Empty<string>();
        }

        var tokenParts = accessToken.Split('.');

        if (tokenParts.Length < 2)
        {
            return Array.Empty<string>();
        }

        var payload = tokenParts[1]
            .Replace('-', '+')
            .Replace('_', '/');

        switch (payload.Length % 4)
        {
            case 2:
                payload += "==";
                break;
            case 3:
                payload += "=";
                break;
        }

        try
        {
            var payloadBytes = Convert.FromBase64String(payload);
            using var document = JsonDocument.Parse(payloadBytes);

            if (!document.RootElement.TryGetProperty("roles", out var rolesElement)
                || rolesElement.ValueKind != JsonValueKind.Array)
            {
                return Array.Empty<string>();
            }

            return rolesElement
                .EnumerateArray()
                .Select(static role => role.GetString())
                .Where(static role => !string.IsNullOrWhiteSpace(role))
                .Cast<string>()
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static string GetString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return string.Empty;
        }

        return property.ValueKind == JsonValueKind.String
            ? property.GetString() ?? string.Empty
            : property.ToString();
    }

    private static DateTimeOffset? GetDateTimeOffset(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return null;
        }

        if (property.ValueKind == JsonValueKind.String
            && DateTimeOffset.TryParse(property.GetString(), out var parsed))
        {
            return parsed;
        }

        return null;
    }

    private static bool GetBoolean(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return false;
        }

        if (property.ValueKind == JsonValueKind.True)
        {
            return true;
        }

        if (property.ValueKind == JsonValueKind.False)
        {
            return false;
        }

        return property.ValueKind == JsonValueKind.String
               && bool.TryParse(property.GetString(), out var parsed)
               && parsed;
    }

    private static int GetInt32(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return 0;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetInt32(out var number))
        {
            return number;
        }

        return property.ValueKind == JsonValueKind.String
               && int.TryParse(property.GetString(), out var parsed)
            ? parsed
            : 0;
    }

    private static string GetNestedString(JsonElement element, string propertyName, string nestedPropertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind != JsonValueKind.Object)
        {
            return string.Empty;
        }

        return GetString(property, nestedPropertyName);
    }

    private static bool GetNestedBoolean(JsonElement element, string propertyName, string nestedPropertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        return GetBoolean(property, nestedPropertyName);
    }

    private static int GetNestedInt32(JsonElement element, string propertyName, string nestedPropertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind != JsonValueKind.Object)
        {
            return 0;
        }

        return GetInt32(property, nestedPropertyName);
    }

    private static int GetOmaSettingInt32(JsonElement element, string omaUri)
    {
        if (!element.TryGetProperty("omaSettings", out var omaSettingsElement)
            || omaSettingsElement.ValueKind != JsonValueKind.Array)
        {
            return 0;
        }

        foreach (var item in omaSettingsElement.EnumerateArray())
        {
            if (!string.Equals(GetString(item, "omaUri"), omaUri, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return GetInt32(item, "value");
        }

        return 0;
    }

    private static int GetFirstAvailableOmaSettingInt32(JsonElement element, params string[] omaUris)
    {
        foreach (var omaUri in omaUris)
        {
            var value = GetOmaSettingInt32(element, omaUri);
            if (value != 0)
            {
                return value;
            }
        }

        return 0;
    }

    private static bool HasOmaSetting(JsonElement element, string omaUri)
    {
        if (!element.TryGetProperty("omaSettings", out var omaSettingsElement)
            || omaSettingsElement.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (var item in omaSettingsElement.EnumerateArray())
        {
            if (string.Equals(GetString(item, "omaUri"), omaUri, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string GetOmaSettingString(JsonElement element, string omaUri)
    {
        if (!element.TryGetProperty("omaSettings", out var omaSettingsElement)
            || omaSettingsElement.ValueKind != JsonValueKind.Array)
        {
            return string.Empty;
        }

        foreach (var item in omaSettingsElement.EnumerateArray())
        {
            if (!string.Equals(GetString(item, "omaUri"), omaUri, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return GetString(item, "value");
        }

        return string.Empty;
    }

    private static Dictionary<string, object?> CreateIntegerOmaSetting(
        string displayName,
        string omaUri,
        int value)
    {
        return new Dictionary<string, object?>
        {
            ["@odata.type"] = "#microsoft.graph.omaSettingInteger",
            ["displayName"] = displayName,
            ["description"] = "Securityzator-managed custom OMA setting.",
            ["omaUri"] = omaUri,
            ["value"] = value
        };
    }

    private static Dictionary<string, object?> CreateStringOmaSetting(
        string displayName,
        string omaUri,
        string value)
    {
        return new Dictionary<string, object?>
        {
            ["@odata.type"] = "#microsoft.graph.omaSettingString",
            ["displayName"] = displayName,
            ["description"] = "Securityzator-managed custom OMA setting.",
            ["omaUri"] = omaUri,
            ["value"] = value
        };
    }

    private static string GetExploitProtectionXml()
    {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><MitigationPolicy><SystemConfig><DEP Enable=\"true\" EmulateAtlThunks=\"false\" /><ASLR ForceRelocateImages=\"false\" RequireInfo=\"false\" BottomUp=\"true\" HighEntropy=\"true\" /><ControlFlowGuard Enable=\"true\" SuppressExports=\"false\" /><SEHOP Enable=\"true\" TelemetryOnly=\"false\" /><Heap TerminateOnError=\"true\" /></SystemConfig></MitigationPolicy>";
    }

    private static bool? GetGroupPolicyDefinitionState(
        IReadOnlyList<GroupPolicyDefinitionValueSnapshot> definitionValues,
        string definitionId)
    {
        var matches = definitionValues
            .Where(item => string.Equals(item.DefinitionId, definitionId, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        return matches.Length == 1 ? matches[0].Enabled : null;
    }

    private static string ToBase64Utf8(string value)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
    }

    private static bool BinaryUtf8Equals(string actual, string desired)
    {
        return string.Equals(
            DecodeBase64Utf8OrOriginal(actual),
            DecodeBase64Utf8OrOriginal(desired),
            StringComparison.Ordinal);
    }

    private static string DecodeBase64Utf8OrOriginal(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        try
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(value));
        }
        catch (FormatException)
        {
            return value;
        }
    }

    private static bool OmaValueEquals(string actual, string desired)
    {
        if (string.Equals(NormalizeOmaValue(actual), "****", StringComparison.Ordinal))
        {
            return !string.IsNullOrWhiteSpace(desired);
        }

        return string.Equals(
            NormalizeOmaValue(actual),
            NormalizeOmaValue(desired),
            StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeOmaValue(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return WebUtility.HtmlDecode(value)
            .ReplaceLineEndings(string.Empty)
            .Replace(" ", string.Empty)
            .Trim();
    }

    private static string BuildErrorMessage(
        string prefix,
        HttpStatusCode statusCode,
        string responseBody,
        IReadOnlyCollection<string> graphRoles)
    {
        var bodySnippet = string.IsNullOrWhiteSpace(responseBody)
            ? string.Empty
            : responseBody.Trim().ReplaceLineEndings(" ");

        if (bodySnippet.Length > 360)
        {
            bodySnippet = bodySnippet[..360];
        }

        if (statusCode == HttpStatusCode.Forbidden
            && !graphRoles.Contains("DeviceManagementConfiguration.ReadWrite.All", StringComparer.OrdinalIgnoreCase))
        {
            return "Intune configuration automation is blocked because the app token does not include Microsoft Graph DeviceManagementConfiguration.ReadWrite.All.";
        }

        if (statusCode == HttpStatusCode.Forbidden
            && !graphRoles.Contains("DeviceManagementConfiguration.Read.All", StringComparer.OrdinalIgnoreCase)
            && !graphRoles.Contains("DeviceManagementConfiguration.ReadWrite.All", StringComparer.OrdinalIgnoreCase))
        {
            return "Intune configuration automation is blocked because the app token does not include Microsoft Graph DeviceManagementConfiguration.Read.All or DeviceManagementConfiguration.ReadWrite.All.";
        }

        return string.IsNullOrWhiteSpace(bodySnippet)
            ? $"{prefix} with {(int)statusCode}."
            : $"{prefix} with {(int)statusCode}. {bodySnippet}";
    }

    private static bool IsDesiredBrowserHardeningSnapshot(EndpointBrowserHardeningConfigurationSnapshot snapshot)
    {
        if (!string.IsNullOrWhiteSpace(snapshot.PolicyConfigurationIngestionType)
            && !string.Equals(snapshot.PolicyConfigurationIngestionType, "builtIn", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(snapshot.PolicyConfigurationIngestionType, "unknown", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (snapshot.DefinitionValues.Count != BrowserHardeningDefinitionStates.Count)
        {
            return false;
        }

        foreach (var desiredState in BrowserHardeningDefinitionStates)
        {
            var matchingValues = snapshot.DefinitionValues
                .Where(item => string.Equals(item.DefinitionId, desiredState.Key, StringComparison.OrdinalIgnoreCase))
                .ToArray();

            if (matchingValues.Length != 1)
            {
                return false;
            }

            if (matchingValues[0].Enabled != desiredState.Value
                || !string.Equals(matchingValues[0].ConfigurationType, "policy", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsDesiredEdgeSmartScreenSnapshot(EndpointEdgeSmartScreenConfigurationSnapshot snapshot)
    {
        if (!string.IsNullOrWhiteSpace(snapshot.PolicyConfigurationIngestionType)
            && !string.Equals(snapshot.PolicyConfigurationIngestionType, "builtIn", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(snapshot.PolicyConfigurationIngestionType, "unknown", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (snapshot.DefinitionValues.Count != EdgeSmartScreenDefinitionStates.Count)
        {
            return false;
        }

        foreach (var desiredState in EdgeSmartScreenDefinitionStates)
        {
            var matchingValues = snapshot.DefinitionValues
                .Where(item => string.Equals(item.DefinitionId, desiredState.Key, StringComparison.OrdinalIgnoreCase))
                .ToArray();

            if (matchingValues.Length != 1)
            {
                return false;
            }

            if (matchingValues[0].Enabled != desiredState.Value
                || !string.Equals(matchingValues[0].ConfigurationType, "policy", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    private static IReadOnlyList<string> BuildBrowserHardeningNotes(string? excludeGroupId)
    {
        var notes = new List<string>
        {
            "Chrome browser hardening is currently enforced through Intune group policy configuration definitions for background apps, AutoFill, password manager, and third-party cookies.",
            "The Secure Score control for outdated Chrome plugins remains a follow-up item because Intune surfaces that policy only under removed Chrome policies, so Securityzator does not treat it as durable baseline coverage.",
            "Adobe JavaScript and Flash controls remain follow-up items because the tenant did not expose stable Adobe definitions on the same Intune surface during live validation."
        };

        if (!string.IsNullOrWhiteSpace(excludeGroupId))
        {
            notes.Add("An exclusion group was applied so the browser baseline can stay in a staged pilot rollout.");
        }

        return notes;
    }

    private static EndpointWslPluginReadinessAssessment BuildWslPluginReadinessAssessment(
        bool hasHealthyTelemetry,
        int scopedOnboardingPolicyCount,
        int scopedDeviceCount)
    {
        var evidence = new List<string>();

        if (scopedOnboardingPolicyCount > 0)
        {
            evidence.Add($"Detected {scopedOnboardingPolicyCount} Intune endpoint detection and response policy assignment(s) covering the pilot scope.");
        }
        else
        {
            evidence.Add("No Intune endpoint detection and response policy assignment directly covered the pilot scope.");
        }

        if (hasHealthyTelemetry)
        {
            evidence.Add("At least one scoped Windows device is already returning current Defender protection telemetry.");
        }
        else if (scopedDeviceCount > 0)
        {
            evidence.Add("Scoped Windows devices are present, but current Defender protection telemetry is incomplete or stale.");
        }
        else
        {
            evidence.Add("No scoped Windows devices were available to verify Defender telemetry.");
        }

        var readyForHostValidation = hasHealthyTelemetry;
        var summary = readyForHostValidation
            ? "WSL plug-in cloud prerequisites look ready enough to continue with host-side validation. Microsoft still requires WSL 2.0.7.0 or newer, at least one active distro, and plug-in installation on the Windows host."
            : "WSL plug-in readiness still needs follow-up. Confirm a scoped Windows host is healthy in Defender for Endpoint first, then validate WSL 2.0.7.0 or newer, at least one active distro, and plug-in installation locally.";

        return new EndpointWslPluginReadinessAssessment(
            readyForHostValidation,
            summary,
            evidence);
    }

    private static IReadOnlyList<string> BuildEndpointSensorAndAgentHealthNotes(
        string? excludeGroupId,
        int scopedDeviceCount,
        int onboardingPolicyCount,
        int scopedOnboardingPolicyCount,
        bool hasHealthyTelemetry,
        EndpointWslPluginReadinessAssessment wslPluginReadiness)
    {
        var notes = new List<string>
        {
            "This assessment uses Intune managed device inventory plus Windows protection-state telemetry to flag stale reporting, overdue signatures, missing core component data, and other Defender agent-health follow-up.",
            "It also reads Intune endpoint detection and response configuration policies so the run can tell whether the pilot scope is already covered by a cloud onboarding policy or is relying on a manual or legacy onboarding path."
        };

        if (scopedDeviceCount == 0)
        {
            notes.Add("No Windows managed devices matched the selected pilot scope.");
        }

        if (onboardingPolicyCount == 0)
        {
            notes.Add("No Intune endpoint detection and response policy was found in the tenant during this assessment. Healthy devices can still reflect manual or legacy onboarding, but no current Intune onboarding policy was visible.");
        }
        else if (scopedOnboardingPolicyCount == 0)
        {
            notes.Add("Intune endpoint detection and response policies exist, but none directly targeted the selected pilot scope. Healthy devices may still be onboarded through broader or older deployment paths.");
        }
        else
        {
            notes.Add($"Detected {scopedOnboardingPolicyCount} Intune endpoint detection and response policy assignment(s) that cover the selected pilot scope.");
        }

        if (!hasHealthyTelemetry && scopedDeviceCount > 0)
        {
            notes.Add("Scoped Windows devices still need healthy Defender telemetry before sensor onboarding and WSL plug-in follow-up can be considered complete.");
        }

        notes.Add(wslPluginReadiness.Summary);

        if (!string.IsNullOrWhiteSpace(excludeGroupId))
        {
            notes.Add($"An exclusion group is applied for staged assessment scope: {excludeGroupId.Trim()}.");
        }

        return notes;
    }

    private sealed record DeviceConfigurationSummary(
        string Id,
        string DisplayName);

    internal sealed record EndpointCoreProtectionBaselineResult(
        string ConfigurationId,
        string HardeningConfigurationId,
        bool AlreadyCompliant,
        bool CreatedConfiguration,
        bool UpdatedConfiguration,
        bool UpdatedAssignments,
        EndpointCoreProtectionConfigurationSnapshot? Before,
        EndpointCoreProtectionConfigurationSnapshot After,
        IReadOnlyList<EndpointAssignmentTargetSnapshot> Assignments,
        EndpointCoreProtectionHardeningConfigurationSnapshot? HardeningBefore,
        EndpointCoreProtectionHardeningConfigurationSnapshot HardeningAfter,
        IReadOnlyList<EndpointAssignmentTargetSnapshot> HardeningAssignments,
        IReadOnlyList<string> Notes);

    internal sealed record EndpointBitLockerBaselineResult(
        string ConfigurationId,
        bool AlreadyCompliant,
        bool CreatedConfiguration,
        bool UpdatedConfiguration,
        bool UpdatedAssignments,
        EndpointBitLockerConfigurationSnapshot? Before,
        EndpointBitLockerConfigurationSnapshot After,
        IReadOnlyList<EndpointAssignmentTargetSnapshot> Assignments,
        IReadOnlyList<string> Notes);

    internal sealed record EndpointExploitProtectionBaselineResult(
        string ConfigurationId,
        bool AlreadyCompliant,
        bool CreatedConfiguration,
        bool UpdatedConfiguration,
        bool UpdatedAssignments,
        EndpointExploitProtectionConfigurationSnapshot? Before,
        EndpointExploitProtectionConfigurationSnapshot After,
        IReadOnlyList<EndpointAssignmentTargetSnapshot> Assignments,
        IReadOnlyList<string> Notes);

    internal sealed record EndpointBrowserHardeningBaselineResult(
        string ConfigurationId,
        bool AlreadyCompliant,
        bool CreatedConfiguration,
        bool UpdatedConfiguration,
        bool UpdatedAssignments,
        EndpointBrowserHardeningConfigurationSnapshot? Before,
        EndpointBrowserHardeningConfigurationSnapshot After,
        IReadOnlyList<EndpointAssignmentTargetSnapshot> Assignments,
        IReadOnlyList<string> Notes);

    internal sealed record EndpointCredentialAndElevationHardeningBaselineResult(
        string ConfigurationId,
        bool AlreadyCompliant,
        bool CreatedConfiguration,
        bool UpdatedConfiguration,
        bool UpdatedAssignments,
        EndpointCredentialAndElevationConfigurationSnapshot? Before,
        EndpointCredentialAndElevationConfigurationSnapshot After,
        IReadOnlyList<EndpointAssignmentTargetSnapshot> Assignments,
        IReadOnlyList<string> Notes);

    internal sealed record EndpointRemoteAccessAndNetworkHardeningBaselineResult(
        string ConfigurationId,
        bool AlreadyCompliant,
        bool CreatedConfiguration,
        bool UpdatedConfiguration,
        bool UpdatedAssignments,
        EndpointRemoteAccessAndNetworkHardeningConfigurationSnapshot? Before,
        EndpointRemoteAccessAndNetworkHardeningConfigurationSnapshot After,
        IReadOnlyList<EndpointAssignmentTargetSnapshot> Assignments,
        IReadOnlyList<string> Notes);

    internal sealed record EndpointSensorAndAgentHealthAssessmentResult(
        int ScopedDeviceCount,
        int HealthyDeviceCount,
        int NeedsFollowUpDeviceCount,
        bool AlreadyCompliant,
        IReadOnlyList<ManagedWindowsDeviceHealthAssessment> Findings,
        IReadOnlyList<EndpointEdrOnboardingPolicyAssessment> OnboardingPolicies,
        EndpointWslPluginReadinessAssessment WslPluginReadiness,
        IReadOnlyList<string> Notes);

    internal sealed record EndpointBitLockerDeploymentAssessmentResult(
        int ScopedDeviceCount,
        int HealthyDeviceCount,
        int NeedsFollowUpDeviceCount,
        bool AlreadyCompliant,
        IReadOnlyList<ManagedWindowsBitLockerAssessment> Findings,
        IReadOnlyList<string> Notes);

    internal sealed record EndpointBrowserAndAdobePolicySurfaceAssessmentResult(
        int SurfaceCount,
        int ReadySurfaceCount,
        int FollowUpSurfaceCount,
        bool AlreadyCompliant,
        IReadOnlyList<EndpointBrowserAndAdobePolicySurfaceFinding> Findings,
        IReadOnlyList<string> Notes);

    internal sealed record EndpointAttackSurfaceReductionBaselineResult(
        string ConfigurationId,
        bool AlreadyCompliant,
        bool CreatedConfiguration,
        bool UpdatedConfiguration,
        bool UpdatedAssignments,
        EndpointAttackSurfaceReductionConfigurationSnapshot? Before,
        EndpointAttackSurfaceReductionConfigurationSnapshot After,
        IReadOnlyList<EndpointAssignmentTargetSnapshot> Assignments,
        IReadOnlyList<string> Notes);

    internal sealed record EndpointFirewallAndSmartScreenBaselineResult(
        string ConfigurationId,
        string EdgeConfigurationId,
        bool AlreadyCompliant,
        bool CreatedConfiguration,
        bool UpdatedConfiguration,
        bool UpdatedAssignments,
        EndpointFirewallAndSmartScreenConfigurationSnapshot? Before,
        EndpointFirewallAndSmartScreenConfigurationSnapshot After,
        IReadOnlyList<EndpointAssignmentTargetSnapshot> Assignments,
        EndpointEdgeSmartScreenConfigurationSnapshot? EdgeBefore,
        EndpointEdgeSmartScreenConfigurationSnapshot EdgeAfter,
        IReadOnlyList<EndpointAssignmentTargetSnapshot> EdgeAssignments,
        IReadOnlyList<string> Notes);

    internal sealed record EndpointOsSecurityBaselineResult(
        string ConfigurationId,
        bool AlreadyCompliant,
        bool CreatedConfiguration,
        bool UpdatedConfiguration,
        bool UpdatedAssignments,
        EndpointOsSecurityConfigurationSnapshot? Before,
        EndpointOsSecurityConfigurationSnapshot After,
        IReadOnlyList<EndpointAssignmentTargetSnapshot> Assignments,
        IReadOnlyList<string> Notes);

    internal sealed record EndpointCoreProtectionConfigurationSnapshot(
        string ODataType,
        string Id,
        string DisplayName,
        string Description,
        bool DefenderRequireRealTimeMonitoring,
        bool DefenderRequireBehaviorMonitoring,
        bool DefenderRequireNetworkInspectionSystem,
        bool DefenderScanDownloads,
        bool DefenderScanScriptsLoadedInInternetExplorer,
        bool DefenderBlockEndUserAccess,
        int DefenderSignatureUpdateIntervalInHours,
        int DefenderScanMaxCpu,
        bool DefenderScanArchiveFiles,
        bool DefenderScanIncomingMail,
        bool DefenderScanRemovableDrivesDuringFullScan,
        bool DefenderScanMappedNetworkDrivesDuringFullScan,
        bool DefenderScanNetworkFiles,
        bool DefenderRequireCloudProtection,
        string DefenderCloudBlockLevel,
        string DefenderPromptForSampleSubmission,
        string DefenderScheduledQuickScanTime,
        string DefenderScanType,
        string DefenderMonitorFileActivity,
        string DefenderPotentiallyUnwantedAppAction,
        string DefenderPotentiallyUnwantedAppActionSetting);

    internal sealed record EndpointBitLockerConfigurationSnapshot(
        string ODataType,
        string Id,
        string DisplayName,
        string Description,
        bool BitLockerEncryptDevice,
        string EncryptionMethod,
        bool StartupAuthenticationRequired,
        bool StartupAuthenticationBlockWithoutTpmChip,
        string StartupAuthenticationTpmUsage,
        string StartupAuthenticationTpmPinUsage,
        string StartupAuthenticationTpmKeyUsage,
        string StartupAuthenticationTpmPinAndKeyUsage,
        int MinimumPinLength);

    internal sealed record EndpointExploitProtectionConfigurationSnapshot(
        string ODataType,
        string Id,
        string DisplayName,
        string Description,
        string DefenderExploitProtectionXml,
        string DefenderExploitProtectionXmlFileName,
        bool DefenderSecurityCenterBlockExploitProtectionOverride);

    internal sealed record EndpointBrowserHardeningConfigurationSnapshot(
        string Id,
        string DisplayName,
        string Description,
        string PolicyConfigurationIngestionType,
        IReadOnlyList<GroupPolicyDefinitionValueSnapshot> DefinitionValues,
        bool? ContinueRunningBackgroundApps,
        bool? EnableAutoFillAddresses,
        bool? EnableAutoFillCreditCards,
        bool? EnablePasswordManager,
        bool? BlockThirdPartyCookies);

    internal sealed record EndpointEdgeSmartScreenConfigurationSnapshot(
        string Id,
        string DisplayName,
        string Description,
        string PolicyConfigurationIngestionType,
        IReadOnlyList<GroupPolicyDefinitionValueSnapshot> DefinitionValues,
        bool? SmartScreenEnabled,
        bool? PreventBypassForSites,
        bool? ForceChecksOnDownloads,
        bool? BlockPotentiallyUnwantedApps);

    internal sealed record ManagedWindowsDeviceSummary(
        string ManagedDeviceId,
        string DeviceName,
        string OperatingSystem,
        string UserId,
        string AzureAdDeviceId,
        string AzureActiveDirectoryDeviceId,
        string ManagementState,
        string ManagementAgent,
        DateTimeOffset? LastSyncDateTime);

    internal sealed record ManagedWindowsProtectionStateSnapshot(
        string ManagedDeviceId,
        bool MalwareProtectionEnabled,
        string DeviceState,
        bool RealTimeProtectionEnabled,
        bool NetworkInspectionSystemEnabled,
        bool QuickScanOverdue,
        bool FullScanOverdue,
        bool SignatureUpdateOverdue,
        bool RebootRequired,
        string EngineVersion,
        string SignatureVersion,
        string AntiMalwareVersion,
        DateTimeOffset? LastReportedDateTime,
        string ProductStatus,
        bool TamperProtectionEnabled);

    internal sealed record ManagedDeviceEncryptionStateSnapshot(
        string ManagedDeviceId,
        string UserPrincipalName,
        string DeviceName,
        string DeviceType,
        string OsVersion,
        string TpmSpecificationVersion,
        string EncryptionReadinessState,
        string EncryptionState,
        string EncryptionPolicySettingState,
        string AdvancedBitLockerStates,
        IReadOnlyList<string> PolicyNames);

    internal sealed record GroupPolicyDefinitionCatalogItem(
        string Id,
        string DisplayName,
        string CategoryPath);

    internal sealed record GroupPolicyUploadedDefinitionFileCatalogItem(
        string Id,
        string DisplayName,
        string FileName,
        string Status,
        DateTimeOffset? LastModifiedDateTime);

    internal sealed record EndpointBrowserAndAdobePolicySurfaceFinding(
        string SurfaceName,
        bool IsReady,
        string Summary,
        IReadOnlyList<string> Evidence);

    internal sealed record EndpointDetectionAndResponsePolicySummary(
        string PolicyId,
        string Name,
        string Description,
        string Platforms,
        string Technologies,
        bool IsAssigned,
        string TemplateFamily,
        string TemplateDisplayName);

    internal sealed record ConfigurationPolicyAssignmentTargetSummary(
        string TargetODataType,
        string EntraObjectId);

    internal sealed record EndpointEdrOnboardingPolicyAssessment(
        string PolicyId,
        string Name,
        string TemplateFamily,
        string TemplateDisplayName,
        bool IsAssigned,
        bool TargetsPilotScope,
        bool HasBroadAssignment,
        IReadOnlyList<ConfigurationPolicyAssignmentTargetSummary> Assignments);

    internal sealed record EndpointWslPluginReadinessAssessment(
        bool ReadyForHostValidation,
        string Summary,
        IReadOnlyList<string> Evidence);

    internal sealed record ManagedWindowsDeviceHealthAssessment(
        string ManagedDeviceId,
        string DeviceName,
        string UserId,
        string AzureAdDeviceId,
        DateTimeOffset? LastSyncDateTime,
        ManagedWindowsProtectionStateSnapshot? ProtectionState,
        IReadOnlyList<string> Issues)
    {
        public bool IsHealthy => Issues.Count == 0;
    }

    internal sealed record ManagedWindowsBitLockerAssessment(
        string ManagedDeviceId,
        string DeviceName,
        string UserId,
        string AzureAdDeviceId,
        DateTimeOffset? LastSyncDateTime,
        ManagedDeviceEncryptionStateSnapshot? EncryptionState,
        IReadOnlyList<string> Issues)
    {
        public bool IsHealthy => Issues.Count == 0;
    }

    internal sealed record EndpointCredentialAndElevationConfigurationSnapshot(
        string ODataType,
        string Id,
        string DisplayName,
        string Description,
        int EnableVirtualizationBasedSecurity,
        int CredentialGuardConfiguration,
        int BlockCredentialStorageForNetworkAuthentication,
        int RunAllAdministratorsInAdminApprovalMode,
        int ElevationPromptForStandardUsers,
        int SwitchToSecureDesktopForElevation,
        int OnlyElevateSignedAndValidatedExecutables,
        int ConfigureLsaProtectedProcess,
        string SafeDllSearchMode,
        string EnumerateAdministratorsOnElevation,
        string ApplyUacRestrictionsToLocalAccountsOnNetworkLogon,
        int AlwaysInstallElevated,
        bool HasExpectedAlwaysInstallElevatedSetting,
        bool HasLegacyAlwaysInstallElevatedSetting,
        string WDigestAuthentication);

    internal sealed record EndpointRemoteAccessAndNetworkHardeningConfigurationSnapshot(
        string ODataType,
        string Id,
        string DisplayName,
        string Description,
        string ProhibitInstallationAndConfigurationOfNetworkBridge,
        string RequireDomainUsersToElevateWhenSettingNetworkLocation,
        string ProhibitInternetConnectionSharing,
        string ConfigureOfferRemoteAssistance,
        string ConfigureSolicitedRemoteAssistance,
        string AllowBasicAuthenticationWinRmClient,
        string AllowBasicAuthenticationWinRmService,
        string DisallowAutoplayForNonVolumeDevices,
        string TurnOffAutoPlayAllDrives,
        string SetDefaultAutoRunBehavior,
        string ConfigureSmbV1ClientDriver,
        string ConfigureSmbV1Server,
        string Ipv6SourceRoutingProtectionLevel,
        string IpSourceRoutingProtectionLevel,
        string RemoteDesktopSecurityLayer);

    internal sealed record EndpointCoreProtectionHardeningConfigurationSnapshot(
        string ODataType,
        string Id,
        string DisplayName,
        string Description,
        string WindowsDefenderTamperProtection,
        string DefenderNetworkProtectionType);

    internal sealed record EndpointFirewallAndSmartScreenConfigurationSnapshot(
        string ODataType,
        string Id,
        string DisplayName,
        string Description,
        string DomainFirewallEnabled,
        bool DomainInboundNotificationsBlocked,
        bool DomainIncomingTrafficBlocked,
        string PrivateFirewallEnabled,
        bool PrivateInboundNotificationsBlocked,
        bool PrivateIncomingTrafficBlocked,
        string PublicFirewallEnabled,
        bool PublicInboundNotificationsBlocked,
        bool PublicIncomingTrafficBlocked,
        bool PublicPolicyRulesFromGroupPolicyMerged,
        bool PublicConnectionSecurityRulesFromGroupPolicyMerged,
        bool SmartScreenEnableInShell,
        bool SmartScreenBlockOverrideForFiles);

    internal sealed record EndpointAttackSurfaceReductionConfigurationSnapshot(
        string ODataType,
        string Id,
        string DisplayName,
        string Description,
        string DefenderAdobeReaderLaunchChildProcess,
        string DefenderOfficeAppsExecutableContentCreationOrLaunchType,
        string DefenderOfficeAppsExecutableContentCreationOrLaunch,
        string DefenderOfficeAppsLaunchChildProcessType,
        string DefenderOfficeAppsLaunchChildProcess,
        string DefenderOfficeAppsOtherProcessInjectionType,
        string DefenderOfficeAppsOtherProcessInjection,
        string DefenderOfficeCommunicationAppsLaunchChildProcess,
        string DefenderOfficeMacroCodeAllowWin32ImportsType,
        string DefenderOfficeMacroCodeAllowWin32Imports,
        string DefenderScriptObfuscatedMacroCodeType,
        string DefenderScriptObfuscatedMacroCode,
        string DefenderScriptDownloadedPayloadExecutionType,
        string DefenderScriptDownloadedPayloadExecution,
        string DefenderEmailContentExecutionType,
        string DefenderEmailContentExecution,
        string DefenderPreventCredentialStealingType,
        string DefenderProcessCreationType,
        string DefenderProcessCreation,
        string DefenderUntrustedUSBProcessType,
        string DefenderUntrustedUSBProcess,
        string DefenderUntrustedExecutableType,
        string DefenderUntrustedExecutable,
        string DefenderAdvancedRansomewareProtectionType,
        string DefenderGuardMyFoldersType,
        string DefenderBlockPersistenceThroughWmiType);

    internal sealed record EndpointOsSecurityConfigurationSnapshot(
        string ODataType,
        string Id,
        string DisplayName,
        string Description,
        bool LocalSecurityOptionsDisableAdministratorAccount,
        bool LocalSecurityOptionsDisableGuestAccount,
        int LocalSecurityOptionsMachineInactivityLimit,
        int LocalSecurityOptionsMachineInactivityLimitInMinutes,
        bool LocalSecurityOptionsBlockRemoteLogonWithBlankPassword,
        bool LocalSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange,
        bool LocalSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares,
        bool LocalSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts,
        bool LocalSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares,
        bool LocalSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers,
        bool LocalSecurityOptionsClientDigitallySignCommunicationsAlways,
        string LanManagerAuthenticationLevel);

    internal sealed record EndpointAssignmentTargetSnapshot(
        string TargetType,
        string TargetId)
    {
        public bool IsIncludeGroup =>
            string.Equals(TargetType, "#microsoft.graph.groupAssignmentTarget", StringComparison.OrdinalIgnoreCase)
            || string.Equals(TargetType, "microsoft.graph.groupAssignmentTarget", StringComparison.OrdinalIgnoreCase)
            || string.Equals(TargetType, "#microsoft.graph.scopeTagGroupAssignmentTarget", StringComparison.OrdinalIgnoreCase)
            || string.Equals(TargetType, "microsoft.graph.scopeTagGroupAssignmentTarget", StringComparison.OrdinalIgnoreCase);

        public bool IsAllDevicesTarget =>
            string.Equals(TargetType, "#microsoft.graph.allDevicesAssignmentTarget", StringComparison.OrdinalIgnoreCase)
            || string.Equals(TargetType, "microsoft.graph.allDevicesAssignmentTarget", StringComparison.OrdinalIgnoreCase);

        public bool IsExcludeGroup =>
            string.Equals(TargetType, "#microsoft.graph.exclusionGroupAssignmentTarget", StringComparison.OrdinalIgnoreCase)
            || string.Equals(TargetType, "microsoft.graph.exclusionGroupAssignmentTarget", StringComparison.OrdinalIgnoreCase);
    }

    internal sealed record GroupPolicyDefinitionValueSnapshot(
        string Id,
        string DefinitionId,
        string DefinitionDisplayName,
        bool Enabled,
        string ConfigurationType);
}
