using Securityzator.Application.Connections;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Securityzator.Infrastructure.Graph;
using Securityzator.Infrastructure.Security;
using Securityzator.Infrastructure.Storage;
using Securityzator.Infrastructure.Teams;

namespace Securityzator.Infrastructure.Connections;

public sealed class FileBackedAzureConnectionService : IAzureConnectionService
{
    private const string DefaultAutomationCertificateStoreLocation = nameof(StoreLocation.LocalMachine);
    private const string DefaultAutomationCertificateStoreName = nameof(StoreName.My);
    private readonly JsonFileSecurityzatorStateStore _stateStore;
    private readonly ClientSecretProtector _secretProtector;
    private readonly GraphAccessTokenService _tokenService;
    private readonly DirectoryGraphClient _directoryClient;
    private readonly ConditionalAccessGraphClient _conditionalAccessClient;
    private readonly SecureScoreGraphClient _secureScoreClient;
    private readonly IntuneManagementGraphClient _intuneManagementClient;
    private readonly TeamsMeetingPolicyAutomationClient _teamsMeetingPolicyClient;

    public FileBackedAzureConnectionService(
        JsonFileSecurityzatorStateStore stateStore,
        ClientSecretProtector secretProtector,
        GraphAccessTokenService tokenService,
        DirectoryGraphClient directoryClient,
        ConditionalAccessGraphClient conditionalAccessClient,
        SecureScoreGraphClient secureScoreClient,
        IntuneManagementGraphClient intuneManagementClient,
        TeamsMeetingPolicyAutomationClient teamsMeetingPolicyClient)
    {
        _stateStore = stateStore;
        _secretProtector = secretProtector;
        _tokenService = tokenService;
        _directoryClient = directoryClient;
        _conditionalAccessClient = conditionalAccessClient;
        _secureScoreClient = secureScoreClient;
        _intuneManagementClient = intuneManagementClient;
        _teamsMeetingPolicyClient = teamsMeetingPolicyClient;
    }

    public Task<IReadOnlyList<AzureConnectionProfile>> ListForOperatorAsync(
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default)
    {
        return _stateStore.ReadAsync<IReadOnlyList<AzureConnectionProfile>>(state =>
            state.Connections
                .Where(connection => connection.OwnerOperatorId == ownerOperatorId)
                .OrderByDescending(connection => connection.UpdatedUtc)
                .Select(ToProfile)
                .ToArray(), cancellationToken);
    }

    public async Task<AzureConnectionProfile?> GetForOperatorAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default)
    {
        var stored = await _stateStore.ReadAsync(
            state => state.Connections.FirstOrDefault(connection =>
                connection.Id == connectionId && connection.OwnerOperatorId == ownerOperatorId),
            cancellationToken);

        return stored is null ? null : ToProfile(stored);
    }

    public Task<AzureConnectionProfile> CreateAsync(
        CreateAzureConnectionRequest request,
        CancellationToken cancellationToken = default)
    {
        return _stateStore.WriteAsync(state =>
        {
            var now = DateTimeOffset.UtcNow;
            var stored = new StoredAzureConnectionProfile
            {
                Id = Guid.NewGuid(),
                OwnerOperatorId = request.OwnerOperatorId,
                DisplayName = request.DisplayName.Trim(),
                TenantId = request.TenantId.Trim(),
                ClientId = request.ClientId.Trim(),
                RedirectUri = request.RedirectUri.Trim(),
                ProtectedClientSecret = _secretProtector.Protect(request.ClientSecret.Trim()),
                AutomationCertificateThumbprint = NormalizeAutomationCertificateThumbprint(request.AutomationCertificateThumbprint),
                AutomationCertificateStoreLocation = NormalizeAutomationCertificateStoreLocation(request.AutomationCertificateStoreLocation),
                AutomationCertificateStoreName = NormalizeAutomationCertificateStoreName(request.AutomationCertificateStoreName),
                DeclaredLicenseCapabilities = TenantLicenseCapabilityCatalog.NormalizeSelected(request.DeclaredLicenseCapabilities).ToList(),
                AutomationCertificateStatus = (int)AutomationCertificateStatus.NotConfigured,
                CreatedUtc = now,
                UpdatedUtc = now,
                SecretUpdatedUtc = now,
                ValidationStatus = (int)AzureConnectionValidationStatus.Unknown
            };

            state.Connections.Add(stored);
            return ToProfile(stored);
        }, cancellationToken);
    }

    public Task<AzureConnectionProfile?> UpdateAsync(
        UpdateAzureConnectionRequest request,
        CancellationToken cancellationToken = default)
    {
        return _stateStore.WriteAsync<AzureConnectionProfile?>(state =>
        {
            var stored = state.Connections.FirstOrDefault(connection =>
                connection.Id == request.ConnectionId && connection.OwnerOperatorId == request.OwnerOperatorId);

            if (stored is null)
            {
                return null;
            }

            stored.DisplayName = request.DisplayName.Trim();
            stored.TenantId = request.TenantId.Trim();
            stored.ClientId = request.ClientId.Trim();
            stored.RedirectUri = request.RedirectUri.Trim();
            stored.AutomationCertificateThumbprint = NormalizeAutomationCertificateThumbprint(request.AutomationCertificateThumbprint);
            stored.AutomationCertificateStoreLocation = NormalizeAutomationCertificateStoreLocation(request.AutomationCertificateStoreLocation);
            stored.AutomationCertificateStoreName = NormalizeAutomationCertificateStoreName(request.AutomationCertificateStoreName);
            stored.DeclaredLicenseCapabilities = TenantLicenseCapabilityCatalog.NormalizeSelected(request.DeclaredLicenseCapabilities).ToList();
            stored.AutomationCertificateStatus = (int)AutomationCertificateStatus.NotConfigured;
            stored.AutomationCertificateSubject = null;
            stored.AutomationCertificateExpiresUtc = null;
            stored.AutomationCertificateMessage = null;
            stored.UpdatedUtc = DateTimeOffset.UtcNow;
            stored.SecretUpdatedUtc = ResolveSecretUpdatedUtc(stored);

            if (!string.IsNullOrWhiteSpace(request.ClientSecret))
            {
                stored.ProtectedClientSecret = _secretProtector.Protect(request.ClientSecret.Trim());
                stored.SecretUpdatedUtc = stored.UpdatedUtc;
            }

            return ToProfile(stored);
        }, cancellationToken);
    }

    public async Task<AzureConnectionValidationOutcome> ValidateAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default)
    {
        var connection = await _stateStore.ReadAsync(
            state => state.Connections.FirstOrDefault(item =>
                item.Id == connectionId && item.OwnerOperatorId == ownerOperatorId),
            cancellationToken);

        if (connection is null)
        {
            return new AzureConnectionValidationOutcome(
                connectionId,
                "Unknown connection",
                AzureConnectionValidationStatus.Failed,
                false,
                "The selected Azure connection could not be found.",
                DateTimeOffset.UtcNow,
                false,
                false,
                false);
        }

        var certificateProbe = ProbeAutomationCertificate(connection);

        if (string.IsNullOrWhiteSpace(connection.ProtectedClientSecret))
        {
            return await PersistValidationAsync(
                connection.Id,
                ownerOperatorId,
                AzureConnectionValidationStatus.Failed,
                "This connection does not have a stored client secret. Update the profile before validating it.",
                null,
                false,
                false,
                false,
                false,
                false,
                false,
                0,
                false,
                false,
                null,
                false,
                null,
                false,
                null,
                certificateProbe,
                cancellationToken);
        }

        try
        {
            var clientSecret = _secretProtector.Unprotect(connection.ProtectedClientSecret);
            var accessToken = await _tokenService.AcquireApplicationTokenAsync(
                connection.TenantId,
                connection.ClientId,
                clientSecret,
                cancellationToken);

            var capabilityErrors = new List<string>();
            var canReadGroups = await ProbeCapabilityAsync(
                () => _directoryClient.ProbeGroupReadAsync(accessToken, cancellationToken),
                "Directory groups",
                capabilityErrors);
            var canReadConditionalAccess = await ProbeCapabilityAsync(
                () => _conditionalAccessClient.ProbePolicyReadAsync(accessToken, cancellationToken),
                "Conditional Access policies",
                capabilityErrors);
            var canReadRecommendations = await ProbeCapabilityAsync(
                () => _secureScoreClient.ProbeSecureScoreReadAsync(accessToken, cancellationToken),
                "Secure Score recommendations",
                capabilityErrors);
            var entraDailyUseProbe = ProbeEntraDailyUseCapability(accessToken);
            var intuneProbe = await ProbeIntuneCapabilityAsync(
                accessToken,
                cancellationToken);
            var teamsProbe = await ProbeTeamsMeetingPolicyCapabilityAsync(
                connection,
                clientSecret,
                cancellationToken);

            if (capabilityErrors.Count == 0)
            {
                var successMessage =
                    $"Validated '{connection.DisplayName}'. Token acquisition, directory groups, Conditional Access, and Secure Score probes all succeeded.";

                if (!teamsProbe.Succeeded)
                {
                    successMessage += $" Teams meeting automation is still blocked: {teamsProbe.Message}";
                }

                if (!string.IsNullOrWhiteSpace(intuneProbe.Message))
                {
                    successMessage += $" {intuneProbe.Message}";
                }

                if (!string.IsNullOrWhiteSpace(entraDailyUseProbe.Message))
                {
                    successMessage += $" {entraDailyUseProbe.Message}";
                }

                return await PersistValidationAsync(
                    connection.Id,
                    ownerOperatorId,
                    AzureConnectionValidationStatus.Succeeded,
                    successMessage,
                    connection.DisplayName,
                    canReadGroups,
                    canReadConditionalAccess,
                    canReadRecommendations,
                    intuneProbe.CanReadManagedDevices,
                    intuneProbe.CanReadIntuneDeviceConfigurations,
                    intuneProbe.CanReadIntuneCompliancePolicies,
                    intuneProbe.EnrolledDeviceCount,
                    intuneProbe.HasIntuneDeviceConfigurations,
                    intuneProbe.HasIntuneCompliancePolicies,
                    intuneProbe.Message,
                    entraDailyUseProbe.CanManageEntraDailyUseHardening,
                    entraDailyUseProbe.Message,
                    teamsProbe.Succeeded,
                    teamsProbe.Message,
                    certificateProbe,
                    cancellationToken);
            }

            var message =
                $"Validated the saved secret for '{connection.DisplayName}', but one or more required Graph surfaces failed: {string.Join(" ", capabilityErrors)}";

            if (!teamsProbe.Succeeded)
            {
                message += $" Teams meeting automation is also blocked: {teamsProbe.Message}";
            }

            if (!string.IsNullOrWhiteSpace(intuneProbe.Message))
            {
                message += $" {intuneProbe.Message}";
            }

            if (!string.IsNullOrWhiteSpace(entraDailyUseProbe.Message))
            {
                message += $" {entraDailyUseProbe.Message}";
            }

            return await PersistValidationAsync(
                connection.Id,
                ownerOperatorId,
                AzureConnectionValidationStatus.Failed,
                message,
                connection.DisplayName,
                canReadGroups,
                canReadConditionalAccess,
                canReadRecommendations,
                intuneProbe.CanReadManagedDevices,
                intuneProbe.CanReadIntuneDeviceConfigurations,
                intuneProbe.CanReadIntuneCompliancePolicies,
                intuneProbe.EnrolledDeviceCount,
                intuneProbe.HasIntuneDeviceConfigurations,
                intuneProbe.HasIntuneCompliancePolicies,
                intuneProbe.Message,
                entraDailyUseProbe.CanManageEntraDailyUseHardening,
                entraDailyUseProbe.Message,
                teamsProbe.Succeeded,
                teamsProbe.Message,
                certificateProbe,
                cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            return await PersistValidationAsync(
                connection.Id,
                ownerOperatorId,
                AzureConnectionValidationStatus.Failed,
                $"Validation failed for '{connection.DisplayName}'. {NormalizeMessage(ex.Message)}",
                connection.DisplayName,
                false,
                false,
                false,
                false,
                false,
                false,
                0,
                false,
                false,
                null,
                false,
                null,
                false,
                null,
                certificateProbe,
                cancellationToken);
        }
    }

    private static AzureConnectionProfile ToProfile(StoredAzureConnectionProfile stored)
    {
        return new AzureConnectionProfile(
            stored.Id,
            stored.OwnerOperatorId,
            stored.DisplayName,
            stored.TenantId,
            stored.ClientId,
            stored.RedirectUri,
            !string.IsNullOrWhiteSpace(stored.ProtectedClientSecret),
            stored.AutomationCertificateThumbprint,
            NormalizeAutomationCertificateStoreLocation(stored.AutomationCertificateStoreLocation),
            NormalizeAutomationCertificateStoreName(stored.AutomationCertificateStoreName),
            Enum.IsDefined(typeof(AutomationCertificateStatus), stored.AutomationCertificateStatus)
                ? (AutomationCertificateStatus)stored.AutomationCertificateStatus
                : AutomationCertificateStatus.NotConfigured,
            stored.AutomationCertificateSubject,
            stored.AutomationCertificateExpiresUtc,
            stored.AutomationCertificateMessage,
            stored.CreatedUtc,
            stored.UpdatedUtc,
            ResolveSecretUpdatedUtc(stored),
            Enum.IsDefined(typeof(AzureConnectionValidationStatus), stored.ValidationStatus)
                ? (AzureConnectionValidationStatus)stored.ValidationStatus
                : AzureConnectionValidationStatus.Unknown,
            stored.LastValidationAttemptUtc,
            stored.LastValidationSuccessUtc,
            stored.LastValidationError,
            stored.CanReadGroups,
            stored.CanReadConditionalAccess,
            stored.CanReadRecommendations,
            stored.CanReadManagedDevices,
            stored.CanReadIntuneDeviceConfigurations,
            stored.CanReadIntuneCompliancePolicies,
            stored.IntuneEnrolledDeviceCount,
            stored.HasIntuneDeviceConfigurations,
            stored.HasIntuneCompliancePolicies,
            stored.IntuneAutomationMessage,
            stored.CanManageEntraDailyUseHardening,
            stored.EntraDailyUseAutomationMessage,
            stored.CanManageTeamsMeetingPolicy,
            stored.TeamsAutomationMessage,
            TenantLicenseCapabilityCatalog.NormalizeSelected(stored.DeclaredLicenseCapabilities));
    }

    private async Task<AzureConnectionValidationOutcome> PersistValidationAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        AzureConnectionValidationStatus validationStatus,
        string message,
        string? connectionDisplayName,
        bool canReadGroups,
        bool canReadConditionalAccess,
        bool canReadRecommendations,
        bool canReadManagedDevices,
        bool canReadIntuneDeviceConfigurations,
        bool canReadIntuneCompliancePolicies,
        int intuneEnrolledDeviceCount,
        bool hasIntuneDeviceConfigurations,
        bool hasIntuneCompliancePolicies,
        string? intuneAutomationMessage,
        bool canManageEntraDailyUseHardening,
        string? entraDailyUseAutomationMessage,
        bool canManageTeamsMeetingPolicy,
        string? teamsAutomationMessage,
        AutomationCertificateProbeResult certificateProbe,
        CancellationToken cancellationToken)
    {
        var attemptedUtc = DateTimeOffset.UtcNow;

        return await _stateStore.WriteAsync(state =>
        {
            var stored = state.Connections.FirstOrDefault(item =>
                item.Id == connectionId && item.OwnerOperatorId == ownerOperatorId);

            if (stored is null)
            {
                return new AzureConnectionValidationOutcome(
                    connectionId,
                    connectionDisplayName ?? "Unknown connection",
                    AzureConnectionValidationStatus.Failed,
                    false,
                    "The selected Azure connection could not be found.",
                    attemptedUtc,
                    canReadGroups,
                    canReadConditionalAccess,
                    canReadRecommendations);
            }

            stored.ValidationStatus = (int)validationStatus;
            stored.LastValidationAttemptUtc = attemptedUtc;
            stored.LastValidationError = validationStatus == AzureConnectionValidationStatus.Succeeded
                ? null
                : NormalizeMessage(message);
            stored.SecretUpdatedUtc = ResolveSecretUpdatedUtc(stored);
            stored.CanReadGroups = canReadGroups;
            stored.CanReadConditionalAccess = canReadConditionalAccess;
            stored.CanReadRecommendations = canReadRecommendations;
            stored.CanReadManagedDevices = canReadManagedDevices;
            stored.CanReadIntuneDeviceConfigurations = canReadIntuneDeviceConfigurations;
            stored.CanReadIntuneCompliancePolicies = canReadIntuneCompliancePolicies;
            stored.IntuneEnrolledDeviceCount = Math.Max(0, intuneEnrolledDeviceCount);
            stored.HasIntuneDeviceConfigurations = hasIntuneDeviceConfigurations;
            stored.HasIntuneCompliancePolicies = hasIntuneCompliancePolicies;
            stored.IntuneAutomationMessage = string.IsNullOrWhiteSpace(intuneAutomationMessage)
                ? null
                : NormalizeMessage(intuneAutomationMessage);
            stored.CanManageEntraDailyUseHardening = canManageEntraDailyUseHardening;
            stored.EntraDailyUseAutomationMessage = string.IsNullOrWhiteSpace(entraDailyUseAutomationMessage)
                ? null
                : NormalizeMessage(entraDailyUseAutomationMessage);
            stored.CanManageTeamsMeetingPolicy = canManageTeamsMeetingPolicy;
            stored.TeamsAutomationMessage = string.IsNullOrWhiteSpace(teamsAutomationMessage)
                ? null
                : NormalizeMessage(teamsAutomationMessage);
            stored.AutomationCertificateStatus = (int)certificateProbe.Status;
            stored.AutomationCertificateSubject = certificateProbe.Subject;
            stored.AutomationCertificateExpiresUtc = certificateProbe.ExpiresUtc;
            stored.AutomationCertificateMessage = certificateProbe.Message;

            if (validationStatus == AzureConnectionValidationStatus.Succeeded)
            {
                stored.LastValidationSuccessUtc = attemptedUtc;
            }

            return new AzureConnectionValidationOutcome(
                stored.Id,
                stored.DisplayName,
                validationStatus,
                validationStatus == AzureConnectionValidationStatus.Succeeded,
                NormalizeMessage(message),
                attemptedUtc,
                canReadGroups,
                canReadConditionalAccess,
                canReadRecommendations);
        }, cancellationToken);
    }

    private async Task<TeamsMeetingPolicyAutomationClient.TeamsMeetingPolicyProbeResult> ProbeTeamsMeetingPolicyCapabilityAsync(
        StoredAzureConnectionProfile connection,
        string clientSecret,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _teamsMeetingPolicyClient.ProbeGlobalMeetingPolicyReadAsync(
                connection.TenantId,
                connection.ClientId,
                clientSecret,
                cancellationToken);
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException)
        {
            return new TeamsMeetingPolicyAutomationClient.TeamsMeetingPolicyProbeResult(
                false,
                NormalizeMessage(ex.Message));
        }
    }

    private async Task<IntuneCapabilityProbeResult> ProbeIntuneCapabilityAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        var graphRoles = ParseGraphRoles(accessToken);
        var canWriteIntuneDeviceConfigurations = graphRoles.Contains(
            "DeviceManagementConfiguration.ReadWrite.All",
            StringComparer.OrdinalIgnoreCase);
        var notes = new List<string>();
        var canReadManagedDevices = false;
        var canReadIntuneDeviceConfigurations = false;
        var canReadIntuneCompliancePolicies = false;
        var enrolledDeviceCount = 0;
        var hasIntuneDeviceConfigurations = false;
        var hasIntuneCompliancePolicies = false;

        try
        {
            var managedDeviceResult = await _intuneManagementClient.ProbeManagedDevicesAsync(accessToken, cancellationToken);
            canReadManagedDevices = true;
            enrolledDeviceCount = managedDeviceResult.EnrolledDeviceCount;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            notes.Add($"Managed devices blocked: {NormalizeMessage(ex.Message)}");
        }

        try
        {
            var deviceConfigurationResult = await _intuneManagementClient.ProbeDeviceConfigurationsAsync(accessToken, cancellationToken);
            canReadIntuneDeviceConfigurations = true;
            hasIntuneDeviceConfigurations = deviceConfigurationResult.HasAnyPolicies;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            notes.Add($"Device configurations blocked: {NormalizeMessage(ex.Message)}");
        }

        try
        {
            var compliancePolicyResult = await _intuneManagementClient.ProbeDeviceCompliancePoliciesAsync(accessToken, cancellationToken);
            canReadIntuneCompliancePolicies = true;
            hasIntuneCompliancePolicies = compliancePolicyResult.HasAnyPolicies;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            notes.Add($"Compliance policies blocked: {NormalizeMessage(ex.Message)}");
        }

        if (notes.Count == 0)
        {
            notes.Add(
                $"Intune device management is ready. Enrolled devices: {enrolledDeviceCount}. Device configurations: {(hasIntuneDeviceConfigurations ? "present" : "none yet")}. Compliance policies: {(hasIntuneCompliancePolicies ? "present" : "none yet")}.");
        }

        notes.Add(
            canWriteIntuneDeviceConfigurations
                ? "Intune write-side automation is ready for device-configuration baselines."
                : "Intune write-side automation is still blocked because the app token does not include Microsoft Graph DeviceManagementConfiguration.ReadWrite.All.");

        return new IntuneCapabilityProbeResult(
            canReadManagedDevices,
            canReadIntuneDeviceConfigurations,
            canReadIntuneCompliancePolicies,
            enrolledDeviceCount,
            hasIntuneDeviceConfigurations,
            hasIntuneCompliancePolicies,
            string.Join(" ", notes));
    }

    private static EntraDailyUseCapabilityProbeResult ProbeEntraDailyUseCapability(
        string accessToken)
    {
        var graphRoles = ParseGraphRoles(accessToken);
        var missingPermissions = new List<string>();

        if (!graphRoles.Contains("Policy.ReadWrite.Authorization", StringComparer.OrdinalIgnoreCase))
        {
            missingPermissions.Add("Policy.ReadWrite.Authorization");
        }

        if (!graphRoles.Contains("Policy.ReadWrite.ConsentRequest", StringComparer.OrdinalIgnoreCase))
        {
            missingPermissions.Add("Policy.ReadWrite.ConsentRequest");
        }

        if (!graphRoles.Contains("Domain.ReadWrite.All", StringComparer.OrdinalIgnoreCase))
        {
            missingPermissions.Add("Domain.ReadWrite.All");
        }

        return missingPermissions.Count == 0
            ? new EntraDailyUseCapabilityProbeResult(
                true,
                "Entra daily-use write automation is ready for authorization policy, admin consent workflow, and default domain password-policy updates.")
            : new EntraDailyUseCapabilityProbeResult(
                false,
                $"Entra daily-use write automation is still blocked because the app token does not include {string.Join(", ", missingPermissions)}.");
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

    private static DateTimeOffset ResolveSecretUpdatedUtc(StoredAzureConnectionProfile stored)
    {
        if (stored.SecretUpdatedUtc != default)
        {
            return stored.SecretUpdatedUtc;
        }

        return stored.UpdatedUtc != default ? stored.UpdatedUtc : stored.CreatedUtc;
    }

    private static string NormalizeAutomationCertificateThumbprint(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return new string(value.Where(static character => !char.IsWhiteSpace(character)).ToArray()).ToUpperInvariant();
    }

    private static string NormalizeAutomationCertificateStoreLocation(string? value)
    {
        return Enum.TryParse<StoreLocation>(value?.Trim(), ignoreCase: true, out var parsedLocation)
            ? parsedLocation.ToString()
            : DefaultAutomationCertificateStoreLocation;
    }

    private static string NormalizeAutomationCertificateStoreName(string? value)
    {
        return Enum.TryParse<StoreName>(value?.Trim(), ignoreCase: true, out var parsedStoreName)
            ? parsedStoreName.ToString()
            : DefaultAutomationCertificateStoreName;
    }

    private static AutomationCertificateProbeResult ProbeAutomationCertificate(StoredAzureConnectionProfile connection)
    {
        var thumbprint = NormalizeAutomationCertificateThumbprint(connection.AutomationCertificateThumbprint);
        var storeLocationText = NormalizeAutomationCertificateStoreLocation(connection.AutomationCertificateStoreLocation);
        var storeNameText = NormalizeAutomationCertificateStoreName(connection.AutomationCertificateStoreName);

        if (string.IsNullOrWhiteSpace(thumbprint))
        {
            return new AutomationCertificateProbeResult(
                AutomationCertificateStatus.NotConfigured,
                null,
                null,
                "No automation certificate is configured yet. Add a thumbprint when you are ready to enable Exchange, SharePoint, Teams, or Purview admin providers.");
        }

        try
        {
            var storeLocation = Enum.Parse<StoreLocation>(storeLocationText, ignoreCase: true);
            var storeName = Enum.Parse<StoreName>(storeNameText, ignoreCase: true);
            using var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);

            var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
            var certificate = certificates
                .OfType<X509Certificate2>()
                .OrderByDescending(item => item.NotAfter)
                .FirstOrDefault();

            if (certificate is null)
            {
                return new AutomationCertificateProbeResult(
                    AutomationCertificateStatus.NotFound,
                    null,
                    null,
                    $"Automation certificate '{thumbprint}' was not found in {storeLocation}.{storeName} on this host.");
            }

            var expiresUtc = new DateTimeOffset(certificate.NotAfter.ToUniversalTime());

            if (!certificate.HasPrivateKey)
            {
                return new AutomationCertificateProbeResult(
                    AutomationCertificateStatus.MissingPrivateKey,
                    certificate.Subject,
                    expiresUtc,
                    $"Automation certificate '{thumbprint}' was found in {storeLocation}.{storeName}, but the private key is not available to the app.");
            }

            if (DateTimeOffset.UtcNow >= expiresUtc)
            {
                return new AutomationCertificateProbeResult(
                    AutomationCertificateStatus.Expired,
                    certificate.Subject,
                    expiresUtc,
                    $"Automation certificate '{thumbprint}' was found in {storeLocation}.{storeName}, but it is expired.");
            }

            return new AutomationCertificateProbeResult(
                AutomationCertificateStatus.Ready,
                certificate.Subject,
                expiresUtc,
                $"Automation certificate '{thumbprint}' is available in {storeLocation}.{storeName} with a usable private key.");
        }
        catch (Exception ex) when (ex is CryptographicException or SecurityException or UnauthorizedAccessException)
        {
            return new AutomationCertificateProbeResult(
                AutomationCertificateStatus.Error,
                null,
                null,
                $"Automation certificate validation failed. {NormalizeMessage(ex.Message)}");
        }
    }

    private static async Task<bool> ProbeCapabilityAsync(
        Func<Task> probe,
        string capabilityName,
        ICollection<string> errors)
    {
        try
        {
            await probe();
            return true;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            errors.Add($"{capabilityName}: {NormalizeMessage(ex.Message)}");
            return false;
        }
    }

    private static string NormalizeMessage(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "No message was recorded.";
        }

        var normalized = value.Trim().ReplaceLineEndings(" ");
        return normalized.Length <= 320 ? normalized : normalized[..320];
    }

    private sealed record AutomationCertificateProbeResult(
        AutomationCertificateStatus Status,
        string? Subject,
        DateTimeOffset? ExpiresUtc,
        string Message);

    private sealed record IntuneCapabilityProbeResult(
        bool CanReadManagedDevices,
        bool CanReadIntuneDeviceConfigurations,
        bool CanReadIntuneCompliancePolicies,
        int EnrolledDeviceCount,
        bool HasIntuneDeviceConfigurations,
        bool HasIntuneCompliancePolicies,
        string Message);

    private sealed record EntraDailyUseCapabilityProbeResult(
        bool CanManageEntraDailyUseHardening,
        string Message);
}
