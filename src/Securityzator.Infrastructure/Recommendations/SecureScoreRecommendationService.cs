using Securityzator.Application.Blueprints;
using Securityzator.Application.Portal;
using Securityzator.Application.Recommendations;
using Securityzator.Infrastructure.Graph;
using Securityzator.Infrastructure.Security;
using Securityzator.Infrastructure.Storage;

namespace Securityzator.Infrastructure.Recommendations;

public sealed class SecureScoreRecommendationService : IRecommendationService
{
    private readonly JsonFileSecurityzatorStateStore _stateStore;
    private readonly ClientSecretProtector _secretProtector;
    private readonly GraphAccessTokenService _tokenService;
    private readonly SecureScoreGraphClient _graphClient;
    private readonly IProductBlueprintService _blueprintService;

    public SecureScoreRecommendationService(
        JsonFileSecurityzatorStateStore stateStore,
        ClientSecretProtector secretProtector,
        GraphAccessTokenService tokenService,
        SecureScoreGraphClient graphClient,
        IProductBlueprintService blueprintService)
    {
        _stateStore = stateStore;
        _secretProtector = secretProtector;
        _tokenService = tokenService;
        _graphClient = graphClient;
        _blueprintService = blueprintService;
    }

    public Task<IReadOnlyList<ConnectionRecommendationSummary>> ListConnectionSummariesAsync(
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default)
    {
        return _stateStore.ReadAsync<IReadOnlyList<ConnectionRecommendationSummary>>(state =>
        {
            var syncStateByConnectionId = state.RecommendationSyncStates
                .Where(syncState => syncState.OwnerOperatorId == ownerOperatorId)
                .ToDictionary(syncState => syncState.ConnectionId);

            return state.Connections
                .Where(connection => connection.OwnerOperatorId == ownerOperatorId)
                .OrderBy(connection => connection.DisplayName, StringComparer.OrdinalIgnoreCase)
                .Select(connection =>
                {
                    if (syncStateByConnectionId.TryGetValue(connection.Id, out var syncState))
                    {
                        return ToSummary(connection, syncState);
                    }

                    return new ConnectionRecommendationSummary(
                        connection.Id,
                        connection.DisplayName,
                        connection.TenantId,
                        !string.IsNullOrWhiteSpace(connection.ProtectedClientSecret),
                        RecommendationSyncStatus.NotStarted,
                        null,
                        null,
                        0,
                        null);
                })
                .ToArray();
        }, cancellationToken);
    }

    public async Task<IReadOnlyList<RecommendationCoverageSummary>> ListCoverageSummariesAsync(
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default)
    {
        var templateMap = await BuildRemediationTemplateMapAsync(cancellationToken);
        var templateLookup = await BuildTemplateLookupAsync(cancellationToken);

        return await _stateStore.ReadAsync<IReadOnlyList<RecommendationCoverageSummary>>(state =>
        {
            var syncStateByConnectionId = state.RecommendationSyncStates
                .Where(syncState => syncState.OwnerOperatorId == ownerOperatorId)
                .ToDictionary(syncState => syncState.ConnectionId);

            return state.Connections
                .Where(connection => connection.OwnerOperatorId == ownerOperatorId)
                .OrderBy(connection => connection.DisplayName, StringComparer.OrdinalIgnoreCase)
                .Select(connection =>
                {
                    syncStateByConnectionId.TryGetValue(connection.Id, out var syncState);
                    return ToCoverageSummary(connection, syncState, templateMap, templateLookup);
                })
                .ToArray();
        }, cancellationToken);
    }

    public async Task<RecommendationSnapshot?> GetLatestSnapshotAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default)
    {
        var templateMap = await BuildRemediationTemplateMapAsync(cancellationToken);

        return await _stateStore.ReadAsync<RecommendationSnapshot?>(state =>
        {
            var connection = state.Connections.FirstOrDefault(item =>
                item.Id == connectionId && item.OwnerOperatorId == ownerOperatorId);

            if (connection is null)
            {
                return null;
            }

            var syncState = state.RecommendationSyncStates.FirstOrDefault(item =>
                item.ConnectionId == connectionId && item.OwnerOperatorId == ownerOperatorId);

            return syncState is null
                ? new RecommendationSnapshot(
                    connection.Id,
                    connection.DisplayName,
                    connection.TenantId,
                    RecommendationSyncStatus.NotStarted,
                    null,
                    null,
                    0,
                    null,
                    Array.Empty<RecommendationRecord>())
                : ToSnapshot(connection, syncState, templateMap);
        }, cancellationToken);
    }

    public async Task<RecommendationSyncOutcome> SyncAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default)
    {
        var syncContext = await _stateStore.ReadAsync(state =>
        {
            var connection = state.Connections.FirstOrDefault(item =>
                item.Id == connectionId && item.OwnerOperatorId == ownerOperatorId);

            if (connection is null)
            {
                return null;
            }

            return new RecommendationSyncContext(
                connection.Id,
                connection.OwnerOperatorId,
                connection.DisplayName,
                connection.TenantId,
                connection.ClientId,
                connection.ProtectedClientSecret);
        }, cancellationToken);

        if (syncContext is null)
        {
            return new RecommendationSyncOutcome(
                connectionId,
                "Unknown connection",
                RecommendationSyncStatus.Failed,
                false,
                "The selected connection no longer exists.",
                DateTimeOffset.UtcNow,
                0);
        }

        if (string.IsNullOrWhiteSpace(syncContext.ProtectedClientSecret))
        {
            return await PersistFailureAsync(
                syncContext,
                "This connection does not have a stored client secret. Update the profile before syncing recommendations.",
                cancellationToken);
        }

        try
        {
            var clientSecret = _secretProtector.Unprotect(syncContext.ProtectedClientSecret);
            var accessToken = await _tokenService.AcquireApplicationTokenAsync(
                syncContext.TenantId,
                syncContext.ClientId,
                clientSecret,
                cancellationToken);

            var controlProfiles = await _graphClient.ListSecureScoreControlProfilesAsync(accessToken, cancellationToken);
            var templateMap = await BuildRemediationTemplateMapAsync(cancellationToken);
            var storedRecords = controlProfiles
                .OrderBy(profile => profile.Rank)
                .ThenBy(profile => profile.Title, StringComparer.OrdinalIgnoreCase)
                .Select(profile => new StoredRecommendationRecord
                {
                    ControlId = profile.ControlId,
                    Title = profile.Title,
                    Category = profile.Category,
                    Product = profile.Product,
                    Rank = profile.Rank,
                    MaxScore = profile.MaxScore,
                    Tier = profile.Tier,
                    ImplementationCost = profile.ImplementationCost,
                    UserImpact = profile.UserImpact,
                    ActionType = profile.ActionType,
                    Remediation = profile.Remediation,
                    RemediationImpact = profile.RemediationImpact,
                    IsDeprecated = profile.IsDeprecated,
                    Threats = profile.Threats.ToList(),
                    RemediationTemplateKey = ResolveRemediationTemplateKey(profile, templateMap)
                })
                .ToList();

            var attemptedUtc = DateTimeOffset.UtcNow;
            var recommendationCount = await _stateStore.WriteAsync(state =>
            {
                var syncState = GetOrCreateSyncState(state, syncContext.ConnectionId, syncContext.OwnerOperatorId);
                syncState.SyncStatus = RecommendationSyncStatus.Succeeded;
                syncState.LastAttemptUtc = attemptedUtc;
                syncState.LastSuccessUtc = attemptedUtc;
                syncState.LastError = null;
                syncState.Recommendations = storedRecords;
                return syncState.Recommendations.Count;
            }, cancellationToken);

            return new RecommendationSyncOutcome(
                syncContext.ConnectionId,
                syncContext.DisplayName,
                RecommendationSyncStatus.Succeeded,
                true,
                $"Synced {recommendationCount} Secure Score recommendation{(recommendationCount == 1 ? string.Empty : "s")} for '{syncContext.DisplayName}'.",
                attemptedUtc,
                recommendationCount);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is GraphServiceException or HttpRequestException or InvalidOperationException)
        {
            return await PersistFailureAsync(syncContext, ex.Message, cancellationToken);
        }
    }

    public async Task<RecommendationMappingBackfillOutcome> BackfillMappingsAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default)
    {
        var templateMap = await BuildRemediationTemplateMapAsync(cancellationToken);

        return await _stateStore.WriteAsync(state =>
        {
            var connection = state.Connections.FirstOrDefault(item =>
                item.Id == connectionId && item.OwnerOperatorId == ownerOperatorId);

            if (connection is null)
            {
                return new RecommendationMappingBackfillOutcome(
                    connectionId,
                    "Unknown connection",
                    false,
                    0,
                    0,
                    0,
                    "The selected connection no longer exists.");
            }

            var syncState = state.RecommendationSyncStates.FirstOrDefault(item =>
                item.ConnectionId == connectionId && item.OwnerOperatorId == ownerOperatorId);

            if (syncState is null || syncState.Recommendations.Count == 0)
            {
                return new RecommendationMappingBackfillOutcome(
                    connection.Id,
                    connection.DisplayName,
                    false,
                    0,
                    0,
                    0,
                    $"Connection '{connection.DisplayName}' does not have a cached recommendation snapshot yet. Run sync first.");
            }

            var updatedCount = 0;
            foreach (var record in syncState.Recommendations)
            {
                var computedTemplateKey = ResolveRemediationTemplateKey(record, templateMap);
                if (string.Equals(record.RemediationTemplateKey, computedTemplateKey, StringComparison.Ordinal))
                {
                    continue;
                }

                record.RemediationTemplateKey = computedTemplateKey;
                updatedCount++;
            }

            return new RecommendationMappingBackfillOutcome(
                connection.Id,
                connection.DisplayName,
                true,
                syncState.Recommendations.Count,
                updatedCount,
                0,
                updatedCount == 0
                    ? $"Cached recommendation mappings for '{connection.DisplayName}' were already current."
                    : $"Refreshed {updatedCount} cached recommendation mapping{(updatedCount == 1 ? string.Empty : "s")} for '{connection.DisplayName}'.");
        }, cancellationToken);
    }

    private async Task<RecommendationSyncOutcome> PersistFailureAsync(
        RecommendationSyncContext syncContext,
        string errorMessage,
        CancellationToken cancellationToken)
    {
        var attemptedUtc = DateTimeOffset.UtcNow;
        var recommendationCount = await _stateStore.WriteAsync(state =>
        {
            var syncState = GetOrCreateSyncState(state, syncContext.ConnectionId, syncContext.OwnerOperatorId);
            syncState.SyncStatus = RecommendationSyncStatus.Failed;
            syncState.LastAttemptUtc = attemptedUtc;
            syncState.LastError = NormalizeErrorMessage(errorMessage);
            return syncState.Recommendations.Count;
        }, cancellationToken);

        return new RecommendationSyncOutcome(
            syncContext.ConnectionId,
            syncContext.DisplayName,
            RecommendationSyncStatus.Failed,
            false,
            $"Recommendation sync failed for '{syncContext.DisplayName}'. {NormalizeErrorMessage(errorMessage)}",
            attemptedUtc,
            recommendationCount);
    }

    private async Task<Dictionary<string, string>> BuildRemediationTemplateMapAsync(
        CancellationToken cancellationToken)
    {
        var blueprint = await _blueprintService.GetPortalBlueprintAsync(cancellationToken);
        var map = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var item in blueprint.RecommendationCatalog)
        {
            map[NormalizeTitle(item.Title)] = item.RemediationTemplateKey;

            foreach (var alias in item.Aliases.Where(alias => !string.IsNullOrWhiteSpace(alias)))
            {
                map[NormalizeTitle(alias)] = item.RemediationTemplateKey;
            }
        }

        return map;
    }

    private async Task<IReadOnlyDictionary<string, RemediationTemplate>> BuildTemplateLookupAsync(
        CancellationToken cancellationToken)
    {
        var blueprint = await _blueprintService.GetPortalBlueprintAsync(cancellationToken);
        return blueprint.RemediationTemplates.ToDictionary(template => template.Key, StringComparer.Ordinal);
    }

    private static StoredRecommendationSyncState GetOrCreateSyncState(
        SecurityzatorStateDocument state,
        Guid connectionId,
        Guid ownerOperatorId)
    {
        var syncState = state.RecommendationSyncStates.FirstOrDefault(item =>
            item.ConnectionId == connectionId && item.OwnerOperatorId == ownerOperatorId);

        if (syncState is not null)
        {
            return syncState;
        }

        syncState = new StoredRecommendationSyncState
        {
            ConnectionId = connectionId,
            OwnerOperatorId = ownerOperatorId
        };

        state.RecommendationSyncStates.Add(syncState);
        return syncState;
    }

    private static ConnectionRecommendationSummary ToSummary(
        StoredAzureConnectionProfile connection,
        StoredRecommendationSyncState syncState)
    {
        return new ConnectionRecommendationSummary(
            connection.Id,
            connection.DisplayName,
            connection.TenantId,
            !string.IsNullOrWhiteSpace(connection.ProtectedClientSecret),
            syncState.SyncStatus,
            syncState.LastAttemptUtc,
            syncState.LastSuccessUtc,
            syncState.Recommendations.Count,
            syncState.LastError);
    }

    private static RecommendationCoverageSummary ToCoverageSummary(
        StoredAzureConnectionProfile connection,
        StoredRecommendationSyncState? syncState,
        IReadOnlyDictionary<string, string> templateMap,
        IReadOnlyDictionary<string, RemediationTemplate> templateLookup)
    {
        if (syncState is null)
        {
            return new RecommendationCoverageSummary(
                connection.Id,
                connection.DisplayName,
                connection.TenantId,
                RecommendationSyncStatus.NotStarted,
                null,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                Array.Empty<RecommendationCoverageTemplateBucket>());
        }

        var coverageRecords = syncState.Recommendations
            .Select(record =>
            {
                var storedTemplateKey = NormalizeTemplateKey(record.RemediationTemplateKey);
                var computedTemplateKey = NormalizeTemplateKey(ResolveRemediationTemplateKey(record, templateMap));
                RemediationTemplate? template = null;
                var hasTemplate = computedTemplateKey is not null
                    && templateLookup.TryGetValue(computedTemplateKey, out template);

                var classification = computedTemplateKey is null
                    ? RecommendationCoverageClassification.Unmapped
                    : !hasTemplate
                        ? RecommendationCoverageClassification.MissingTemplate
                        : template!.SupportsQueueExecution
                            ? RecommendationCoverageClassification.RunnableNow
                            : RecommendationCoverageClassification.MappedFamily;

                return new RecommendationCoverageRecord(
                    computedTemplateKey,
                    storedTemplateKey,
                    classification,
                    template);
            })
            .ToArray();

        var topTemplates = coverageRecords
            .Where(record =>
                record.Classification is RecommendationCoverageClassification.RunnableNow
                or RecommendationCoverageClassification.MappedFamily)
            .GroupBy(record => record.TemplateKey!, StringComparer.Ordinal)
            .Select(group =>
            {
                var template = group.First().Template!;
                return new RecommendationCoverageTemplateBucket(
                    group.Key,
                    template.Name,
                    group.Count(),
                    template.SupportsQueueExecution);
            })
            .OrderByDescending(bucket => bucket.ControlCount)
            .ThenBy(bucket => bucket.TemplateName, StringComparer.OrdinalIgnoreCase)
            .Take(5)
            .ToArray();

        return new RecommendationCoverageSummary(
            connection.Id,
            connection.DisplayName,
            connection.TenantId,
            syncState.SyncStatus,
            syncState.LastSuccessUtc,
            syncState.Recommendations.Count,
            coverageRecords.Count(record =>
                record.Classification is RecommendationCoverageClassification.RunnableNow
                or RecommendationCoverageClassification.MappedFamily),
            coverageRecords.Count(record => record.Classification == RecommendationCoverageClassification.RunnableNow),
            coverageRecords.Count(record => record.Classification == RecommendationCoverageClassification.MappedFamily),
            coverageRecords.Count(record => record.Classification == RecommendationCoverageClassification.Unmapped),
            coverageRecords.Count(record => record.Classification == RecommendationCoverageClassification.MissingTemplate),
            coverageRecords.Count(record => !string.Equals(record.StoredTemplateKey, record.TemplateKey, StringComparison.Ordinal)),
            topTemplates);
    }

    private static RecommendationSnapshot ToSnapshot(
        StoredAzureConnectionProfile connection,
        StoredRecommendationSyncState syncState,
        IReadOnlyDictionary<string, string> templateMap)
    {
        return new RecommendationSnapshot(
            connection.Id,
            connection.DisplayName,
            connection.TenantId,
            syncState.SyncStatus,
            syncState.LastAttemptUtc,
            syncState.LastSuccessUtc,
            syncState.Recommendations.Count,
            syncState.LastError,
            syncState.Recommendations
                .OrderBy(item => item.Rank)
                .ThenBy(item => item.Title, StringComparer.OrdinalIgnoreCase)
                .Select(item => new RecommendationRecord(
                    item.ControlId,
                    item.Title,
                    item.Category,
                    item.Product,
                    item.Rank,
                    item.MaxScore,
                    item.Tier,
                    item.ImplementationCost,
                    item.UserImpact,
                    item.ActionType,
                    item.Remediation,
                    item.RemediationImpact,
                    item.IsDeprecated,
                    item.Threats.ToArray(),
                    ResolveRemediationTemplateKey(item, templateMap) ?? item.RemediationTemplateKey))
                .ToArray());
    }

    private static string? ResolveRemediationTemplateKey(
        GraphSecureScoreControlProfile profile,
        IReadOnlyDictionary<string, string> templateMap)
    {
        return ResolveRemediationTemplateKey(profile.Title, profile.Product, profile.Category, templateMap);
    }

    private static string? ResolveRemediationTemplateKey(
        StoredRecommendationRecord record,
        IReadOnlyDictionary<string, string> templateMap)
    {
        return ResolveRemediationTemplateKey(record.Title, record.Product, record.Category, templateMap);
    }

    private static string? ResolveRemediationTemplateKey(
        string title,
        IReadOnlyDictionary<string, string> templateMap)
    {
        return ResolveRemediationTemplateKey(title, string.Empty, string.Empty, templateMap);
    }

    private static string? ResolveRemediationTemplateKey(
        string title,
        string? product,
        string? category,
        IReadOnlyDictionary<string, string> templateMap)
    {
        var normalizedTitle = NormalizeTitle(title);
        var normalizedProduct = NormalizeTitle(product ?? string.Empty);
        var normalizedCategory = NormalizeTitle(category ?? string.Empty);

        if (templateMap.TryGetValue(normalizedTitle, out var templateKey))
        {
            return templateKey;
        }

        if (normalizedTitle.Contains("LEGACY AUTHENTICATION", StringComparison.Ordinal))
        {
            return "block-legacy-auth";
        }

        if (ContainsAll(normalizedTitle, "MULTIFACTOR AUTHENTICATION", "ADMINISTRATIVE ROLES"))
        {
            return "require-mfa-admins";
        }

        if (ContainsAll(normalizedTitle, "MULTIFACTOR AUTHENTICATION", "ALL USERS"))
        {
            return "mfa-all-users";
        }

        if (normalizedTitle.Contains("SIGN-IN RISK", StringComparison.Ordinal))
        {
            return "require-mfa-risky-sign-ins";
        }

        if (normalizedTitle.Contains("USER RISK", StringComparison.Ordinal))
        {
            return "require-password-change-high-risk-users";
        }

        if (ContainsAll(normalizedTitle, "SECURITY INFO", "REGISTRATION"))
        {
            return "secure-security-info-registration";
        }

        if (ContainsAll(normalizedTitle, "IDENTITY PROTECTION", "RISK"))
        {
            return "entra-risk-policies";
        }

        if (normalizedTitle.Contains("MICROSOFT AZURE MANAGEMENT", StringComparison.Ordinal))
        {
            return "require-mfa-azure-management";
        }

        if (ContainsAny(
                normalizedTitle,
                "PASSWORD HASH SYNC",
                "USER CONSENT TO APPS",
                "LEAST PRIVILEGED ADMINISTRATIVE ROLES",
                "SELF SERVICE PASSWORD RESET",
                "PASSWORD EXPIRATION POLICY",
                "DESIGNATE MORE THAN ONE GLOBAL ADMIN",
                "LINKEDIN ACCOUNT CONNECTIONS",
                "ADMINISTRATIVE ACCOUNTS ARE SEPARATE AND CLOUD-ONLY",
                "CUSTOM BANNED PASSWORDS LISTS",
                "PASSWORD PROTECTION IS ENABLED FOR ON-PREM ACTIVE DIRECTORY",
                "SIGN-IN FREQUENCY IS ENABLED",
                "ORGANIZATIONALLY MANAGED/APPROVED PUBLIC GROUPS",
                "ADMIN CONSENT WORKFLOW",
                "THIRD PARTY INTEGRATED APPLICATIONS",
                "LEAKED CREDENTIALS"))
        {
            if (IsEntraDailyUseHardening(normalizedTitle))
            {
                return "entra-daily-use-hardening";
            }

            return normalizedTitle.Contains("LEAKED CREDENTIALS", StringComparison.Ordinal)
                ? "entra-risk-policies"
                : "entra-identity-hygiene-baseline";
        }

        if (ContainsAll(normalizedTitle, "PHISHING-RESISTANT", "MFA")
            && (normalizedTitle.Contains("ADMINISTRATOR", StringComparison.Ordinal)
                || normalizedTitle.Contains("ADMINISTRATIVE", StringComparison.Ordinal)))
        {
            return "require-phishing-resistant-mfa-admins";
        }

        if (ContainsAny(
                normalizedTitle,
                "DEFENDER FOR CLOUD APPS",
                "LOG COLLECTOR",
                "SHADOW IT"))
        {
            return "defender-cloud-apps-foundation";
        }

        if (IsDefenderForOfficeAntiPhishing(normalizedTitle))
        {
            return "mdo-anti-phishing-and-impersonation";
        }

        if (IsDefenderForOfficeAntiMalware(normalizedTitle))
        {
            return "mdo-anti-malware-baseline";
        }

        if (IsDefenderForOfficeSafeLinksAndAttachments(normalizedTitle))
        {
            return "mdo-safe-links-and-attachments";
        }

        if (IsDefenderForOfficeSpamAndForwarding(normalizedTitle))
        {
            return "mdo-spam-and-forwarding-baseline";
        }

        if (IsExchangeOnlineCollaborationAndMailbox(normalizedTitle))
        {
            return "exchange-online-collaboration-and-mailbox";
        }

        if (IsPurviewDataProtection(normalizedTitle))
        {
            return "purview-data-protection-baseline";
        }

        if (IsTeamsMeetingHardening(normalizedTitle))
        {
            return "teams-meeting-hardening";
        }

        if (IsSharePointOnlineHardening(normalizedTitle))
        {
            return "sharepoint-online-session-hardening";
        }

        if (ContainsAny(
                normalizedTitle,
                "DEFENDER FOR IDENTITY",
                "INSTALLING SENSORS",
                "DOMAIN CONTROLLERS"))
        {
            return "defender-identity-foundation";
        }

        if (IsDefenderForEndpointMacOs(normalizedTitle, normalizedProduct))
        {
            return "defender-endpoint-macos-hardening";
        }

        if (IsDefenderForEndpointLinux(normalizedTitle, normalizedProduct))
        {
            return "defender-endpoint-linux-hardening";
        }

        if (IsDefenderForEndpointSensorAndAgentHealth(normalizedTitle, normalizedProduct))
        {
            return "defender-endpoint-sensor-and-agent-health";
        }

        if (IsDefenderForEndpointAttackSurfaceReduction(normalizedTitle, normalizedProduct))
        {
            return "defender-endpoint-attack-surface-reduction";
        }

        if (IsDefenderForEndpointCoreProtection(normalizedTitle, normalizedProduct))
        {
            return "defender-endpoint-core-protection";
        }

        if (IsDefenderForEndpointBitLockerBaseline(normalizedTitle, normalizedProduct))
        {
            return "defender-endpoint-bitlocker-baseline";
        }

        if (IsDefenderForEndpointCredentialAndElevationHardening(normalizedTitle, normalizedProduct))
        {
            return "defender-endpoint-credential-and-elevation-hardening";
        }

        if (IsDefenderForEndpointRemoteAccessAndNetworkHardening(normalizedTitle, normalizedProduct))
        {
            return "defender-endpoint-remote-access-and-network-hardening";
        }

        if (IsDefenderForEndpointBrowserAndAdobePolicySurfaceReadiness(normalizedTitle, normalizedProduct))
        {
            return "defender-endpoint-browser-and-adobe-policy-surface-readiness";
        }

        if (IsDefenderForEndpointBrowserHardening(normalizedTitle, normalizedProduct))
        {
            return "defender-endpoint-browser-hardening";
        }

        if (IsDefenderForEndpointFirewallAndSmartScreen(normalizedTitle, normalizedProduct))
        {
            return "defender-endpoint-firewall-and-smartscreen";
        }

        if (IsDefenderForEndpointExploitProtection(normalizedTitle, normalizedProduct))
        {
            return "defender-endpoint-exploit-protection";
        }

        if (IsDefenderForEndpointOsSecurityBaseline(normalizedTitle, normalizedProduct))
        {
            return "defender-endpoint-os-security-baseline";
        }

        if (string.Equals(normalizedProduct, "MDATP", StringComparison.Ordinal))
        {
            return "defender-endpoint-security-posture";
        }

        if (string.Equals(normalizedProduct, "AZURE ATP", StringComparison.Ordinal))
        {
            if (IsDefenderIdentitySensorCoverage(normalizedTitle))
            {
                return "defender-identity-sensor-coverage";
            }

            if (IsActiveDirectoryCertificateServicesHardening(normalizedTitle))
            {
                return "active-directory-certificate-services-hardening";
            }

            if (IsFederatedIdentityProviderHygiene(normalizedTitle))
            {
                return "federated-identity-provider-hygiene";
            }

            if (IsActiveDirectoryPrivilegedAccountHygiene(normalizedTitle))
            {
                return "active-directory-privileged-account-hygiene";
            }

            return "active-directory-domain-security-hardening";
        }

        if (string.Equals(normalizedProduct, "AZUREAD", StringComparison.Ordinal)
            || string.Equals(normalizedCategory, "IDENTITY", StringComparison.Ordinal) && normalizedProduct.Length == 0)
        {
            if (normalizedTitle.Contains("SIGN-IN RISK", StringComparison.Ordinal))
            {
                return "require-mfa-risky-sign-ins";
            }

            if (normalizedTitle.Contains("USER RISK", StringComparison.Ordinal)
                || normalizedTitle.Contains("LEAKED CREDENTIALS", StringComparison.Ordinal))
            {
                return "require-password-change-high-risk-users";
            }

            return normalizedTitle.Contains("RISK", StringComparison.Ordinal)
                ? "entra-risk-policies"
                : "entra-identity-hygiene-baseline";
        }

        if (string.Equals(normalizedProduct, "EXO", StringComparison.Ordinal))
        {
            return "exchange-online-collaboration-and-mailbox";
        }

        if (string.Equals(normalizedProduct, "MIP", StringComparison.Ordinal))
        {
            return "purview-data-protection-baseline";
        }

        if (string.Equals(normalizedProduct, "SPO", StringComparison.Ordinal))
        {
            return IsSharePointOnlineHardening(normalizedTitle)
                ? "sharepoint-online-session-hardening"
                : "sharepoint-collaboration-and-device-access";
        }

        if (string.Equals(normalizedProduct, "MS TEAMS", StringComparison.Ordinal))
        {
            return "teams-meeting-hardening";
        }

        if (string.Equals(normalizedProduct, "APPG", StringComparison.Ordinal)
            || string.Equals(normalizedProduct, "ADMINCENTER", StringComparison.Ordinal))
        {
            return "app-governance-and-user-owned-apps";
        }

        if (string.Equals(normalizedProduct, "MCAS", StringComparison.Ordinal))
        {
            return "defender-cloud-apps-foundation";
        }

        if (string.Equals(normalizedProduct, "SWAY", StringComparison.Ordinal)
            || string.Equals(normalizedProduct, "FORMS", StringComparison.Ordinal))
        {
            return "microsoft-365-collaboration-sharing-governance";
        }

        if (string.Equals(normalizedProduct, "MDA_SF", StringComparison.Ordinal))
        {
            return "salesforce-security-posture";
        }

        if (string.Equals(normalizedProduct, "MDA_SNOW", StringComparison.Ordinal))
        {
            return "servicenow-security-posture";
        }

        if (string.Equals(normalizedProduct, "MDA_GITHUB", StringComparison.Ordinal))
        {
            return "github-enterprise-hardening";
        }

        if (normalizedProduct.StartsWith("MDA_", StringComparison.Ordinal))
        {
            return "connected-saas-session-and-auth-hardening";
        }

        return null;
    }

    private static bool ContainsAll(string value, params string[] segments)
    {
        return segments.All(segment => value.Contains(segment, StringComparison.Ordinal));
    }

    private static bool ContainsAny(string value, params string[] segments)
    {
        return segments.Any(segment => value.Contains(segment, StringComparison.Ordinal));
    }

    private static bool IsDefenderForOfficeAntiPhishing(string normalizedTitle)
    {
        return normalizedTitle.Contains("IMPERSONATION", StringComparison.Ordinal)
               || normalizedTitle.Contains("IMPERSONATED", StringComparison.Ordinal)
               || normalizedTitle.Contains("MAILBOX INTELLIGENCE", StringComparison.Ordinal)
               || normalizedTitle.Contains("ANTI-PHISHING", StringComparison.Ordinal)
               || normalizedTitle.Contains("HIGH CONFIDENCE PHISHING", StringComparison.Ordinal)
               || normalizedTitle.Contains("PHISHING EMAIL LEVEL THRESHOLD", StringComparison.Ordinal)
               || normalizedTitle.Contains("SAFETY TIP", StringComparison.Ordinal)
               || normalizedTitle.StartsWith("SET ACTION TO TAKE ON PHISHING DETECTION", StringComparison.Ordinal)
               || normalizedTitle.Contains("ZERO-HOUR AUTO PURGE POLICIES FOR PHISHING", StringComparison.Ordinal);
    }

    private static bool IsDefenderForOfficeSafeLinksAndAttachments(string normalizedTitle)
    {
        return normalizedTitle.Contains("SAFE LINKS", StringComparison.Ordinal)
               || normalizedTitle.Contains("SAFE ATTACHMENTS", StringComparison.Ordinal)
               || normalizedTitle.Contains("SAFE DOCUMENTS", StringComparison.Ordinal)
               || normalizedTitle.Contains("DEFENDER FOR OFFICE 365 IN SHAREPOINT, ONEDRIVE, AND MICROSOFT TEAMS", StringComparison.Ordinal);
    }

    private static bool IsDefenderForOfficeAntiMalware(string normalizedTitle)
    {
        return normalizedTitle.Contains("COMMON ATTACHMENT TYPES FILTER", StringComparison.Ordinal)
               || normalizedTitle.Contains("ZERO-HOUR AUTO PURGE POLICIES FOR MALWARE", StringComparison.Ordinal)
               || normalizedTitle.Contains("ANTI-MALWARE", StringComparison.Ordinal)
               || normalizedTitle.Contains("MALWARE FILTER", StringComparison.Ordinal);
    }

    private static bool IsDefenderForOfficeSpamAndForwarding(string normalizedTitle)
    {
        return normalizedTitle.Contains("HIGH CONFIDENCE SPAM", StringComparison.Ordinal)
               || normalizedTitle.Contains("SPAM DETECTION", StringComparison.Ordinal)
               || normalizedTitle.Contains("RETAIN SPAM IN QUARANTINE", StringComparison.Ordinal)
               || normalizedTitle.Contains("BULK SPAM", StringComparison.Ordinal)
               || normalizedTitle.Contains("BULK COMPLAINT LEVEL", StringComparison.Ordinal)
               || normalizedTitle.Contains("MAIL FORWARDING", StringComparison.Ordinal)
               || normalizedTitle.Contains("AUTOMATIC EMAIL FORWARDING", StringComparison.Ordinal)
               || normalizedTitle.Contains("MESSAGE LIMIT", StringComparison.Ordinal)
               || normalizedTitle.Contains("EXTERNAL RECIPIENTS", StringComparison.Ordinal)
               || normalizedTitle.Contains("INTERNAL RECIPIENTS", StringComparison.Ordinal)
               || normalizedTitle.Contains("ALLOWED IP ADDRESSES", StringComparison.Ordinal)
               || normalizedTitle.Contains("SENDER DOMAINS", StringComparison.Ordinal)
               || normalizedTitle.Contains("SPAM CONFIDENCE LEVEL", StringComparison.Ordinal)
               || normalizedTitle.Contains("ZERO-HOUR AUTO PURGE POLICIES FOR SPAM", StringComparison.Ordinal)
               || normalizedTitle.Contains("SPAM POLICIES", StringComparison.Ordinal);
    }

    private static bool IsExchangeOnlineCollaborationAndMailbox(string normalizedTitle)
    {
        return normalizedTitle.Contains("OUTLOOK ON THE WEB", StringComparison.Ordinal)
               || normalizedTitle.Contains("MAILTIPS", StringComparison.Ordinal)
               || normalizedTitle.Contains("MAILBOX AUDITING", StringComparison.Ordinal)
               || normalizedTitle.Contains("OUTLOOK ADD-INS", StringComparison.Ordinal)
               || normalizedTitle.Contains("CUSTOMER LOCKBOX", StringComparison.Ordinal)
               || normalizedTitle.Contains("EXTERNAL SHARING", StringComparison.Ordinal)
               || normalizedTitle.Contains("SPF RECORDS", StringComparison.Ordinal)
               || normalizedTitle.Contains("MODERN AUTHENTICATION FOR EXCHANGE ONLINE", StringComparison.Ordinal);
    }

    private static bool IsPurviewDataProtection(string normalizedTitle)
    {
        return normalizedTitle.Contains("DLP POLICIES", StringComparison.Ordinal)
               || normalizedTitle.Contains("AUDIT LOG SEARCH", StringComparison.Ordinal)
               || normalizedTitle.Contains("MANAGEMENT ACTIVITY API", StringComparison.Ordinal)
               || normalizedTitle.Contains("SENSITIVITY LABEL", StringComparison.Ordinal)
               || normalizedTitle.Contains("AUTO-LABELING", StringComparison.Ordinal);
    }

    private static bool IsTeamsMeetingHardening(string normalizedTitle)
    {
        return normalizedTitle.Contains("TEAMS MEETINGS", StringComparison.Ordinal)
               || normalizedTitle.Contains("TEAMS MEETING", StringComparison.Ordinal)
               || normalizedTitle.Contains("ANONYMOUS USERS", StringComparison.Ordinal)
               || normalizedTitle.Contains("DIAL-IN USERS", StringComparison.Ordinal)
               || normalizedTitle.Contains("ALLOWED TO PRESENT", StringComparison.Ordinal)
               || normalizedTitle.Contains("AUTOMATICALLY ADMITTED", StringComparison.Ordinal);
    }

    private static bool IsSharePointOnlineHardening(string normalizedTitle)
    {
        return normalizedTitle.Contains("SHAREPOINT ONLINE", StringComparison.Ordinal)
               || normalizedTitle.Contains("MODERN AUTHENTICATION FOR SHAREPOINT", StringComparison.Ordinal);
    }

    private static bool IsDefenderForEndpointMacOs(string normalizedTitle, string normalizedProduct)
    {
        return string.Equals(normalizedProduct, "MDATP", StringComparison.Ordinal)
               && normalizedTitle.Contains("MACOS", StringComparison.Ordinal);
    }

    private static bool IsDefenderForEndpointLinux(string normalizedTitle, string normalizedProduct)
    {
        return string.Equals(normalizedProduct, "MDATP", StringComparison.Ordinal)
               && normalizedTitle.Contains("LINUX", StringComparison.Ordinal);
    }

    private static bool IsDefenderForEndpointSensorAndAgentHealth(string normalizedTitle, string normalizedProduct)
    {
        return string.Equals(normalizedProduct, "MDATP", StringComparison.Ordinal)
               && ContainsAny(
                   normalizedTitle,
                   "MICROSOFT DEFENDER FOR ENDPOINT SENSOR",
                   "SENSOR DATA COLLECTION",
                   "IMPAIRED COMMUNICATIONS",
                   "CORE COMPONENTS",
                   "ONBOARDING",
                   "PLUG-IN FOR WSL",
                   "PLUGIN FOR WSL");
    }

    private static bool IsEntraDailyUseHardening(string normalizedTitle)
    {
        return ContainsAny(
            normalizedTitle,
            "USER CONSENT TO APPS",
            "ADMIN CONSENT WORKFLOW",
            "PASSWORD EXPIRATION POLICY");
    }

    private static bool IsDefenderForEndpointAttackSurfaceReduction(string normalizedTitle, string normalizedProduct)
    {
        return string.Equals(normalizedProduct, "MDATP", StringComparison.Ordinal)
               && (normalizedTitle.StartsWith("BLOCK ", StringComparison.Ordinal)
                   || ContainsAny(
                       normalizedTitle,
                       "RANSOMWARE",
                       "ADOBE READER",
                       "OFFICE APPLICATIONS",
                       "OFFICE COMMUNICATION APPLICATION",
                       "EXECUTABLE CONTENT FROM EMAIL CLIENT AND WEBMAIL",
                       "UNTRUSTED AND UNSIGNED PROCESSES THAT RUN FROM USB",
                       "PERSISTENCE THROUGH WMI",
                       "PSEXEC",
                       "OBFUSCATED SCRIPTS",
                       "JAVASCRIPT OR VBSCRIPT",
                       "WIN32 API CALLS FROM OFFICE MACROS",
                       "CONTROLLED FOLDER ACCESS",
                       "FLASH PLUGINS",
                       "WEBSHELL",
                       "SAFE MODE",
                       "COPIED OR IMPERSONATED SYSTEM TOOLS"));
    }

    private static bool IsDefenderForEndpointCoreProtection(string normalizedTitle, string normalizedProduct)
    {
        return string.Equals(normalizedProduct, "MDATP", StringComparison.Ordinal)
               && ContainsAny(
                   normalizedTitle,
                   "NETWORK PROTECTION",
                   "CLOUD-DELIVERED PROTECTION",
                   "TAMPER PROTECTION",
                   "DEFENDER ANTIVIRUS",
                   "AUTOMATIC UPDATES",
                   "HIDE OPTION TO ENABLE OR DISABLE UPDATES",
                   "EDR IN BLOCK MODE",
                   "BEHAVIOR MONITORING",
                   "REAL-TIME PROTECTION",
                   "PUA PROTECTION",
                   "REMOVABLE DRIVES DURING A FULL SCAN",
                   "UPDATE MICROSOFT DEFENDER FOR ENDPOINT CORE COMPONENTS",
                   "UPDATE MICROSOFT DEFENDER ANTIVIRUS DEFINITIONS");
    }

    private static bool IsDefenderForEndpointBitLockerBaseline(string normalizedTitle, string normalizedProduct)
    {
        return string.Equals(normalizedProduct, "MDATP", StringComparison.Ordinal)
               && ContainsAny(
                   normalizedTitle,
                   "ENCRYPT ALL BITLOCKER-SUPPORTED DRIVES",
                   "RESUME BITLOCKER PROTECTION ON ALL DRIVES",
                   "BITLOCKER DRIVE COMPATIBILITY",
                   "REQUIRE ADDITIONAL AUTHENTICATION AT STARTUP",
                   "MINIMUM PIN LENGTH FOR STARTUP");
    }

    private static bool IsDefenderForEndpointCredentialAndElevationHardening(string normalizedTitle, string normalizedProduct)
    {
        return string.Equals(normalizedProduct, "MDATP", StringComparison.Ordinal)
               && ContainsAny(
                   normalizedTitle,
                   "MICROSOFT DEFENDER CREDENTIAL GUARD",
                   "DISABLE 'WDIGEST AUTHENTICATION'",
                   "LOCAL STORAGE OF PASSWORDS AND CREDENTIALS",
                   "AUTOMATICALLY DENY ELEVATION REQUESTS",
                   "INVALID SIGNATURE",
                   "LOCAL SECURITY AUTHORITY (LSA) PROTECTION",
                   "SAFE DLL SEARCH MODE",
                   "ENUMERATE ADMINISTRATOR ACCOUNTS ON ELEVATION",
                   "APPLY UAC RESTRICTIONS TO LOCAL ACCOUNTS ON NETWORK LOGONS",
                   "ALWAYS INSTALL WITH ELEVATED PRIVILEGES",
                   "WDIGEST AUTHENTICATION");
    }

    private static bool IsDefenderForEndpointRemoteAccessAndNetworkHardening(string normalizedTitle, string normalizedProduct)
    {
        return string.Equals(normalizedProduct, "MDATP", StringComparison.Ordinal)
               && ContainsAny(
                   normalizedTitle,
                   "REMOTE DESKTOP SECURITY LEVEL",
                   "NETWORK BRIDGE ON YOUR DNS DOMAIN NETWORK",
                   "REQUIRE DOMAIN USERS TO ELEVATE WHEN SETTING A NETWORK'S LOCATION",
                   "INTERNET CONNECTION SHARING ON YOUR DNS DOMAIN NETWORK",
                   "CONFIGURE OFFER REMOTE ASSISTANCE",
                   "SOLICITED REMOTE ASSISTANCE",
                   "ALLOW BASIC AUTHENTICATION' FOR WINRM CLIENT",
                   "ALLOW BASIC AUTHENTICATION' FOR WINRM SERVICE",
                   "DISABLE 'AUTOPLAY' FOR ALL DRIVES",
                   "AUTOPLAY FOR NON-VOLUME DEVICES",
                   "AUTOPLAY' FOR ALL DRIVES",
                   "DEFAULT BEHAVIOR FOR 'AUTORUN' TO 'ENABLED: DO NOT EXECUTE ANY AUTORUN COMMANDS'",
                   "DEFAULT BEHAVIOR FOR 'AUTORUN'",
                   "DISABLE SMBV1 SERVER",
                    "SMBV1 CLIENT DRIVER",
                    "SMBV1 SERVER",
                    "IPV6 SOURCE ROUTING TO HIGHEST PROTECTION",
                    "IP SOURCE ROUTING");
    }

    private static bool IsDefenderForEndpointOsSecurityBaseline(string normalizedTitle, string normalizedProduct)
    {
        return string.Equals(normalizedProduct, "MDATP", StringComparison.Ordinal)
               && ContainsAny(
                   normalizedTitle,
                   "INSECURE GUEST LOGONS",
                   "STORE LAN MANAGER HASH VALUE",
                   "NAMED PIPES AND SHARES",
                   "ANONYMOUS ENUMERATION OF SHARES",
                   "ANONYMOUS ENUMERATION OF SAM ACCOUNTS",
                   "UNENCRYPTED PASSWORD TO THIRD-PARTY SMB SERVERS",
                   "DIGITALLY SIGN COMMUNICATIONS (ALWAYS)",
                   "BLANK PASSWORDS TO CONSOLE LOGON ONLY",
                   "LAN MANAGER AUTHENTICATION LEVEL",
                   "LOCAL MACHINE ZONE LOCKDOWN SECURITY",
                   "BUILT-IN ADMINISTRATOR ACCOUNT",
                   "BUILT-IN GUEST ACCOUNT",
                   "MINIMUM PASSWORD LENGTH",
                   "PASSWORD HISTORY",
                   "MAXIMUM PASSWORD AGE",
                   "MINIMUM PASSWORD AGE",
                   "ACCOUNT LOCKOUT",
                   "INTERACTIVE LOGON",
                   "ANONYMOUS USERS",
                   "UNQUOTED SERVICE PATH",
                   "SERVICE EXECUTABLE PATH",
                   "SERVICE ACCOUNT",
                   "NETWORK LEVEL AUTHENTICATION",
                   "OFFLINE ACCESS TO SHARES",
                   "REMOVE SHARE",
                   "ACCESS-BASED ENUMERATION",
                   "LSA PROTECTION",
                   "LDAP",
                   "REMOTE REGISTRY",
                   "NTLM AUTHENTICATION",
                   "UEFI SECURE BOOT");
    }

    private static bool IsDefenderForEndpointBrowserHardening(string normalizedTitle, string normalizedProduct)
    {
        return string.Equals(normalizedProduct, "MDATP", StringComparison.Ordinal)
               && ContainsAny(
                   normalizedTitle,
                   "CONTINUE RUNNING BACKGROUND APPS WHEN GOOGLE CHROME IS CLOSED",
                   "DISABLE 'AUTOFILL'",
                   "PASSWORD MANAGER",
                   "BLOCK THIRD PARTY COOKIES");
    }

    private static bool IsDefenderForEndpointBrowserAndAdobePolicySurfaceReadiness(string normalizedTitle, string normalizedProduct)
    {
        return string.Equals(normalizedProduct, "MDATP", StringComparison.Ordinal)
               && ContainsAny(
                   normalizedTitle,
                   "ALLOW RUNNING PLUGINS THAT ARE OUTDATED",
                   "DISABLE JAVASCRIPT ON ADOBE",
                   "DISABLE FLASH ON ADOBE");
    }

    private static bool IsDefenderForEndpointFirewallAndSmartScreen(string normalizedTitle, string normalizedProduct)
    {
        return string.Equals(normalizedProduct, "MDATP", StringComparison.Ordinal)
               && ContainsAny(
                   normalizedTitle,
                   "TURN ON MICROSOFT DEFENDER FIREWALL",
                   "SECURE MICROSOFT DEFENDER FIREWALL DOMAIN PROFILE",
                   "SECURE MICROSOFT DEFENDER FIREWALL PRIVATE PROFILE",
                   "SECURE MICROSOFT DEFENDER FIREWALL PUBLIC PROFILE",
                   "DISABLE MICROSOFT DEFENDER FIREWALL NOTIFICATIONS WHEN PROGRAMS ARE BLOCKED FOR DOMAIN PROFILE",
                   "DISABLE MICROSOFT DEFENDER FIREWALL NOTIFICATIONS WHEN PROGRAMS ARE BLOCKED FOR PRIVATE PROFILE",
                   "DISABLE MICROSOFT DEFENDER FIREWALL NOTIFICATIONS WHEN PROGRAMS ARE BLOCKED FOR PUBLIC PROFILE",
                   "DISABLE MERGING OF LOCAL MICROSOFT DEFENDER FIREWALL RULES WITH GROUP POLICY FIREWALL RULES FOR THE PUBLIC PROFILE",
                   "DISABLE MERGING OF LOCAL MICROSOFT DEFENDER FIREWALL CONNECTION RULES WITH GROUP POLICY FIREWALL RULES FOR THE PUBLIC PROFILE",
                   "SET MICROSOFT DEFENDER SMARTSCREEN APP AND FILE CHECKING TO BLOCK OR WARN",
                   "SET MICROSOFT DEFENDER SMARTSCREEN MICROSOFT EDGE SITE AND DOWNLOAD CHECKING TO BLOCK OR WARN");
    }

    private static bool IsDefenderForEndpointExploitProtection(string normalizedTitle, string normalizedProduct)
    {
        return string.Equals(normalizedProduct, "MDATP", StringComparison.Ordinal)
               && ContainsAny(
                   normalizedTitle,
                   "EXPLORER DATA EXECUTION PREVENTION (DEP)",
                   "ALL SYSTEM-LEVEL EXPLOIT PROTECTION SETTINGS");
    }

    private static bool IsActiveDirectoryCertificateServicesHardening(string normalizedTitle)
    {
        return ContainsAny(
            normalizedTitle,
            "CERTIFICATE",
            "ENROLLMENT",
            "(ESC");
    }

    private static bool IsDefenderIdentitySensorCoverage(string normalizedTitle)
    {
        return ContainsAny(
            normalizedTitle,
            "DEFENDER FOR IDENTITY DEPLOYMENT",
            "INSTALL DEFENDER FOR IDENTITY SENSOR",
            "HONEYTOKEN ACCOUNT",
            "VPN INTEGRATION");
    }

    private static bool IsFederatedIdentityProviderHygiene(string normalizedTitle)
    {
        return ContainsAny(
            normalizedTitle,
            "OKTA",
            "PINGONE",
            "SAILPOINT",
            "CYBERARK IDENTITY");
    }

    private static bool IsActiveDirectoryPrivilegedAccountHygiene(string normalizedTitle)
    {
        return ContainsAny(
            normalizedTitle,
            "CHANGE PASSWORD",
            "PRIVILEGED ROLE",
            "PRIVILEGED USER",
            "PRIVILEGED ACCOUNTS",
            "STALE ",
            "DORMANT ",
            "LEAKED CREDENTIALS",
            "LOCAL ADMINS",
            "LAPS",
            "DCSYNC",
            "ADMIN SDHOLDER",
            "SID HISTORY",
            "SEAMLESS SSO",
            "OPERATOR GROUPS",
            "DNSADMINS",
            "DISCOVERABLE PASSWORDS");
    }

    private static string NormalizeTitle(string value)
    {
        return value.Trim().ToUpperInvariant();
    }

    private static string? NormalizeTemplateKey(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? null
            : value.Trim();
    }

    private static string NormalizeErrorMessage(string errorMessage)
    {
        if (string.IsNullOrWhiteSpace(errorMessage))
        {
            return "The Microsoft Graph sync failed without returning an error message.";
        }

        var normalized = errorMessage.Trim().ReplaceLineEndings(" ");
        return normalized.Length <= 320 ? normalized : normalized[..320];
    }

    private sealed record RecommendationSyncContext(
        Guid ConnectionId,
        Guid OwnerOperatorId,
        string DisplayName,
        string TenantId,
        string ClientId,
        string ProtectedClientSecret);

    private sealed record RecommendationCoverageRecord(
        string? TemplateKey,
        string? StoredTemplateKey,
        RecommendationCoverageClassification Classification,
        RemediationTemplate? Template);

    private enum RecommendationCoverageClassification
    {
        RunnableNow,
        MappedFamily,
        Unmapped,
        MissingTemplate
    }
}
