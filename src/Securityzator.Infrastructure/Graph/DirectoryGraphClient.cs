using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Securityzator.Infrastructure.Graph;

public sealed class DirectoryGraphClient
{
    private static readonly HashSet<string> RecommendedAntiPhishRoleDisplayNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Global Administrator",
        "Privileged Role Administrator",
        "Security Administrator",
        "Exchange Administrator",
        "Authentication Administrator",
        "Conditional Access Administrator",
        "Cloud Application Administrator",
        "Application Administrator"
    };

    private readonly HttpClient _httpClient;
    private readonly IOptions<SecurityzatorGraphOptions> _options;

    public DirectoryGraphClient(
        HttpClient httpClient,
        IOptions<SecurityzatorGraphOptions> options)
    {
        _httpClient = httpClient;
        _options = options;
    }

    internal async Task<IReadOnlyList<GraphDirectoryGroup>> ListGroupsAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var groups = new List<GraphDirectoryGroup>();
        var nextRequestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/groups?$top=999&$select=id,displayName";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            var responseBody = await SendGetAsync(nextRequestUrl, accessToken, cancellationToken);

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var resultsElement)
                && resultsElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var result in resultsElement.EnumerateArray())
                {
                    groups.Add(new GraphDirectoryGroup(
                        GetString(result, "id"),
                        GetString(result, "displayName")));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return groups;
    }

    internal async Task ProbeGroupReadAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var requestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/groups?$top=1&$select=id,displayName";
        _ = await SendGetAsync(requestUrl, accessToken, cancellationToken);
    }

    internal async Task<EntraIdentityHygieneAssessmentResult> AssessEntraIdentityHygieneAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var authorizationPolicy = await GetAuthorizationPolicyAsync(accessToken, cancellationToken);
        var adminConsentRequestPolicy = await GetAdminConsentRequestPolicyAsync(accessToken, cancellationToken);
        var defaultDomain = await GetDefaultDomainAsync(accessToken, cancellationToken);
        var globalAdministrators = await ListGlobalAdministratorsAsync(accessToken, cancellationToken);
        var activeGlobalAdministrators = globalAdministrators
            .Where(user => user.AccountEnabled)
            .OrderBy(user => user.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(user => user.UserPrincipalName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var findings = new List<EntraIdentityHygieneFinding>
        {
            BuildUserConsentFinding(authorizationPolicy),
            BuildAdminConsentWorkflowFinding(adminConsentRequestPolicy),
            BuildSelfServicePasswordResetFinding(authorizationPolicy),
            BuildGlobalAdministratorCountFinding(activeGlobalAdministrators),
            BuildPasswordExpirationPolicyFinding(defaultDomain),
            BuildCloudOnlyAdminAccountFinding(activeGlobalAdministrators),
            BuildLeastPrivilegeAdminRolesFinding(activeGlobalAdministrators),
            BuildPasswordHashSyncFinding(activeGlobalAdministrators),
            BuildOnPremPasswordProtectionFinding(),
            BuildCustomBannedPasswordsFinding(),
            BuildLinkedInConnectionsFinding(),
            BuildManagedApprovedPublicGroupsFinding(authorizationPolicy),
            BuildSignInFrequencyFinding(),
            BuildThirdPartyAppsFinding(authorizationPolicy, adminConsentRequestPolicy)
        };

        var satisfiedCount = findings.Count(finding => string.Equals(finding.Status, "Satisfied", StringComparison.OrdinalIgnoreCase));
        var needsFollowUpCount = findings.Count(finding => string.Equals(finding.Status, "NeedsFollowUp", StringComparison.OrdinalIgnoreCase));
        var manualReviewCount = findings.Count(finding => string.Equals(finding.Status, "ManualReview", StringComparison.OrdinalIgnoreCase));
        var notApplicableCount = findings.Count(finding => string.Equals(finding.Status, "NotApplicable", StringComparison.OrdinalIgnoreCase));

        var notes = new List<string>
        {
            "This assessment uses Microsoft Graph authorization policy, admin consent request policy, default domain settings, and active Global Administrator membership to evaluate the cloud-only Entra hygiene items that are currently visible to the app.",
            "Hybrid identity controls such as password hash sync, on-prem Active Directory password protection, and custom banned-password lists still need Entra Connect or on-prem validation outside the current app-only lane.",
            "Role hygiene, separate admin identities, LinkedIn account connections, public-group governance, sign-in frequency design, and third-party app restrictions are still partially governance-heavy even when Graph exposes related posture signals."
        };

        return new EntraIdentityHygieneAssessmentResult(
            findings.Count,
            satisfiedCount,
            needsFollowUpCount,
            manualReviewCount,
            notApplicableCount,
            needsFollowUpCount == 0 && manualReviewCount == 0,
            findings,
            notes);
    }

    internal async Task<EntraDailyUseHardeningResult> ApplyEntraDailyUseHardeningAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var authorizationPolicyBefore = await GetAuthorizationPolicyAsync(accessToken, cancellationToken);
        var adminConsentRequestPolicyBefore = await GetAdminConsentRequestPolicyAsync(accessToken, cancellationToken);
        var defaultDomainBefore = await GetDefaultDomainAsync(accessToken, cancellationToken);
        var globalAdministrators = await ListGlobalAdministratorsAsync(accessToken, cancellationToken);
        var activeGlobalAdministrators = globalAdministrators
            .Where(user => user.AccountEnabled && !string.IsNullOrWhiteSpace(user.Id))
            .OrderBy(user => user.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(user => user.UserPrincipalName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var notes = new List<string>();
        var userConsentUpdated = false;
        var adminConsentWorkflowUpdated = false;
        var passwordPolicyUpdated = false;

        if (authorizationPolicyBefore.PermissionGrantPoliciesAssigned.Count > 0
            || authorizationPolicyBefore.AllowUserConsentForRiskyApps)
        {
            await UpdateAuthorizationPolicyAsync(
                accessToken,
                new Dictionary<string, object?>
                {
                    ["allowUserConsentForRiskyApps"] = false,
                    ["defaultUserRolePermissions"] = new Dictionary<string, object?>
                    {
                        ["permissionGrantPoliciesAssigned"] = Array.Empty<string>()
                    }
                },
                cancellationToken);
            userConsentUpdated = true;
            notes.Add("Disabled default user consent to apps and kept user consent for risky apps disabled.");
        }
        else
        {
            notes.Add("Default user consent was already disabled.");
        }

        var reviewerQueries = adminConsentRequestPolicyBefore.ReviewerQueries.Count > 0
            ? adminConsentRequestPolicyBefore.ReviewerQueries
            : activeGlobalAdministrators
                .Select(user => $"/users/{user.Id}")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

        var needsAdminConsentWorkflowUpdate =
            !adminConsentRequestPolicyBefore.IsEnabled
            || !adminConsentRequestPolicyBefore.NotifyReviewers
            || !adminConsentRequestPolicyBefore.RemindersEnabled
            || adminConsentRequestPolicyBefore.RequestDurationInDays is null or <= 0
            || adminConsentRequestPolicyBefore.ReviewerQueries.Count == 0;

        if (needsAdminConsentWorkflowUpdate)
        {
            if (reviewerQueries.Count == 0)
            {
                notes.Add("Skipped admin consent workflow enablement because no active Global Administrator accounts were available to seed as reviewers.");
            }
            else
            {
                await UpdateAdminConsentRequestPolicyAsync(
                    accessToken,
                    new Dictionary<string, object?>
                    {
                        ["isEnabled"] = true,
                        ["notifyReviewers"] = true,
                        ["remindersEnabled"] = true,
                        ["requestDurationInDays"] = adminConsentRequestPolicyBefore.RequestDurationInDays is > 0
                            ? adminConsentRequestPolicyBefore.RequestDurationInDays
                            : 14,
                        ["reviewers"] = reviewerQueries
                            .Select(query => new Dictionary<string, object?>
                            {
                                ["query"] = query,
                                ["queryType"] = "MicrosoftGraph"
                            })
                            .ToArray()
                    },
                    cancellationToken);
                adminConsentWorkflowUpdated = true;
                notes.Add($"Enabled the admin consent workflow with {reviewerQueries.Count} reviewer scope(s).");
            }
        }
        else
        {
            notes.Add("Admin consent workflow was already enabled with reviewer coverage.");
        }

        const int NeverExpireDays = int.MaxValue;
        var currentPasswordValidity = defaultDomainBefore.PasswordValidityPeriodInDays ?? 90;
        var currentNotificationWindow = defaultDomainBefore.PasswordNotificationWindowInDays ?? 14;

        if (currentPasswordValidity != NeverExpireDays)
        {
            await UpdateDomainAsync(
                accessToken,
                defaultDomainBefore.Id,
                new Dictionary<string, object?>
                {
                    ["passwordValidityPeriodInDays"] = NeverExpireDays,
                    ["passwordNotificationWindowInDays"] = currentNotificationWindow
                },
                cancellationToken);
            passwordPolicyUpdated = true;
            notes.Add($"Set the default domain password validity period to never expire for '{defaultDomainBefore.Id}'.");
        }
        else
        {
            notes.Add($"Default domain '{defaultDomainBefore.Id}' already used the never-expire password-validity setting.");
        }

        var authorizationPolicyAfter = await GetAuthorizationPolicyAsync(accessToken, cancellationToken);
        var adminConsentRequestPolicyAfter = await GetAdminConsentRequestPolicyAsync(accessToken, cancellationToken);
        var defaultDomainAfter = await GetDefaultDomainAsync(accessToken, cancellationToken);

        return new EntraDailyUseHardeningResult(
            userConsentUpdated,
            adminConsentWorkflowUpdated,
            passwordPolicyUpdated,
            authorizationPolicyBefore,
            authorizationPolicyAfter,
            adminConsentRequestPolicyBefore,
            adminConsentRequestPolicyAfter,
            defaultDomainBefore,
            defaultDomainAfter,
            activeGlobalAdministrators.Select(user => user.UserPrincipalNameOrDisplayName).ToArray(),
            notes);
    }

    internal async Task<IReadOnlyList<GraphDirectoryGroupMember>> ListGroupMembersAsync(
        string groupId,
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var members = new List<GraphDirectoryGroupMember>();
        var nextRequestUrl =
            $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/groups/{Uri.EscapeDataString(groupId)}/members?$top=999";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            var responseBody = await SendGetAsync(nextRequestUrl, accessToken, cancellationToken);

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var resultsElement)
                && resultsElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var result in resultsElement.EnumerateArray())
                {
                    members.Add(new GraphDirectoryGroupMember(
                        GetString(result, "id"),
                        GetString(result, "@odata.type"),
                        GetString(result, "displayName"),
                        GetString(result, "userPrincipalName"),
                        GetString(result, "deviceId")));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return members;
    }

    internal async Task<IReadOnlyList<GraphDirectoryUser>> ListRecommendedAntiPhishProtectedUsersAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var roles = await ListDirectoryRolesAsync(accessToken, cancellationToken);
        var matchingRoles = roles
            .Where(role => RecommendedAntiPhishRoleDisplayNames.Contains(role.DisplayName))
            .ToArray();

        var users = new List<GraphDirectoryUser>();

        foreach (var role in matchingRoles)
        {
            var roleMembers = await ListDirectoryRoleMembersAsync(role.Id, accessToken, cancellationToken);
            users.AddRange(roleMembers);
        }

        return users
            .Where(user =>
                user.AccountEnabled
                && string.Equals(user.UserType, "Member", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(user.PreferredAddress))
            .DistinctBy(user => user.PreferredAddress, StringComparer.OrdinalIgnoreCase)
            .OrderBy(user => user.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(user => user.PreferredAddress, StringComparer.OrdinalIgnoreCase)
            .Take(25)
            .ToArray();
    }

    internal async Task<string> ResolveExchangeOrganizationAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var requestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/organization?$select=verifiedDomains";
        var responseBody = await SendGetAsync(requestUrl, accessToken, cancellationToken);

        using var payload = JsonDocument.Parse(responseBody);

        if (!payload.RootElement.TryGetProperty("value", out var resultsElement)
            || resultsElement.ValueKind != JsonValueKind.Array)
        {
            throw new GraphServiceException("Directory organization lookup did not return a Graph result set.");
        }

        var organization = resultsElement.EnumerateArray().FirstOrDefault();

        if (organization.ValueKind == JsonValueKind.Undefined)
        {
            throw new GraphServiceException("Directory organization lookup did not return an organization record.");
        }

        if (!organization.TryGetProperty("verifiedDomains", out var verifiedDomainsElement)
            || verifiedDomainsElement.ValueKind != JsonValueKind.Array)
        {
            throw new GraphServiceException("Directory organization lookup did not return verified domains.");
        }

        var verifiedDomains = verifiedDomainsElement
            .EnumerateArray()
            .Select(domain => new GraphVerifiedDomain(
                GetString(domain, "name"),
                GetBoolean(domain, "isInitial"),
                GetBoolean(domain, "isDefault")))
            .Where(domain => !string.IsNullOrWhiteSpace(domain.Name))
            .ToArray();

        var selectedDomain = verifiedDomains.FirstOrDefault(domain => domain.IsInitial)
            ?? verifiedDomains.FirstOrDefault(domain => domain.IsDefault)
            ?? verifiedDomains.FirstOrDefault();

        if (selectedDomain is null || string.IsNullOrWhiteSpace(selectedDomain.Name))
        {
            throw new GraphServiceException("Directory organization lookup did not return a usable verified domain for Exchange Online.");
        }

        return selectedDomain.Name;
    }

    internal async Task<IReadOnlyList<GraphDirectoryUser>> ListGlobalAdministratorsAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var roles = await ListDirectoryRolesAsync(accessToken, cancellationToken);
        var globalAdministratorRole = roles.FirstOrDefault(role =>
            string.Equals(role.DisplayName, "Global Administrator", StringComparison.OrdinalIgnoreCase)
            || string.Equals(role.DisplayName, "Company Administrator", StringComparison.OrdinalIgnoreCase));

        if (globalAdministratorRole is null)
        {
            return Array.Empty<GraphDirectoryUser>();
        }

        return await ListDirectoryRoleMembersAsync(globalAdministratorRole.Id, accessToken, cancellationToken);
    }

    private async Task<IReadOnlyList<GraphDirectoryRole>> ListDirectoryRolesAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        var roles = new List<GraphDirectoryRole>();
        var nextRequestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/directoryRoles?$select=id,displayName";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            var responseBody = await SendGetAsync(nextRequestUrl, accessToken, cancellationToken);

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var resultsElement)
                && resultsElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var result in resultsElement.EnumerateArray())
                {
                    roles.Add(new GraphDirectoryRole(
                        GetString(result, "id"),
                        GetString(result, "displayName")));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return roles;
    }

    private async Task<IReadOnlyList<GraphDirectoryUser>> ListDirectoryRoleMembersAsync(
        string roleId,
        string accessToken,
        CancellationToken cancellationToken)
    {
        var users = new List<GraphDirectoryUser>();
        var nextRequestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/directoryRoles/{Uri.EscapeDataString(roleId)}/members?$select=id,displayName,userPrincipalName,mail,userType,accountEnabled,onPremisesSyncEnabled";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            var responseBody = await SendGetAsync(nextRequestUrl, accessToken, cancellationToken);

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var resultsElement)
                && resultsElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var result in resultsElement.EnumerateArray())
                {
                    var odataType = GetString(result, "@odata.type");
                    var userPrincipalName = GetString(result, "userPrincipalName");

                    if (!string.Equals(odataType, "#microsoft.graph.user", StringComparison.OrdinalIgnoreCase)
                        && string.IsNullOrWhiteSpace(userPrincipalName))
                    {
                        continue;
                    }

                    users.Add(new GraphDirectoryUser(
                        GetString(result, "id"),
                        GetString(result, "displayName"),
                        userPrincipalName,
                        GetString(result, "mail"),
                        GetBoolean(result, "accountEnabled"),
                        GetString(result, "userType"),
                        GetNullableBoolean(result, "onPremisesSyncEnabled")));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return users;
    }

    private async Task SendPatchAsync(
        string requestUrl,
        string accessToken,
        object payload,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Patch, requestUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(response.StatusCode, responseBody));
        }
    }

    private async Task SendPutAsync(
        string requestUrl,
        string accessToken,
        object payload,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, requestUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(response.StatusCode, responseBody));
        }
    }

    private async Task<string> SendGetAsync(
        string requestUrl,
        string accessToken,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (response.IsSuccessStatusCode)
        {
            return responseBody;
        }

        if (GraphApiVersionResolver.ShouldRetryWithBeta(_options.Value, response.StatusCode, requestUrl))
        {
            var betaUrl = GraphApiVersionResolver.ToBetaUrl(_options.Value, requestUrl);
            using var betaRequest = new HttpRequestMessage(HttpMethod.Get, betaUrl);
            betaRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            using var betaResponse = await _httpClient.SendAsync(betaRequest, cancellationToken);
            var betaResponseBody = await betaResponse.Content.ReadAsStringAsync(cancellationToken);

            if (betaResponse.IsSuccessStatusCode)
            {
                return betaResponseBody;
            }
        }

        throw new GraphServiceException(BuildErrorMessage(response.StatusCode, responseBody));
    }

    private async Task<GraphAuthorizationPolicy> GetAuthorizationPolicyAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        var requestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/policies/authorizationPolicy";
        var responseBody = await SendGetAsync(requestUrl, accessToken, cancellationToken);

        using var payload = JsonDocument.Parse(responseBody);
        var permissionGrantPoliciesAssigned = payload.RootElement.TryGetProperty("defaultUserRolePermissions", out var defaultUserRolePermissions)
            && defaultUserRolePermissions.ValueKind == JsonValueKind.Object
            && defaultUserRolePermissions.TryGetProperty("permissionGrantPoliciesAssigned", out var policiesElement)
            && policiesElement.ValueKind == JsonValueKind.Array
                ? policiesElement
                    .EnumerateArray()
                    .Where(item => item.ValueKind == JsonValueKind.String)
                    .Select(item => item.GetString())
                    .Where(item => !string.IsNullOrWhiteSpace(item))
                    .Select(item => item!)
                    .ToArray()
                : Array.Empty<string>();

        return new GraphAuthorizationPolicy(
            GetBoolean(payload.RootElement, "allowedToUseSSPR"),
            GetBoolean(payload.RootElement, "allowUserConsentForRiskyApps"),
            payload.RootElement.TryGetProperty("defaultUserRolePermissions", out defaultUserRolePermissions)
                && defaultUserRolePermissions.ValueKind == JsonValueKind.Object
                && GetBoolean(defaultUserRolePermissions, "allowedToCreateSecurityGroups"),
            permissionGrantPoliciesAssigned);
    }

    private async Task<GraphAdminConsentRequestPolicy> GetAdminConsentRequestPolicyAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        var requestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/policies/adminConsentRequestPolicy";
        var responseBody = await SendGetAsync(requestUrl, accessToken, cancellationToken);

        using var payload = JsonDocument.Parse(responseBody);
        var reviewerQueries = payload.RootElement.TryGetProperty("reviewers", out var reviewersElement)
            && reviewersElement.ValueKind == JsonValueKind.Array
                ? reviewersElement
                    .EnumerateArray()
                    .Select(reviewer => GetString(reviewer, "query"))
                    .Where(query => !string.IsNullOrWhiteSpace(query))
                    .ToArray()
                : Array.Empty<string>();

        return new GraphAdminConsentRequestPolicy(
            GetBoolean(payload.RootElement, "isEnabled"),
            GetBoolean(payload.RootElement, "notifyReviewers"),
            GetBoolean(payload.RootElement, "remindersEnabled"),
            GetInt32(payload.RootElement, "requestDurationInDays"),
            reviewerQueries);
    }

    private async Task<GraphDomainPasswordPolicy> GetDefaultDomainAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        var requestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/domains?$select=id,isDefault,isInitial,isVerified,passwordValidityPeriodInDays,passwordNotificationWindowInDays";
        var responseBody = await SendGetAsync(requestUrl, accessToken, cancellationToken);

        using var payload = JsonDocument.Parse(responseBody);

        if (!payload.RootElement.TryGetProperty("value", out var resultsElement)
            || resultsElement.ValueKind != JsonValueKind.Array)
        {
            throw new GraphServiceException("Domain lookup did not return a Graph result set.");
        }

        GraphDomainPasswordPolicy? selectedDomain = null;

        foreach (var result in resultsElement.EnumerateArray())
        {
            var domain = new GraphDomainPasswordPolicy(
                GetString(result, "id"),
                GetBoolean(result, "isDefault"),
                GetBoolean(result, "isInitial"),
                GetBoolean(result, "isVerified"),
                GetNullableInt32(result, "passwordValidityPeriodInDays"),
                GetNullableInt32(result, "passwordNotificationWindowInDays"));

            if (selectedDomain is null
                || domain.IsDefault
                || (!selectedDomain.IsDefault && domain.IsInitial))
            {
                selectedDomain = domain;
            }
        }

        return selectedDomain
            ?? throw new GraphServiceException("Domain lookup did not return a usable default or initial domain.");
    }

    private async Task UpdateAuthorizationPolicyAsync(
        string accessToken,
        object payload,
        CancellationToken cancellationToken)
    {
        var requestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/policies/authorizationPolicy";
        await SendPatchAsync(requestUrl, accessToken, payload, cancellationToken);
    }

    private async Task UpdateAdminConsentRequestPolicyAsync(
        string accessToken,
        object payload,
        CancellationToken cancellationToken)
    {
        var requestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/policies/adminConsentRequestPolicy";
        await SendPutAsync(requestUrl, accessToken, payload, cancellationToken);
    }

    private async Task UpdateDomainAsync(
        string accessToken,
        string domainId,
        object payload,
        CancellationToken cancellationToken)
    {
        var requestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/domains/{Uri.EscapeDataString(domainId)}";
        await SendPatchAsync(requestUrl, accessToken, payload, cancellationToken);
    }

    private static EntraIdentityHygieneFinding BuildUserConsentFinding(GraphAuthorizationPolicy authorizationPolicy)
    {
        var consentDisabled = authorizationPolicy.PermissionGrantPoliciesAssigned.Count == 0;
        var summary = consentDisabled
            ? "Default user consent to apps is disabled."
            : $"Default user consent is still enabled through {authorizationPolicy.PermissionGrantPoliciesAssigned.Count} permission grant policy assignment(s).";
        var evidence = consentDisabled
            ? new[] { "defaultUserRolePermissions.permissionGrantPoliciesAssigned is empty." }
            : authorizationPolicy.PermissionGrantPoliciesAssigned;

        return new EntraIdentityHygieneFinding(
            "IntegratedApps",
            "Ensure user consent to apps accessing company data on their behalf is not allowed",
            consentDisabled ? "Satisfied" : "NeedsFollowUp",
            summary,
            evidence);
    }

    private static EntraIdentityHygieneFinding BuildAdminConsentWorkflowFinding(GraphAdminConsentRequestPolicy adminConsentRequestPolicy)
    {
        var enabledWithReviewers = adminConsentRequestPolicy.IsEnabled && adminConsentRequestPolicy.ReviewerQueries.Count > 0;
        var summary = enabledWithReviewers
            ? "The admin consent workflow is enabled and has one or more configured reviewers."
            : adminConsentRequestPolicy.IsEnabled
                ? "The admin consent workflow is enabled, but no reviewers were returned."
                : "The admin consent workflow is disabled.";

        var evidence = new List<string>
        {
            $"isEnabled={adminConsentRequestPolicy.IsEnabled}",
            $"reviewerCount={adminConsentRequestPolicy.ReviewerQueries.Count}",
            $"notifyReviewers={adminConsentRequestPolicy.NotifyReviewers}",
            $"remindersEnabled={adminConsentRequestPolicy.RemindersEnabled}",
            $"requestDurationInDays={adminConsentRequestPolicy.RequestDurationInDays?.ToString() ?? "Missing"}"
        };
        evidence.AddRange(adminConsentRequestPolicy.ReviewerQueries);

        return new EntraIdentityHygieneFinding(
            "aad_admin_consent_workflow",
            "Ensure the admin consent workflow is enabled",
            enabledWithReviewers ? "Satisfied" : "NeedsFollowUp",
            summary,
            evidence);
    }

    private static EntraIdentityHygieneFinding BuildSelfServicePasswordResetFinding(GraphAuthorizationPolicy authorizationPolicy)
    {
        return new EntraIdentityHygieneFinding(
            "SelfServicePasswordReset",
            "Ensure 'Self service password reset enabled' is set to 'All'",
            authorizationPolicy.AllowedToUseSspr ? "Satisfied" : "NeedsFollowUp",
            authorizationPolicy.AllowedToUseSspr
                ? "Tenant administrators are allowed to use self-service password reset."
                : "Tenant administrators are not currently allowed to use self-service password reset.",
            [$"allowedToUseSSPR={authorizationPolicy.AllowedToUseSspr}"]);
    }

    private static EntraIdentityHygieneFinding BuildGlobalAdministratorCountFinding(IReadOnlyList<GraphDirectoryUser> activeGlobalAdministrators)
    {
        return new EntraIdentityHygieneFinding(
            "OneAdmin",
            "Designate more than one global admin",
            activeGlobalAdministrators.Count >= 2 ? "Satisfied" : "NeedsFollowUp",
            activeGlobalAdministrators.Count >= 2
                ? $"Found {activeGlobalAdministrators.Count} active Global Administrator account(s)."
                : $"Found only {activeGlobalAdministrators.Count} active Global Administrator account(s).",
            activeGlobalAdministrators.Count == 0
                ? ["No active Global Administrator membership was returned by Graph."]
                : activeGlobalAdministrators.Select(user => user.UserPrincipalNameOrDisplayName).ToArray());
    }

    private static EntraIdentityHygieneFinding BuildPasswordExpirationPolicyFinding(GraphDomainPasswordPolicy defaultDomain)
    {
        const int NeverExpireDays = int.MaxValue;
        var neverExpires = defaultDomain.PasswordValidityPeriodInDays == NeverExpireDays;

        return new EntraIdentityHygieneFinding(
            "PWAgePolicyNew",
            "Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (recommended)'",
            neverExpires ? "Satisfied" : "NeedsFollowUp",
            neverExpires
                ? $"Default domain '{defaultDomain.Id}' is configured with passwordValidityPeriodInDays={NeverExpireDays}."
                : $"Default domain '{defaultDomain.Id}' returned passwordValidityPeriodInDays={defaultDomain.PasswordValidityPeriodInDays?.ToString() ?? "Missing"}.",
            [
                $"domain={defaultDomain.Id}",
                $"isDefault={defaultDomain.IsDefault}",
                $"passwordValidityPeriodInDays={defaultDomain.PasswordValidityPeriodInDays?.ToString() ?? "Missing"}",
                $"passwordNotificationWindowInDays={defaultDomain.PasswordNotificationWindowInDays?.ToString() ?? "Missing"}"
            ]);
    }

    private static EntraIdentityHygieneFinding BuildCloudOnlyAdminAccountFinding(IReadOnlyList<GraphDirectoryUser> activeGlobalAdministrators)
    {
        if (activeGlobalAdministrators.Count == 0)
        {
            return new EntraIdentityHygieneFinding(
                "aad_admin_accounts_separate_unassigned_cloud_only",
                "Ensure Administrative accounts are separate and cloud-only",
                "ManualReview",
                "No active Global Administrator accounts were returned, so cloud-only admin posture could not be verified from this assessment.",
                ["No active Global Administrator membership was returned by Graph."]);
        }

        var syncedAdmins = activeGlobalAdministrators
            .Where(user => user.OnPremisesSyncEnabled == true)
            .Select(user => user.UserPrincipalNameOrDisplayName)
            .ToArray();

        if (syncedAdmins.Length > 0)
        {
            return new EntraIdentityHygieneFinding(
                "aad_admin_accounts_separate_unassigned_cloud_only",
                "Ensure Administrative accounts are separate and cloud-only",
                "NeedsFollowUp",
                $"Found {syncedAdmins.Length} active Global Administrator account(s) that appear synchronized from on-premises.",
                syncedAdmins);
        }

        return new EntraIdentityHygieneFinding(
            "aad_admin_accounts_separate_unassigned_cloud_only",
            "Ensure Administrative accounts are separate and cloud-only",
            "ManualReview",
            "All active Global Administrator accounts returned by Graph appear cloud-only. Separate admin identities from daily-use accounts still needs human review.",
            activeGlobalAdministrators.Select(user => $"{user.UserPrincipalNameOrDisplayName};onPremisesSyncEnabled={user.OnPremisesSyncEnabled?.ToString() ?? "Missing"}").ToArray());
    }

    private static EntraIdentityHygieneFinding BuildLeastPrivilegeAdminRolesFinding(IReadOnlyList<GraphDirectoryUser> activeGlobalAdministrators)
    {
        return new EntraIdentityHygieneFinding(
            "RoleOverlap",
            "Use least privileged administrative roles",
            "ManualReview",
            "Securityzator can count Global Administrator membership, but least-privilege role design still needs a human review across all privileged roles and operator workflows.",
            [
                $"activeGlobalAdministratorCount={activeGlobalAdministrators.Count}",
                "Review Global Administrator usage, permanent assignments, and broader privileged-role overlap outside this app-only assessment."
            ]);
    }

    private static EntraIdentityHygieneFinding BuildPasswordHashSyncFinding(IReadOnlyList<GraphDirectoryUser> activeGlobalAdministrators)
    {
        var syncedAdminCount = activeGlobalAdministrators.Count(user => user.OnPremisesSyncEnabled == true);
        var summary = syncedAdminCount > 0
            ? $"Detected {syncedAdminCount} synchronized Global Administrator account(s). Verify password hash sync and broader hybrid sign-in posture in Entra Connect."
            : "No synchronized Global Administrator accounts were returned. Password hash sync still needs hybrid validation because Graph does not expose Entra Connect posture directly here.";

        return new EntraIdentityHygieneFinding(
            "PasswordHashSync",
            "Ensure that password hash sync is enabled for hybrid deployments",
            "ManualReview",
            summary,
            [
                $"synchronizedGlobalAdministratorCount={syncedAdminCount}",
                "Validate password hash sync and staged-hybrid configuration in Entra Connect or Microsoft Entra Connect Health."
            ]);
    }

    private static EntraIdentityHygieneFinding BuildOnPremPasswordProtectionFinding()
    {
        return new EntraIdentityHygieneFinding(
            "aad_password_protection",
            "Ensure password protection is enabled for on-prem Active Directory",
            "ManualReview",
            "This control depends on hybrid password protection deployment in on-prem Active Directory and is not directly exposed through the current app-only Graph lane.",
            ["Validate Microsoft Entra Password Protection proxy and DC agent rollout in the hybrid environment."]);
    }

    private static EntraIdentityHygieneFinding BuildCustomBannedPasswordsFinding()
    {
        return new EntraIdentityHygieneFinding(
            "aad_custom_banned_passwords",
            "Ensure custom banned passwords lists are used",
            "ManualReview",
            "The current app-only assessment does not read the tenant custom banned-password list or its hybrid deployment state.",
            ["Validate Microsoft Entra Password Protection custom banned-password configuration separately."]);
    }

    private static EntraIdentityHygieneFinding BuildLinkedInConnectionsFinding()
    {
        return new EntraIdentityHygieneFinding(
            "aad_linkedin_connection_disables",
            "Ensure 'LinkedIn account connections' is disabled",
            "ManualReview",
            "The current Graph assessment does not expose a stable LinkedIn account-connections tenant setting, so this item still needs manual review.",
            ["Review Microsoft Entra user settings for LinkedIn account connections separately."]);
    }

    private static EntraIdentityHygieneFinding BuildManagedApprovedPublicGroupsFinding(GraphAuthorizationPolicy authorizationPolicy)
    {
        return new EntraIdentityHygieneFinding(
            "aad_managed_approved_public_groups_only",
            "Ensure that only organizationally managed/approved public groups are enabled",
            "ManualReview",
            "Securityzator can see whether default users can create security groups, but the full public-group governance posture still needs a dedicated Microsoft 365 groups policy assessment.",
            [$"allowedToCreateSecurityGroups={authorizationPolicy.AllowedToCreateSecurityGroups}"]);
    }

    private static EntraIdentityHygieneFinding BuildSignInFrequencyFinding()
    {
        return new EntraIdentityHygieneFinding(
            "aad_sign_in_freq_session_timeout",
            "Ensure Sign-in frequency is enabled and browser sessions are not persistent for administrative users",
            "ManualReview",
            "This control should be evaluated against Conditional Access session controls, which Securityzator has not yet modeled as part of the Entra hygiene assessment.",
            ["Review Conditional Access session controls for sign-in frequency and persistent browser sessions."]);
    }

    private static EntraIdentityHygieneFinding BuildThirdPartyAppsFinding(
        GraphAuthorizationPolicy authorizationPolicy,
        GraphAdminConsentRequestPolicy adminConsentRequestPolicy)
    {
        var postureSummary = authorizationPolicy.PermissionGrantPoliciesAssigned.Count == 0 && adminConsentRequestPolicy.IsEnabled
            ? "Default user consent is disabled and the admin consent workflow is enabled, which reduces uncontrolled third-party app integration, but existing enterprise app exposure still needs a separate review."
            : "Third-party app restrictions still need follow-up. User consent and admin consent workflow posture alone do not prove that broader third-party integrations are locked down.";

        return new EntraIdentityHygieneFinding(
            "aad_third_party_apps",
            "Ensure third party integrated applications are not allowed",
            "ManualReview",
            postureSummary,
            [
                $"permissionGrantPoliciesAssignedCount={authorizationPolicy.PermissionGrantPoliciesAssigned.Count}",
                $"adminConsentWorkflowEnabled={adminConsentRequestPolicy.IsEnabled}",
                "Review enterprise applications, consent grants, and approved third-party integration paths separately."
            ]);
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

    private static bool GetBoolean(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return false;
        }

        return property.ValueKind == JsonValueKind.True
            || (property.ValueKind == JsonValueKind.String
                && bool.TryParse(property.GetString(), out var parsed)
                && parsed);
    }

    private static bool? GetNullableBoolean(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return null;
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
                ? parsed
                : null;
    }

    private static int? GetNullableInt32(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return null;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetInt32(out var number))
        {
            return number;
        }

        return property.ValueKind == JsonValueKind.String
            && int.TryParse(property.GetString(), out var parsed)
                ? parsed
                : null;
    }

    private static int? GetInt32(JsonElement element, string propertyName) =>
        GetNullableInt32(element, propertyName);

    private static string BuildErrorMessage(
        System.Net.HttpStatusCode statusCode,
        string responseBody)
    {
        var bodySnippet = string.IsNullOrWhiteSpace(responseBody)
            ? string.Empty
            : responseBody.Trim().ReplaceLineEndings(" ");

        if (bodySnippet.Length > 320)
        {
            bodySnippet = bodySnippet[..320];
        }

        return string.IsNullOrWhiteSpace(bodySnippet)
            ? $"Directory request failed with {(int)statusCode}."
            : $"Directory request failed with {(int)statusCode}. {bodySnippet}";
    }

    private sealed record GraphVerifiedDomain(
        string Name,
        bool IsInitial,
        bool IsDefault);

    internal sealed record GraphDirectoryRole(
        string Id,
        string DisplayName);

    internal sealed record GraphDirectoryUser(
        string Id,
        string DisplayName,
        string UserPrincipalName,
        string Mail,
        bool AccountEnabled,
        string UserType,
        bool? OnPremisesSyncEnabled)
    {
        public string PreferredAddress =>
            string.IsNullOrWhiteSpace(Mail) ? UserPrincipalName : Mail;

        public string UserPrincipalNameOrDisplayName =>
            string.IsNullOrWhiteSpace(UserPrincipalName)
                ? DisplayName
                : UserPrincipalName;

        public string AntiPhishIdentity =>
            string.IsNullOrWhiteSpace(DisplayName)
                ? PreferredAddress
                : $"{DisplayName};{PreferredAddress}";
    }

    internal sealed record GraphDirectoryGroupMember(
        string Id,
        string ODataType,
        string DisplayName,
        string UserPrincipalName,
        string DeviceId)
    {
        public bool IsUser =>
            string.Equals(ODataType, "#microsoft.graph.user", StringComparison.OrdinalIgnoreCase);

        public bool IsDevice =>
            string.Equals(ODataType, "#microsoft.graph.device", StringComparison.OrdinalIgnoreCase);
    }

    internal sealed record GraphAuthorizationPolicy(
        bool AllowedToUseSspr,
        bool AllowUserConsentForRiskyApps,
        bool AllowedToCreateSecurityGroups,
        IReadOnlyList<string> PermissionGrantPoliciesAssigned);

    internal sealed record GraphAdminConsentRequestPolicy(
        bool IsEnabled,
        bool NotifyReviewers,
        bool RemindersEnabled,
        int? RequestDurationInDays,
        IReadOnlyList<string> ReviewerQueries);

    internal sealed record GraphDomainPasswordPolicy(
        string Id,
        bool IsDefault,
        bool IsInitial,
        bool IsVerified,
        int? PasswordValidityPeriodInDays,
        int? PasswordNotificationWindowInDays);

    internal sealed record EntraIdentityHygieneFinding(
        string ControlId,
        string ControlTitle,
        string Status,
        string Summary,
        IReadOnlyList<string> Evidence);

    internal sealed record EntraIdentityHygieneAssessmentResult(
        int FindingCount,
        int SatisfiedCount,
        int NeedsFollowUpCount,
        int ManualReviewCount,
        int NotApplicableCount,
        bool AlreadyCompliant,
        IReadOnlyList<EntraIdentityHygieneFinding> Findings,
        IReadOnlyList<string> Notes);

    internal sealed record EntraDailyUseHardeningResult(
        bool UserConsentUpdated,
        bool AdminConsentWorkflowUpdated,
        bool PasswordPolicyUpdated,
        GraphAuthorizationPolicy AuthorizationPolicyBefore,
        GraphAuthorizationPolicy AuthorizationPolicyAfter,
        GraphAdminConsentRequestPolicy AdminConsentRequestPolicyBefore,
        GraphAdminConsentRequestPolicy AdminConsentRequestPolicyAfter,
        GraphDomainPasswordPolicy DefaultDomainBefore,
        GraphDomainPasswordPolicy DefaultDomainAfter,
        IReadOnlyList<string> ReviewerDisplayNames,
        IReadOnlyList<string> Notes)
    {
        public bool AlreadyCompliant =>
            !UserConsentUpdated
            && !AdminConsentWorkflowUpdated
            && !PasswordPolicyUpdated;
    }
}
