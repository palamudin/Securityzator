using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using Securityzator.Application.Remediations;

namespace Securityzator.Infrastructure.Graph;

public sealed class ConditionalAccessGraphClient
{
    private const string AzureResourceManagerApplicationId = "797f4846-ba00-4fd7-ba43-dac1f8f63013";
    private const string GuestsOrExternalUsersScope = "GuestsOrExternalUsers";
    private const string MicrosoftAdminPortalsApplication = "MicrosoftAdminPortals";
    private const string MultifactorAuthenticationStrengthId = "00000000-0000-0000-0000-000000000002";
    private const string MultifactorAuthenticationStrengthDisplayName = "Multifactor authentication";
    private const string PhishingResistantAuthenticationStrengthId = "00000000-0000-0000-0000-000000000004";
    private const string PhishingResistantAuthenticationStrengthDisplayName = "Phishing resistant MFA";
    private static readonly string[] ProtectedAdminRoleTemplateIds =
    [
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
        "c4e39bd9-1100-46d3-8c65-fb160da0071f",
        "b0f54661-2d74-4c50-afa3-1ec803f12efe",
        "158c047a-c907-4556-b7ef-446551a6b5f7",
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
        "29232cdf-9323-42fd-ade2-1d097af3e4de",
        "62e90394-69f5-4237-9190-012177145e10",
        "729827e3-9c14-49f7-bb1b-9608f156bbb8",
        "966707d0-3269-4727-9be2-8c3a10f19b9d",
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
        "194ae4cb-b126-40b2-bd5b-6091b380977d",
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
        "fe930be7-5e62-47db-91af-98c3a49a38b1",
        "0526716b-113d-4c15-b2c8-68e3c22b9f80",
        "fdd7a751-b60b-444a-984c-02652fe8fa1c",
        "4d6ac14f-3453-41d0-bef9-a3e0c569773a",
        "2b745bdf-0803-4d80-aa65-822c4493daac",
        "11648597-926c-4cf3-9c36-bcebb0ba8dcc",
        "e8611ab8-c189-46e8-94e1-60213ab1f814",
        "f023fd81-a637-4b56-95fd-791ac0226033",
        "69091246-20e8-4a56-aa4d-066075b2a7a8"
    ];

    private readonly HttpClient _httpClient;
    private readonly IOptions<SecurityzatorGraphOptions> _options;

    public ConditionalAccessGraphClient(
        HttpClient httpClient,
        IOptions<SecurityzatorGraphOptions> options)
    {
        _httpClient = httpClient;
        _options = options;
    }

    internal async Task<ConditionalAccessPolicySummary?> FindPolicyByDisplayNameAsync(
        string accessToken,
        string displayName,
        CancellationToken cancellationToken = default)
    {
        var escapedName = displayName.Replace("'", "''", StringComparison.Ordinal);
        var filter = Uri.EscapeDataString($"displayName eq '{escapedName}'");
        var requestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/identity/conditionalAccess/policies?$filter={filter}&$select=id,displayName,state";
        var responseBody = await SendGetAsync(requestUrl, "Conditional Access lookup failed", accessToken, cancellationToken);

        using var payload = JsonDocument.Parse(responseBody);

        if (!payload.RootElement.TryGetProperty("value", out var results)
            || results.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var first = results.EnumerateArray().FirstOrDefault();
        return first.ValueKind == JsonValueKind.Undefined
            ? null
            : new ConditionalAccessPolicySummary(
                GetString(first, "id"),
                GetString(first, "displayName"),
                GetString(first, "state"));
    }

    internal async Task ProbePolicyReadAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var requestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/identity/conditionalAccess/policies?$top=1&$select=id,state";
        _ = await SendGetAsync(requestUrl, "Conditional Access probe failed", accessToken, cancellationToken);
    }

    internal async Task<ConditionalAccessPolicySummary> CreateBlockLegacyAuthenticationPolicyAsync(
        string accessToken,
        RemediationLaunchMode launchMode,
        string includeGroupId,
        string? excludeGroupId,
        CancellationToken cancellationToken = default)
    {
        var payload = BuildGroupTargetedPolicyRequest(
            "SS-AUTO | Block legacy authentication",
            launchMode,
            includeGroupId,
            excludeGroupId,
            ["other"],
            ["block"]);

        return await CreatePolicyAsync(accessToken, payload, cancellationToken);
    }

    internal async Task<ConditionalAccessPolicySummary> CreateRequireMfaForAdminsPolicyAsync(
        string accessToken,
        RemediationLaunchMode launchMode,
        string includeGroupId,
        string? excludeGroupId,
        CancellationToken cancellationToken = default)
    {
        var payload = BuildGroupTargetedPolicyRequest(
            "SS-AUTO | Require MFA for privileged admins",
            launchMode,
            includeGroupId,
            excludeGroupId,
            ["all"],
            ["mfa"]);

        return await CreatePolicyAsync(accessToken, payload, cancellationToken);
    }

    internal async Task<ConditionalAccessPolicySummary> CreateRequireMfaForAllUsersPolicyAsync(
        string accessToken,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        CancellationToken cancellationToken = default)
    {
        var payload = BuildAllUsersPolicyRequest(
            "SS-AUTO | Require MFA for all users",
            launchMode,
            excludeGroupId,
            CreateAuthenticationStrengthReference(
                MultifactorAuthenticationStrengthId,
                MultifactorAuthenticationStrengthDisplayName));

        return await CreatePolicyAsync(accessToken, payload, cancellationToken);
    }

    internal async Task<ConditionalAccessPolicySummary> CreateRequireMfaForGuestAccessPolicyAsync(
        string accessToken,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        CancellationToken cancellationToken = default)
    {
        var payload = BuildGuestAccessPolicyRequest(
            "SS-AUTO | Require MFA for guest access",
            launchMode,
            excludeGroupId,
            ["mfa"]);

        return await CreatePolicyAsync(accessToken, payload, cancellationToken);
    }

    internal async Task<ConditionalAccessPolicySummary> CreateRequireMfaForAdminPortalsPolicyAsync(
        string accessToken,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        CancellationToken cancellationToken = default)
    {
        var payload = BuildAdminRolesPolicyRequest(
            "SS-AUTO | Require MFA for Microsoft admin portals",
            launchMode,
            [MicrosoftAdminPortalsApplication],
            excludeGroupId,
            null,
            null,
            ["mfa"]);

        return await CreatePolicyAsync(accessToken, payload, cancellationToken);
    }

    internal async Task<ConditionalAccessPolicySummary> CreateRequireMfaForAzureManagementPolicyAsync(
        string accessToken,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        CancellationToken cancellationToken = default)
    {
        var payload = BuildAllUsersPolicyRequest(
            "SS-AUTO | Require MFA for Azure management",
            launchMode,
            excludeGroupId,
            includeApplications: [AzureResourceManagerApplicationId],
            builtInControls: ["mfa"]);

        return await CreatePolicyAsync(accessToken, payload, cancellationToken);
    }

    internal async Task<ConditionalAccessPolicySummary> CreateSecureSecurityInfoRegistrationPolicyAsync(
        string accessToken,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        CancellationToken cancellationToken = default)
    {
        var payload = BuildUserActionPolicyRequest(
            "SS-AUTO | Secure security info registration",
            launchMode,
            "urn:user:registersecurityinfo",
            excludeGroupId,
            ["mfa"],
            ["All"],
            ["AllTrusted"],
            [GuestsOrExternalUsersScope]);

        return await CreatePolicyAsync(accessToken, payload, cancellationToken);
    }

    internal async Task<ConditionalAccessPolicySummary> CreateRequireMfaForRiskySignInsPolicyAsync(
        string accessToken,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        CancellationToken cancellationToken = default)
    {
        var payload = BuildAllUsersPolicyRequest(
            "SS-AUTO | Require MFA when risky sign-ins are detected",
            launchMode,
            excludeGroupId,
            includeApplications: ["All"],
            builtInControls: ["mfa"],
            signInRiskLevels: ["medium", "high"],
            excludeSpecialUsers: [GuestsOrExternalUsersScope],
            excludeRoleIds: ProtectedAdminRoleTemplateIds,
            sessionControls: CreateEveryTimeSignInFrequency());

        return await CreatePolicyAsync(accessToken, payload, cancellationToken);
    }

    internal async Task<ConditionalAccessPolicySummary> CreateRequirePasswordChangeForHighRiskUsersPolicyAsync(
        string accessToken,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        CancellationToken cancellationToken = default)
    {
        var payload = BuildAllUsersPolicyRequest(
            "SS-AUTO | Require password change for high-risk users",
            launchMode,
            excludeGroupId,
            includeApplications: ["All"],
            builtInControls: ["mfa", "passwordChange"],
            userRiskLevels: ["high"],
            excludeSpecialUsers: [GuestsOrExternalUsersScope],
            excludeRoleIds: ProtectedAdminRoleTemplateIds,
            sessionControls: CreateEveryTimeSignInFrequency());

        return await CreatePolicyAsync(accessToken, payload, cancellationToken);
    }

    internal async Task<ConditionalAccessPolicySummary> CreateRequirePhishingResistantMfaForAdminsPolicyAsync(
        string accessToken,
        RemediationLaunchMode launchMode,
        string includeGroupId,
        string? excludeGroupId,
        CancellationToken cancellationToken = default)
    {
        var payload = BuildGroupTargetedPolicyRequest(
            "SS-AUTO | Require phishing-resistant MFA for privileged admins",
            launchMode,
            includeGroupId,
            excludeGroupId,
            ["all"],
            Array.Empty<string>(),
            CreateAuthenticationStrengthReference(
                PhishingResistantAuthenticationStrengthId,
                PhishingResistantAuthenticationStrengthDisplayName));

        return await CreatePolicyAsync(accessToken, payload, cancellationToken);
    }

    internal async Task<ConditionalAccessPolicySummary> UpdatePolicyStateAsync(
        string accessToken,
        string policyId,
        string policyState,
        CancellationToken cancellationToken = default)
    {
        await SendJsonAsync(
            HttpMethod.Patch,
            $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/identity/conditionalAccess/policies/{Uri.EscapeDataString(policyId)}",
            new { state = policyState },
            "Conditional Access policy update failed",
            accessToken,
            cancellationToken);

        var lookupBody = await SendGetAsync(
            $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/identity/conditionalAccess/policies/{Uri.EscapeDataString(policyId)}?$select=id,displayName,state",
            "Conditional Access policy readback failed",
            accessToken,
            cancellationToken);

        using var document = JsonDocument.Parse(lookupBody);
        return new ConditionalAccessPolicySummary(
            GetString(document.RootElement, "id"),
            GetString(document.RootElement, "displayName"),
            GetString(document.RootElement, "state"));
    }

    private async Task<ConditionalAccessPolicySummary> CreatePolicyAsync(
        string accessToken,
        ConditionalAccessCreateRequest payload,
        CancellationToken cancellationToken)
    {
        var responseBody = await SendJsonAsync(
            HttpMethod.Post,
            $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/identity/conditionalAccess/policies",
            payload,
            "Conditional Access policy creation failed",
            accessToken,
            cancellationToken);

        using var document = JsonDocument.Parse(responseBody);
        return new ConditionalAccessPolicySummary(
            GetString(document.RootElement, "id"),
            GetString(document.RootElement, "displayName"),
            GetString(document.RootElement, "state"));
    }

    private async Task<string> SendGetAsync(
        string requestUrl,
        string errorPrefix,
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

        throw new GraphServiceException(BuildErrorMessage(errorPrefix, response.StatusCode, responseBody));
    }

    private async Task<string> SendJsonAsync(
        HttpMethod method,
        string requestUrl,
        object payload,
        string errorPrefix,
        string accessToken,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, requestUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Content = JsonContent.Create(payload);

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (response.IsSuccessStatusCode)
        {
            return responseBody;
        }

        if (GraphApiVersionResolver.ShouldRetryWithBeta(_options.Value, response.StatusCode, requestUrl))
        {
            var betaUrl = GraphApiVersionResolver.ToBetaUrl(_options.Value, requestUrl);
            using var betaRequest = new HttpRequestMessage(method, betaUrl);
            betaRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            betaRequest.Content = JsonContent.Create(payload);

            using var betaResponse = await _httpClient.SendAsync(betaRequest, cancellationToken);
            var betaResponseBody = await betaResponse.Content.ReadAsStringAsync(cancellationToken);

            if (betaResponse.IsSuccessStatusCode)
            {
                return betaResponseBody;
            }
        }

        throw new GraphServiceException(BuildErrorMessage(errorPrefix, response.StatusCode, responseBody));
    }

    private static ConditionalAccessCreateRequest BuildGroupTargetedPolicyRequest(
        string displayName,
        RemediationLaunchMode launchMode,
        string includeGroupId,
        string? excludeGroupId,
        string[] clientAppTypes,
        string[] builtInControls,
        AuthenticationStrengthReference? authenticationStrength = null)
    {
        return new ConditionalAccessCreateRequest(
            DisplayName: displayName,
            State: ResolvePolicyState(launchMode),
            Conditions: new ConditionalAccessConditions(
                Users: new ConditionalAccessUsers(
                    IncludeUsers: [],
                    ExcludeUsers: [],
                    IncludeGroups: [includeGroupId],
                    ExcludeGroups: string.IsNullOrWhiteSpace(excludeGroupId) ? [] : [excludeGroupId],
                    IncludeRoles: [],
                    ExcludeRoles: []),
                Applications: new ConditionalAccessApplications(["All"]),
                ClientAppTypes: clientAppTypes),
            GrantControls: new ConditionalAccessGrantControls("OR", builtInControls, authenticationStrength));
    }

    private static ConditionalAccessCreateRequest BuildAllUsersPolicyRequest(
        string displayName,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        AuthenticationStrengthReference authenticationStrength)
    {
        return BuildAllUsersPolicyRequest(
            displayName,
            launchMode,
            excludeGroupId,
            ["All"],
            [],
            authenticationStrength);
    }

    private static ConditionalAccessCreateRequest BuildAllUsersPolicyRequest(
        string displayName,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        string[] includeApplications,
        string[] builtInControls,
        AuthenticationStrengthReference? authenticationStrength = null,
        string[]? signInRiskLevels = null,
        string[]? userRiskLevels = null,
        string[]? excludeSpecialUsers = null,
        string[]? excludeRoleIds = null,
        ConditionalAccessSessionControls? sessionControls = null)
    {
        var excludeUsers = excludeSpecialUsers ?? [];

        return new ConditionalAccessCreateRequest(
            DisplayName: displayName,
            State: ResolvePolicyState(launchMode),
            Conditions: new ConditionalAccessConditions(
                Users: new ConditionalAccessUsers(
                    IncludeUsers: ["All"],
                    ExcludeUsers: excludeUsers,
                    IncludeGroups: [],
                    ExcludeGroups: string.IsNullOrWhiteSpace(excludeGroupId) ? [] : [excludeGroupId],
                    IncludeRoles: [],
                    ExcludeRoles: excludeRoleIds ?? []),
                Applications: new ConditionalAccessApplications(includeApplications),
                ClientAppTypes: ["all"],
                SignInRiskLevels: signInRiskLevels ?? [],
                UserRiskLevels: userRiskLevels ?? [],
                Locations: null),
            GrantControls: new ConditionalAccessGrantControls("OR", builtInControls, authenticationStrength),
            SessionControls: sessionControls);
    }

    private static ConditionalAccessCreateRequest BuildGuestAccessPolicyRequest(
        string displayName,
        RemediationLaunchMode launchMode,
        string? excludeGroupId,
        string[] builtInControls)
    {
        return new ConditionalAccessCreateRequest(
            DisplayName: displayName,
            State: ResolvePolicyState(launchMode),
            Conditions: new ConditionalAccessConditions(
                Users: new ConditionalAccessUsers(
                    IncludeUsers: [GuestsOrExternalUsersScope],
                    ExcludeUsers: [],
                    IncludeGroups: [],
                    ExcludeGroups: string.IsNullOrWhiteSpace(excludeGroupId) ? [] : [excludeGroupId],
                    IncludeRoles: [],
                    ExcludeRoles: []),
                Applications: new ConditionalAccessApplications(["All"]),
                ClientAppTypes: ["all"]),
            GrantControls: new ConditionalAccessGrantControls("OR", builtInControls, null));
    }

    private static ConditionalAccessCreateRequest BuildAdminRolesPolicyRequest(
        string displayName,
        RemediationLaunchMode launchMode,
        string[] includeApplications,
        string? excludeGroupId,
        string[]? signInRiskLevels,
        string[]? userRiskLevels,
        string[] builtInControls,
        AuthenticationStrengthReference? authenticationStrength = null,
        ConditionalAccessSessionControls? sessionControls = null)
    {
        return new ConditionalAccessCreateRequest(
            DisplayName: displayName,
            State: ResolvePolicyState(launchMode),
            Conditions: new ConditionalAccessConditions(
                Users: new ConditionalAccessUsers(
                    IncludeUsers: [],
                    ExcludeUsers: [],
                    IncludeGroups: [],
                    ExcludeGroups: string.IsNullOrWhiteSpace(excludeGroupId) ? [] : [excludeGroupId],
                    IncludeRoles: ProtectedAdminRoleTemplateIds,
                    ExcludeRoles: []),
                Applications: new ConditionalAccessApplications(includeApplications),
                ClientAppTypes: ["all"],
                SignInRiskLevels: signInRiskLevels ?? [],
                UserRiskLevels: userRiskLevels ?? [],
                Locations: null),
            GrantControls: new ConditionalAccessGrantControls("OR", builtInControls, authenticationStrength),
            SessionControls: sessionControls);
    }

    private static ConditionalAccessCreateRequest BuildUserActionPolicyRequest(
        string displayName,
        RemediationLaunchMode launchMode,
        string userAction,
        string? excludeGroupId,
        string[] builtInControls,
        string[] includeLocations,
        string[] excludeLocations,
        string[] excludeSpecialUsers)
    {
        return new ConditionalAccessCreateRequest(
            DisplayName: displayName,
            State: ResolvePolicyState(launchMode),
            Conditions: new ConditionalAccessConditions(
                Users: new ConditionalAccessUsers(
                    IncludeUsers: ["All"],
                    ExcludeUsers: excludeSpecialUsers,
                    IncludeGroups: [],
                    ExcludeGroups: string.IsNullOrWhiteSpace(excludeGroupId) ? [] : [excludeGroupId],
                    IncludeRoles: [],
                    ExcludeRoles: []),
                Applications: new ConditionalAccessApplications([], [userAction]),
                ClientAppTypes: ["all"],
                SignInRiskLevels: [],
                UserRiskLevels: [],
                Locations: new ConditionalAccessLocations(includeLocations, excludeLocations)),
            GrantControls: new ConditionalAccessGrantControls("OR", builtInControls, null));
    }

    private static AuthenticationStrengthReference CreateAuthenticationStrengthReference(
        string id,
        string displayName)
    {
        return new AuthenticationStrengthReference(id, displayName);
    }

    private static string BuildErrorMessage(
        string prefix,
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
            ? $"{prefix} with {(int)statusCode}."
            : $"{prefix} with {(int)statusCode}. {bodySnippet}";
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

    private sealed record ConditionalAccessCreateRequest(
        [property: JsonPropertyName("displayName")] string DisplayName,
        [property: JsonPropertyName("state")] string State,
        [property: JsonPropertyName("conditions")] ConditionalAccessConditions Conditions,
        [property: JsonPropertyName("grantControls")] ConditionalAccessGrantControls GrantControls,
        [property: JsonPropertyName("sessionControls"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        ConditionalAccessSessionControls? SessionControls = null);

    private sealed record ConditionalAccessConditions(
        [property: JsonPropertyName("users")] ConditionalAccessUsers Users,
        [property: JsonPropertyName("applications")] ConditionalAccessApplications Applications,
        [property: JsonPropertyName("clientAppTypes")] string[] ClientAppTypes,
        [property: JsonPropertyName("signInRiskLevels"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        string[] SignInRiskLevels,
        [property: JsonPropertyName("userRiskLevels"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        string[] UserRiskLevels,
        [property: JsonPropertyName("locations"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        ConditionalAccessLocations? Locations)
    {
        internal ConditionalAccessConditions(
            ConditionalAccessUsers Users,
            ConditionalAccessApplications Applications,
            string[] ClientAppTypes)
            : this(Users, Applications, ClientAppTypes, [], [], null)
        {
        }
    }

    private sealed record ConditionalAccessUsers(
        [property: JsonPropertyName("includeUsers")] string[] IncludeUsers,
        [property: JsonPropertyName("excludeUsers")] string[] ExcludeUsers,
        [property: JsonPropertyName("includeGroups")] string[] IncludeGroups,
        [property: JsonPropertyName("excludeGroups")] string[] ExcludeGroups,
        [property: JsonPropertyName("includeRoles")] string[] IncludeRoles,
        [property: JsonPropertyName("excludeRoles")] string[] ExcludeRoles);

    private sealed record ConditionalAccessApplications(
        [property: JsonPropertyName("includeApplications")] string[] IncludeApplications,
        [property: JsonPropertyName("includeUserActions"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        string[] IncludeUserActions)
    {
        internal ConditionalAccessApplications(string[] IncludeApplications)
            : this(IncludeApplications, [])
        {
        }
    }

    private sealed record ConditionalAccessLocations(
        [property: JsonPropertyName("includeLocations")] string[] IncludeLocations,
        [property: JsonPropertyName("excludeLocations")] string[] ExcludeLocations);

    private sealed record ConditionalAccessGrantControls(
        [property: JsonPropertyName("operator")] string Operator,
        [property: JsonPropertyName("builtInControls")] string[] BuiltInControls,
        [property: JsonPropertyName("authenticationStrength"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        AuthenticationStrengthReference? AuthenticationStrength);

    private sealed record ConditionalAccessSessionControls(
        [property: JsonPropertyName("signInFrequency")] SignInFrequencySessionControl SignInFrequency);

    private sealed record SignInFrequencySessionControl(
        [property: JsonPropertyName("value")] int? Value,
        [property: JsonPropertyName("type")] string Type,
        [property: JsonPropertyName("frequencyInterval")] string FrequencyInterval,
        [property: JsonPropertyName("isEnabled")] bool IsEnabled,
        [property: JsonPropertyName("authenticationType")] string AuthenticationType);

    private sealed record AuthenticationStrengthReference(
        [property: JsonPropertyName("id")] string Id,
        [property: JsonPropertyName("displayName"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        string? DisplayName);

    private static ConditionalAccessSessionControls CreateEveryTimeSignInFrequency()
    {
        return new ConditionalAccessSessionControls(
            new SignInFrequencySessionControl(
                null,
                "hours",
                "everyTime",
                true,
                "primaryAndSecondaryAuthentication"));
    }

    private static string ResolvePolicyState(RemediationLaunchMode launchMode)
    {
        return launchMode switch
        {
            RemediationLaunchMode.ReportOnly => "enabledForReportingButNotEnforced",
            RemediationLaunchMode.Enabled => "enabled",
            _ => throw new InvalidOperationException("Direct-apply mode does not map to a Conditional Access policy state.")
        };
    }
}
