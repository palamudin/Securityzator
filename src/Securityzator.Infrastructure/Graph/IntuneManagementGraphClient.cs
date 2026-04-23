using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Securityzator.Infrastructure.Graph;

public sealed class IntuneManagementGraphClient
{
    private readonly HttpClient _httpClient;
    private readonly IOptions<SecurityzatorGraphOptions> _options;

    public IntuneManagementGraphClient(
        HttpClient httpClient,
        IOptions<SecurityzatorGraphOptions> options)
    {
        _httpClient = httpClient;
        _options = options;
    }

    internal async Task<IntuneManagedDeviceProbeResult> ProbeManagedDevicesAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var requestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/deviceManagement/managedDeviceOverview";
        var responseBody = await SendGetAsync(requestUrl, "Intune managed-device overview probe failed", accessToken, cancellationToken);

        using var payload = JsonDocument.Parse(responseBody);

        return new IntuneManagedDeviceProbeResult(
            GetInt32(payload.RootElement, "enrolledDeviceCount"));
    }

    internal Task<IntunePolicyProbeResult> ProbeDeviceConfigurationsAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var requestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/deviceManagement/deviceConfigurations?$top=1&$select=id,displayName";
        return ProbeCollectionAsync(requestUrl, "Intune device-configuration probe failed", accessToken, cancellationToken);
    }

    internal Task<IntunePolicyProbeResult> ProbeDeviceCompliancePoliciesAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var requestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/deviceManagement/deviceCompliancePolicies?$top=1&$select=id,displayName";
        return ProbeCollectionAsync(requestUrl, "Intune compliance-policy probe failed", accessToken, cancellationToken);
    }

    private async Task<IntunePolicyProbeResult> ProbeCollectionAsync(
        string requestUrl,
        string errorPrefix,
        string accessToken,
        CancellationToken cancellationToken)
    {
        var responseBody = await SendGetAsync(requestUrl, errorPrefix, accessToken, cancellationToken);

        using var payload = JsonDocument.Parse(responseBody);

        if (!payload.RootElement.TryGetProperty("value", out var resultsElement)
            || resultsElement.ValueKind != JsonValueKind.Array)
        {
            return new IntunePolicyProbeResult(false);
        }

        return new IntunePolicyProbeResult(resultsElement.GetArrayLength() > 0);
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

    private static int GetInt32(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return 0;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetInt32(out var numericValue))
        {
            return numericValue;
        }

        return property.ValueKind == JsonValueKind.String
               && int.TryParse(property.GetString(), out var parsed)
            ? parsed
            : 0;
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

    internal sealed record IntuneManagedDeviceProbeResult(
        int EnrolledDeviceCount);

    internal sealed record IntunePolicyProbeResult(
        bool HasAnyPolicies);
}
