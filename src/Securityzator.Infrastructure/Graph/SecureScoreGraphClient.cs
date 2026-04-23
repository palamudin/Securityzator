using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Securityzator.Infrastructure.Graph;

public sealed class SecureScoreGraphClient
{
    private readonly HttpClient _httpClient;
    private readonly IOptions<SecurityzatorGraphOptions> _options;

    public SecureScoreGraphClient(
        HttpClient httpClient,
        IOptions<SecurityzatorGraphOptions> options)
    {
        _httpClient = httpClient;
        _options = options;
    }

    internal async Task<IReadOnlyList<GraphSecureScoreControlProfile>> ListSecureScoreControlProfilesAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var profiles = new List<GraphSecureScoreControlProfile>();
        var nextRequestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/security/secureScoreControlProfiles?$top=999";

        while (!string.IsNullOrWhiteSpace(nextRequestUrl))
        {
            var responseBody = await SendGetAsync(nextRequestUrl, accessToken, cancellationToken);

            using var payload = JsonDocument.Parse(responseBody);

            if (payload.RootElement.TryGetProperty("value", out var resultsElement)
                && resultsElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var result in resultsElement.EnumerateArray())
                {
                    profiles.Add(MapControlProfile(result));
                }
            }

            nextRequestUrl = payload.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement)
                ? nextLinkElement.GetString()
                : null;
        }

        return profiles;
    }

    internal async Task ProbeSecureScoreReadAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var requestUrl = $"{_options.Value.GraphBaseUrl.TrimEnd('/')}/security/secureScoreControlProfiles?$top=1&$select=id,title";
        _ = await SendGetAsync(requestUrl, accessToken, cancellationToken);
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

    private static GraphSecureScoreControlProfile MapControlProfile(JsonElement element)
    {
        return new GraphSecureScoreControlProfile(
            GetString(element, "id"),
            GetString(element, "title"),
            GetString(element, "controlCategory"),
            GetString(element, "service"),
            GetInt32(element, "rank"),
            GetDouble(element, "maxScore"),
            GetString(element, "tier"),
            GetString(element, "implementationCost"),
            GetString(element, "userImpact"),
            GetString(element, "actionType"),
            GetString(element, "remediation"),
            GetString(element, "remediationImpact"),
            GetBoolean(element, "deprecated"),
            GetStringArray(element, "threats"));
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

    private static int GetInt32(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return 0;
        }

        if (property.ValueKind == JsonValueKind.Number)
        {
            if (property.TryGetInt32(out var intValue))
            {
                return intValue;
            }

            if (property.TryGetDouble(out var doubleValue))
            {
                return (int)Math.Round(doubleValue, MidpointRounding.AwayFromZero);
            }
        }

        return int.TryParse(property.ToString(), out var parsedValue) ? parsedValue : 0;
    }

    private static double GetDouble(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return 0;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetDouble(out var doubleValue))
        {
            return doubleValue;
        }

        return double.TryParse(property.ToString(), out var parsedValue) ? parsedValue : 0;
    }

    private static bool GetBoolean(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return false;
        }

        if (property.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            return property.GetBoolean();
        }

        return bool.TryParse(property.ToString(), out var parsedValue) && parsedValue;
    }

    private static IReadOnlyList<string> GetStringArray(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<string>();
        }

        return property
            .EnumerateArray()
            .Where(item => item.ValueKind == JsonValueKind.String)
            .Select(item => item.GetString())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Cast<string>()
            .ToArray();
    }

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
            ? $"Secure Score sync failed with {(int)statusCode}."
            : $"Secure Score sync failed with {(int)statusCode}. {bodySnippet}";
    }
}
