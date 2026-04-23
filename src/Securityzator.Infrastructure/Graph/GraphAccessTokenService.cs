using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Securityzator.Infrastructure.Graph;

public sealed class GraphAccessTokenService
{
    private readonly HttpClient _httpClient;
    private readonly IOptions<SecurityzatorGraphOptions> _options;

    public GraphAccessTokenService(
        HttpClient httpClient,
        IOptions<SecurityzatorGraphOptions> options)
    {
        _httpClient = httpClient;
        _options = options;
    }

    public async Task<string> AcquireApplicationTokenAsync(
        string tenantId,
        string clientId,
        string clientSecret,
        CancellationToken cancellationToken = default)
    {
        return await AcquireApplicationTokenForScopeAsync(
            tenantId,
            clientId,
            clientSecret,
            "https://graph.microsoft.com/.default",
            cancellationToken);
    }

    public async Task<string> AcquireApplicationTokenForScopeAsync(
        string tenantId,
        string clientId,
        string clientSecret,
        string scope,
        CancellationToken cancellationToken = default)
    {
        var authorityBaseUrl = _options.Value.AuthorityBaseUrl.TrimEnd('/');
        var tokenEndpoint = $"{authorityBaseUrl}/{tenantId.Trim()}/oauth2/v2.0/token";

        using var requestContent = new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("client_id", clientId.Trim()),
            new KeyValuePair<string, string>("client_secret", clientSecret),
            new KeyValuePair<string, string>("scope", scope.Trim()),
            new KeyValuePair<string, string>("grant_type", "client_credentials")
        ]);

        using var response = await _httpClient.PostAsync(tokenEndpoint, requestContent, cancellationToken);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            throw new GraphServiceException(BuildErrorMessage(response.StatusCode, responseBody));
        }

        using var payload = JsonDocument.Parse(responseBody);

        if (!payload.RootElement.TryGetProperty("access_token", out var accessTokenElement))
        {
            throw new GraphServiceException("Token request succeeded but Microsoft Entra did not return an access token.");
        }

        var accessToken = accessTokenElement.GetString();

        if (string.IsNullOrWhiteSpace(accessToken))
        {
            throw new GraphServiceException("Token request succeeded but the returned access token was empty.");
        }

        return accessToken;
    }

    private static string BuildErrorMessage(
        System.Net.HttpStatusCode statusCode,
        string responseBody)
    {
        var bodySnippet = SummarizeResponseBody(responseBody);
        return string.IsNullOrWhiteSpace(bodySnippet)
            ? $"Token request failed with {(int)statusCode}."
            : $"Token request failed with {(int)statusCode}. {bodySnippet}";
    }

    private static string SummarizeResponseBody(string responseBody)
    {
        if (string.IsNullOrWhiteSpace(responseBody))
        {
            return string.Empty;
        }

        var normalized = responseBody.Trim().ReplaceLineEndings(" ");
        return normalized.Length <= 320 ? normalized : normalized[..320];
    }
}
