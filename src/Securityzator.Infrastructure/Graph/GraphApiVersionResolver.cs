using System.Net;

namespace Securityzator.Infrastructure.Graph;

internal static class GraphApiVersionResolver
{
    internal static string GetPrimaryBaseUrl(SecurityzatorGraphOptions options)
    {
        return options.GraphBaseUrl.Trim().TrimEnd('/');
    }

    internal static string GetBetaBaseUrl(SecurityzatorGraphOptions options)
    {
        return string.IsNullOrWhiteSpace(options.GraphBetaBaseUrl)
            ? GetPrimaryBaseUrl(options)
            : options.GraphBetaBaseUrl.Trim().TrimEnd('/');
    }

    internal static bool ShouldRetryWithBeta(
        SecurityzatorGraphOptions options,
        HttpStatusCode statusCode,
        string requestUrl)
    {
        if (!options.EnableBetaFallback || string.IsNullOrWhiteSpace(requestUrl))
        {
            return false;
        }

        var primaryBaseUrl = GetPrimaryBaseUrl(options);
        var betaBaseUrl = GetBetaBaseUrl(options);

        if (!requestUrl.StartsWith(primaryBaseUrl, StringComparison.OrdinalIgnoreCase)
            || requestUrl.StartsWith(betaBaseUrl, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return statusCode is HttpStatusCode.BadRequest
            or HttpStatusCode.NotFound
            or HttpStatusCode.MethodNotAllowed;
    }

    internal static string ToBetaUrl(
        SecurityzatorGraphOptions options,
        string requestUrl)
    {
        var primaryBaseUrl = GetPrimaryBaseUrl(options);
        var betaBaseUrl = GetBetaBaseUrl(options);

        if (!requestUrl.StartsWith(primaryBaseUrl, StringComparison.OrdinalIgnoreCase))
        {
            return requestUrl;
        }

        return betaBaseUrl + requestUrl[primaryBaseUrl.Length..];
    }
}
