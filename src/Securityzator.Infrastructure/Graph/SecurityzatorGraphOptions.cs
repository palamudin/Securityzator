namespace Securityzator.Infrastructure.Graph;

public sealed class SecurityzatorGraphOptions
{
    public string GraphBaseUrl { get; set; } = "https://graph.microsoft.com/v1.0";
    public string GraphBetaBaseUrl { get; set; } = "https://graph.microsoft.com/beta";
    public bool EnableBetaFallback { get; set; } = true;

    public string AuthorityBaseUrl { get; set; } = "https://login.microsoftonline.com";

    public bool UseEnvironmentProxy { get; set; }
}
