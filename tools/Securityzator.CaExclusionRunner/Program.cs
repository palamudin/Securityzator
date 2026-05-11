using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Securityzator.Infrastructure.DependencyInjection;
using Securityzator.Infrastructure.Graph;
using Securityzator.Infrastructure.Security;
using Securityzator.Infrastructure.Storage;

var userPrincipalName = ResolveRequiredArgument(args, "--userPrincipalName");
var selectedConnectionId = ResolveOptionalArgument(args, "--connectionId");
var emitJson = HasFlag(args, "--json");
var jsonPath = ResolveOptionalArgument(args, "--jsonPath");

var contentRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "Securityzator.Worker"));
using var host = Host.CreateDefaultBuilder(args)
    .UseContentRoot(contentRoot)
    .ConfigureAppConfiguration((_, configuration) =>
    {
        configuration.Sources.Clear();
        configuration
            .SetBasePath(contentRoot)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
            .AddEnvironmentVariables();
    })
    .ConfigureServices((context, services) =>
    {
        services.AddSecurityzatorInfrastructure(context.Configuration, new RunnerHostEnvironment(contentRoot));
    })
    .Build();

var stateStore = host.Services.GetRequiredService<JsonFileSecurityzatorStateStore>();
var protector = host.Services.GetRequiredService<ClientSecretProtector>();
var tokenService = host.Services.GetRequiredService<GraphAccessTokenService>();
var graphOptions = host.Services.GetRequiredService<IOptions<SecurityzatorGraphOptions>>().Value;

var connection = await stateStore.ReadAsync(state =>
{
    var connections = state.Connections.AsEnumerable();

    if (!string.IsNullOrWhiteSpace(selectedConnectionId) && Guid.TryParse(selectedConnectionId, out var parsedConnectionId))
    {
        connections = connections.Where(item => item.Id == parsedConnectionId);
    }

    return connections
        .OrderByDescending(item => item.UpdatedUtc)
        .FirstOrDefault();
});

if (connection is null)
{
    throw new InvalidOperationException("No saved Azure connection was found for the Conditional Access exclusion update.");
}

if (string.IsNullOrWhiteSpace(connection.ProtectedClientSecret))
{
    throw new InvalidOperationException($"Connection '{connection.DisplayName}' does not have a stored client secret.");
}

var clientSecret = protector.Unprotect(connection.ProtectedClientSecret);
var accessToken = await tokenService.AcquireApplicationTokenAsync(
    connection.TenantId,
    connection.ClientId,
    clientSecret);

using var httpClient = new HttpClient(CreateHttpHandler(graphOptions.UseEnvironmentProxy));
httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

var resolvedUser = await ResolveUserAsync(httpClient, graphOptions.GraphBaseUrl, userPrincipalName);
var policies = await GetConditionalAccessPoliciesAsync(httpClient, graphOptions.GraphBaseUrl);
var spread = BuildSpread(policies);
var results = new List<PolicyUpdateResult>(policies.Count);

Console.WriteLine($"Connection: {connection.DisplayName} ({connection.TenantId})");
Console.WriteLine($"Target user: {resolvedUser.UserPrincipalName} ({resolvedUser.Id})");
Console.WriteLine($"Policies found: {spread.Total} | enabled={spread.Enabled} reportOnly={spread.ReportOnly} disabled={spread.Disabled}");

foreach (var policy in policies)
{
    Console.WriteLine($"Processing '{policy.DisplayName}' ({policy.State})...");

    try
    {
        if (policy.ConditionsNode is null)
        {
            results.Add(new PolicyUpdateResult(
                policy.Id,
                policy.DisplayName,
                policy.State,
                "Skipped",
                "Policy did not return a conditions block.",
                0,
                0));
            continue;
        }

        var conditionsNode = policy.ConditionsNode.DeepClone();
        var usersNode = conditionsNode["users"] as JsonObject;

        if (usersNode is null)
        {
            results.Add(new PolicyUpdateResult(
                policy.Id,
                policy.DisplayName,
                policy.State,
                "Skipped",
                "Policy did not return a users conditions block.",
                0,
                0));
            continue;
        }

        var excludeUsers = usersNode["excludeUsers"] as JsonArray ?? [];
        if (usersNode["excludeUsers"] is null)
        {
            usersNode["excludeUsers"] = excludeUsers;
        }

        var before = excludeUsers
            .Select(node => node?.GetValue<string>() ?? string.Empty)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (before.Contains(resolvedUser.Id, StringComparer.OrdinalIgnoreCase))
        {
            results.Add(new PolicyUpdateResult(
                policy.Id,
                policy.DisplayName,
                policy.State,
                "AlreadyExcluded",
                "User object ID already exists in excludeUsers.",
                before.Count,
                before.Count));
            continue;
        }

        excludeUsers.Add(resolvedUser.Id);

        var merged = excludeUsers
            .Select(node => node?.GetValue<string>() ?? string.Empty)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        usersNode["excludeUsers"] = new JsonArray(merged.Select(value => JsonValue.Create(value)).ToArray());

        var patchBody = new JsonObject
        {
            ["conditions"] = conditionsNode
        };

        await SendJsonAsync(
            httpClient,
            $"{graphOptions.GraphBaseUrl.TrimEnd('/')}/identity/conditionalAccess/policies/{Uri.EscapeDataString(policy.Id)}",
            HttpMethod.Patch,
            patchBody);

        results.Add(new PolicyUpdateResult(
            policy.Id,
            policy.DisplayName,
            policy.State,
            "Updated",
            "Added user object ID to excludeUsers.",
            before.Count,
            merged.Length));
    }
    catch (Exception ex)
    {
        results.Add(new PolicyUpdateResult(
            policy.Id,
            policy.DisplayName,
            policy.State,
            "Failed",
            NormalizeMessage(ex.Message),
            null,
            null));
    }
}

var report = new CaExclusionRunnerReport(
    connection.Id,
    connection.DisplayName,
    connection.TenantId,
    resolvedUser.Id,
    resolvedUser.DisplayName,
    resolvedUser.UserPrincipalName,
    spread,
    results,
    DateTimeOffset.UtcNow);

Console.WriteLine($"Updated: {results.Count(item => item.Result == "Updated")}");
Console.WriteLine($"Already excluded: {results.Count(item => item.Result == "AlreadyExcluded")}");
Console.WriteLine($"Failed: {results.Count(item => item.Result == "Failed")}");
Console.WriteLine($"Skipped: {results.Count(item => item.Result == "Skipped")}");

if (emitJson || !string.IsNullOrWhiteSpace(jsonPath))
{
    var json = JsonSerializer.Serialize(report, new JsonSerializerOptions(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    });

    var effectiveJsonPath = jsonPath;
    if (string.IsNullOrWhiteSpace(effectiveJsonPath))
    {
        effectiveJsonPath = Path.Combine(
            contentRoot,
            "..",
            "..",
            "artifacts",
            "runlogs",
            $"ca-exclusions-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}",
            "summary.json");
    }

    var fullJsonPath = Path.GetFullPath(effectiveJsonPath);
    var directory = Path.GetDirectoryName(fullJsonPath);
    if (!string.IsNullOrWhiteSpace(directory))
    {
        Directory.CreateDirectory(directory);
    }

    await File.WriteAllTextAsync(fullJsonPath, json);
    Console.WriteLine($"JSON report: {fullJsonPath}");

    var markdownPath = Path.Combine(directory ?? Path.GetDirectoryName(fullJsonPath) ?? contentRoot, "summary.md");
    await File.WriteAllLinesAsync(markdownPath, BuildMarkdown(report));
    Console.WriteLine($"Markdown report: {markdownPath}");

    if (emitJson)
    {
        Console.WriteLine(json);
    }
}

if (results.Any(item => item.Result == "Failed"))
{
    throw new InvalidOperationException("One or more Conditional Access policies could not be updated.");
}

static HttpClientHandler CreateHttpHandler(bool useEnvironmentProxy) =>
    new()
    {
        UseProxy = useEnvironmentProxy,
        Proxy = useEnvironmentProxy ? WebRequest.DefaultWebProxy : null
    };

static async Task<ResolvedUser> ResolveUserAsync(
    HttpClient httpClient,
    string graphBaseUrl,
    string userPrincipalName)
{
    var requestUrl =
        $"{graphBaseUrl.TrimEnd('/')}/users/{Uri.EscapeDataString(userPrincipalName)}?$select=id,displayName,userPrincipalName,accountEnabled";
    using var response = await httpClient.GetAsync(requestUrl);
    var responseBody = await response.Content.ReadAsStringAsync();

    if (!response.IsSuccessStatusCode)
    {
        throw new InvalidOperationException(BuildGraphError("User lookup failed", response.StatusCode, responseBody));
    }

    using var document = JsonDocument.Parse(responseBody);
    var root = document.RootElement;
    var resolvedUserId = GetString(root, "id");

    if (string.IsNullOrWhiteSpace(resolvedUserId))
    {
        throw new InvalidOperationException($"Graph did not return an object ID for '{userPrincipalName}'.");
    }

    return new ResolvedUser(
        resolvedUserId,
        GetString(root, "displayName"),
        GetString(root, "userPrincipalName"));
}

static async Task<IReadOnlyList<ConditionalAccessPolicySnapshot>> GetConditionalAccessPoliciesAsync(
    HttpClient httpClient,
    string graphBaseUrl)
{
    var policies = new List<ConditionalAccessPolicySnapshot>();
    var nextRequestUrl = $"{graphBaseUrl.TrimEnd('/')}/identity/conditionalAccess/policies?$top=999";

    while (!string.IsNullOrWhiteSpace(nextRequestUrl))
    {
        using var response = await httpClient.GetAsync(nextRequestUrl);
        var responseBody = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(BuildGraphError("Conditional Access policy read failed", response.StatusCode, responseBody));
        }

        var payload = JsonNode.Parse(responseBody)?.AsObject()
            ?? throw new InvalidOperationException("Conditional Access policy read returned an empty response.");

        if (payload["value"] is JsonArray policiesArray)
        {
            foreach (var node in policiesArray)
            {
                if (node is not JsonObject policyObject)
                {
                    continue;
                }

                policies.Add(new ConditionalAccessPolicySnapshot(
                    policyObject["id"]?.GetValue<string>() ?? string.Empty,
                    policyObject["displayName"]?.GetValue<string>() ?? string.Empty,
                    policyObject["state"]?.GetValue<string>() ?? string.Empty,
                    policyObject["conditions"]?.DeepClone()));
            }
        }

        nextRequestUrl = payload["@odata.nextLink"]?.GetValue<string>();
    }

    return policies;
}

static async Task SendJsonAsync(
    HttpClient httpClient,
    string requestUrl,
    HttpMethod method,
    JsonNode body)
{
    using var request = new HttpRequestMessage(method, requestUrl)
    {
        Content = new StringContent(
            body.ToJsonString(new JsonSerializerOptions(JsonSerializerDefaults.Web)),
            Encoding.UTF8,
            "application/json")
    };

    using var response = await httpClient.SendAsync(request);
    var responseBody = await response.Content.ReadAsStringAsync();

    if (!response.IsSuccessStatusCode)
    {
        throw new InvalidOperationException(BuildGraphError("Conditional Access policy update failed", response.StatusCode, responseBody));
    }
}

static PolicySpread BuildSpread(IReadOnlyList<ConditionalAccessPolicySnapshot> policies) =>
    new(
        policies.Count,
        policies.Count(policy => string.Equals(policy.State, "enabled", StringComparison.OrdinalIgnoreCase)),
        policies.Count(policy => string.Equals(policy.State, "enabledForReportingButNotEnforced", StringComparison.OrdinalIgnoreCase)),
        policies.Count(policy => string.Equals(policy.State, "disabled", StringComparison.OrdinalIgnoreCase)));

static string[] BuildMarkdown(CaExclusionRunnerReport report)
{
    var lines = new List<string>
    {
        "# Conditional Access exclusion update",
        string.Empty,
        $"- Timestamp UTC: {report.CompletedUtc:O}",
        $"- Connection: {report.ConnectionDisplayName} ({report.ConnectionId})",
        $"- Tenant: {report.TenantId}",
        $"- Target user: {report.ResolvedUserPrincipalName} ({report.ResolvedUserId})",
        $"- Policies found: {report.PolicySpread.Total}",
        $"- Policies updated: {report.Results.Count(item => item.Result == "Updated")}",
        $"- Policies already excluding user: {report.Results.Count(item => item.Result == "AlreadyExcluded")}",
        $"- Policies failed: {report.Results.Count(item => item.Result == "Failed")}",
        $"- Policies skipped: {report.Results.Count(item => item.Result == "Skipped")}",
        string.Empty,
        "| Policy | State | Result | Reason |",
        "| --- | --- | --- | --- |"
    };

    foreach (var result in report.Results.OrderBy(item => item.PolicyName, StringComparer.OrdinalIgnoreCase))
    {
        lines.Add($"| {result.PolicyName.Replace("|", "\\|", StringComparison.Ordinal)} | {result.State} | {result.Result} | {result.Reason.Replace("|", "\\|", StringComparison.Ordinal)} |");
    }

    return lines.ToArray();
}

static string ResolveRequiredArgument(IReadOnlyList<string> args, string argumentName)
{
    var value = ResolveOptionalArgument(args, argumentName);
    if (!string.IsNullOrWhiteSpace(value))
    {
        return value;
    }

    throw new ArgumentException($"Missing required argument '{argumentName}'.");
}

static string? ResolveOptionalArgument(IReadOnlyList<string> args, string argumentName)
{
    for (var index = 0; index < args.Count; index++)
    {
        if (!string.Equals(args[index], argumentName, StringComparison.OrdinalIgnoreCase))
        {
            continue;
        }

        var valueIndex = index + 1;
        if (valueIndex < args.Count)
        {
            return args[valueIndex];
        }

        return null;
    }

    return null;
}

static bool HasFlag(IReadOnlyList<string> args, string flag) =>
    args.Any(argument => string.Equals(argument, flag, StringComparison.OrdinalIgnoreCase));

static string GetString(JsonElement element, string propertyName)
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

static string BuildGraphError(string prefix, HttpStatusCode statusCode, string responseBody)
{
    var normalized = NormalizeMessage(responseBody);
    return string.IsNullOrWhiteSpace(normalized)
        ? $"{prefix} with {(int)statusCode}."
        : $"{prefix} with {(int)statusCode}. {normalized}";
}

static string NormalizeMessage(string value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return string.Empty;
    }

    var normalized = value.Trim().ReplaceLineEndings(" ");
    return normalized.Length <= 320 ? normalized : normalized[..320];
}

internal sealed record ConditionalAccessPolicySnapshot(
    string Id,
    string DisplayName,
    string State,
    JsonNode? ConditionsNode);

internal sealed record PolicySpread(
    int Total,
    int Enabled,
    int ReportOnly,
    int Disabled);

internal sealed record PolicyUpdateResult(
    string PolicyId,
    string PolicyName,
    string State,
    string Result,
    string Reason,
    int? ExcludeUsersBefore,
    int? ExcludeUsersAfter);

internal sealed record ResolvedUser(
    string Id,
    string DisplayName,
    string UserPrincipalName);

internal sealed record CaExclusionRunnerReport(
    Guid ConnectionId,
    string ConnectionDisplayName,
    string TenantId,
    string ResolvedUserId,
    string ResolvedDisplayName,
    string ResolvedUserPrincipalName,
    PolicySpread PolicySpread,
    IReadOnlyList<PolicyUpdateResult> Results,
    DateTimeOffset CompletedUtc);

internal sealed class RunnerHostEnvironment : IHostEnvironment
{
    public RunnerHostEnvironment(string contentRootPath)
    {
        ContentRootPath = contentRootPath;
        ContentRootFileProvider = new PhysicalFileProvider(contentRootPath);
        ApplicationName = "Securityzator.CaExclusionRunner";
        EnvironmentName = Environments.Production;
    }

    public string EnvironmentName { get; set; }

    public string ApplicationName { get; set; }

    public string ContentRootPath { get; set; }

    public IFileProvider ContentRootFileProvider { get; set; }
}
