using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Securityzator.Web.Controllers;

[Authorize]
public class ReportingController : Controller
{
    private static readonly HttpClient _jiraClient = new();
    private static readonly string _jiraRestApi;
    private static readonly string _jiraAuthHeader;
    private static List<Dictionary<string, object?>>? _cachedCwm;
    private static List<Dictionary<string, object?>>? _cachedJira;
    private static DateTime _cacheExpiry = DateTime.MinValue;
    private static readonly SemaphoreSlim _cacheLock = new(1, 1);

    static ReportingController()
    {
        _jiraRestApi = "https://ai-msp.atlassian.net/rest/api/3";

        // Read JIRA auth from AIMSP Auth.txt (same auth as the rest of the stack)
        var aimspAuthPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "..", "..", "usr", "local", "lib", "hermes-agent",
            "aimsp_review", "aimsp_extracted", "AIMSP", "Auth", "Auth.txt");

        string? email = null;
        string? token = null;

        if (System.IO.File.Exists(aimspAuthPath))
        {
            var lines = System.IO.File.ReadAllLines(aimspAuthPath);
            foreach (var line in lines)
            {
                if (line.StartsWith("Atlassianapi:", StringComparison.OrdinalIgnoreCase))
                    token = line.Split(':', 2)[1].Trim();
                if (line.Contains("@") && !line.Contains("serviceaccount") && !line.Contains(":"))
                    email = line.Trim();
            }
        }

        email ??= "jakovposao@gmail.com";
        token ??= ""; 

        _jiraAuthHeader = "Basic " + Convert.ToBase64String(
            Encoding.UTF8.GetBytes($"{email}:{token}"));
    }

    // ── Reporter page ────────────────────────────────────────────

    [HttpGet]
    public IActionResult Index()
    {
        return Redirect("/reporter/index.html");
    }

    // ── Data API ─────────────────────────────────────────────────

    [HttpGet("reporting/data")]
    [AllowAnonymous]
    public async Task<IActionResult> GetData(
        [FromQuery] string? source = null,
        CancellationToken cancellationToken = default)
    {
        // source=cwm (default) → ConnectWise format via JIRA mapper
        // source=jira → JIRA-native format
        // source=auto → try JIRA first, fall back to CWM
        var useSource = (source ?? "cwm").ToLowerInvariant();

        try
        {
            var cached = useSource == "jira" ? _cachedJira : _cachedCwm;
            if (cached != null && DateTime.UtcNow < _cacheExpiry)
                return new JsonResult(cached, new JsonSerializerOptions(JsonSerializerDefaults.Web));

            await _cacheLock.WaitAsync(cancellationToken);
            try
            {
                cached = useSource == "jira" ? _cachedJira : _cachedCwm;
                if (cached != null && DateTime.UtcNow < _cacheExpiry)
                    return new JsonResult(cached, new JsonSerializerOptions(JsonSerializerDefaults.Web));

                var tickets = await FetchAllJiraTicketsAsync(cancellationToken);
                
                var result = useSource switch
                {
                    "jira" => tickets.Select(MapJiraToNative).ToList(),
                    _ => tickets.Select(MapJiraToCw).ToList()
                };
                
                if (useSource == "jira") _cachedJira = result;
                else _cachedCwm = result;
                _cacheExpiry = DateTime.UtcNow.AddSeconds(5);  // Short TTL — client caches instead
                
                return new JsonResult(result, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            }
            finally { _cacheLock.Release(); }
        }
        catch (Exception ex)
        {
            var stale = useSource == "jira" ? _cachedJira : _cachedCwm;
            if (stale != null)
                return new JsonResult(stale, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            return new JsonResult(new { error = ex.Message }) { StatusCode = 500 };
        }
    }

    // ── Audit Trail API ───────────────────────────────────────────

    [HttpGet("reporting/audit")]
    [AllowAnonymous]
    public IActionResult GetAudit(
        [FromQuery] string? action = "stats",
        [FromQuery] int? id = null,
        [FromQuery] string? type = null)
    {
        try
        {
            var fakerRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "..", "..", "usr", "local", "lib", "hermes-agent",
                "aimsp_review", "aimsp_extracted", "m365_faker");

            var args = new List<string> { "audit_trail.py", action ?? "stats" };
            if (id.HasValue) { args.Add("--id"); args.Add(id.Value.ToString()); }
            if (!string.IsNullOrEmpty(type)) { args.Add("--type"); args.Add(type); }

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "python3",
                WorkingDirectory = fakerRoot,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var proc = System.Diagnostics.Process.Start(psi)!;
            var stdout = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            if (proc.ExitCode != 0)
                return new JsonResult(new { error = "Audit query failed", exitCode = proc.ExitCode })
                    { StatusCode = 500 };

            return Content(stdout, "application/json", Encoding.UTF8);
        }
        catch (Exception ex)
        {
            return new JsonResult(new { error = ex.Message }) { StatusCode = 500 };
        }
    }

    // ── JIRA Fetch ───────────────────────────────────────────────

    private async Task<List<JsonElement>> FetchAllJiraTicketsAsync(CancellationToken ct)
    {
        var allIssues = new List<JsonElement>();
        string? nextToken = null;

        _jiraClient.DefaultRequestHeaders.Clear();
        _jiraClient.DefaultRequestHeaders.Add("Authorization", _jiraAuthHeader);
        _jiraClient.DefaultRequestHeaders.Add("Accept", "application/json");

        while (allIssues.Count < 500)  // Fetch up to 500 tickets from JIRA
        {
            var payload = new Dictionary<string, object>
            {
                ["jql"] = "project = MSP ORDER BY created DESC",
                ["maxResults"] = Math.Min(500 - allIssues.Count, 100)
            };
            if (nextToken != null)
                payload["nextPageToken"] = nextToken;

            var json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _jiraClient.PostAsync(
                $"{_jiraRestApi}/search/jql", content, ct);

            if (!response.IsSuccessStatusCode) break;

            var body = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (!root.TryGetProperty("issues", out var issuesRefs)) break;

            foreach (var issueRef in issuesRefs.EnumerateArray())
            {
                var issueId = issueRef.GetProperty("id").GetString()!;
                var detailResponse = await _jiraClient.GetAsync(
                    $"{_jiraRestApi}/issue/{issueId}", ct);
                if (detailResponse.IsSuccessStatusCode)
                {
                    var detailBody = await detailResponse.Content.ReadAsStringAsync(ct);
                    using var detailDoc = JsonDocument.Parse(detailBody);
                    allIssues.Add(detailDoc.RootElement.Clone());
                }
                if (allIssues.Count >= 200) break;
            }

            if (root.TryGetProperty("nextPageToken", out var nt))
                nextToken = nt.GetString();
            else break;

            if (root.TryGetProperty("isLast", out var isLast) && isLast.GetBoolean())
                break;
        }

        return allIssues;
    }

    // ── JIRA → ConnectWise Mapper ────────────────────────────────

    private static Dictionary<string, object?> MapJiraToCw(JsonElement issue)
    {
        var fields = issue.GetProperty("fields");
        var key = issue.GetProperty("key").GetString()!;
        
        var statusName = SafeNestedString(fields, "status", "name") ?? "Open";
        var assigneeName = SafeNestedString(fields, "assignee", "displayName") ?? "Unassigned";
        var priorityName = SafeNestedString(fields, "priority", "name") ?? "Medium";
        var companyName = SafeCustomField(fields, "Company Name");
        if (string.IsNullOrWhiteSpace(companyName)) companyName = "Strong MSP";
        var issueType = SafeNestedString(fields, "issuetype", "name") ?? "Task";
        var reporterName = SafeNestedString(fields, "reporter", "displayName") ?? assigneeName;
        var created = SafeString(fields, "created") ?? DateTime.UtcNow.ToString("o");
        var updated = SafeString(fields, "updated") ?? created;
        var resolved = SafeString(fields, "resolutiondate");
        if (string.IsNullOrWhiteSpace(resolved) && IsClosedStatus(statusName))
            resolved = updated;  // Fallback: use last-updated when resolutiondate is null

        return new Dictionary<string, object?>
        {
            ["id"] = key,
            ["summary"] = SafeString(fields, "summary") ?? key,
            ["recordType"] = "ServiceTicket",
            ["board"] = new Dictionary<string, object> { ["id"] = 1, ["name"] = "MSP Service Desk" },
            ["status"] = new Dictionary<string, object> { ["id"] = 1, ["name"] = statusName },
            ["company"] = new Dictionary<string, object>
            {
                ["id"] = 1,
                ["identifier"] = companyName.Replace(" ", "").ToUpper()[..Math.Min(companyName.Length, 8)],
                ["name"] = companyName
            },
            ["contact"] = new Dictionary<string, object>
            {
                ["name"] = reporterName,
                ["email"] = NullIfEmpty(SafeCustomField(fields, "User Contact Email")) ?? $"{reporterName.Replace(" ",".").ToLower()}@msp.local"
            },
            ["team"] = new Dictionary<string, object> { ["name"] = assigneeName },
            ["owner"] = new Dictionary<string, object> { ["name"] = assigneeName },
            ["priority"] = new Dictionary<string, object>
            {
                ["name"] = priorityName,
                ["level"] = MapPriorityLevel(priorityName)
            },
            ["type"] = new Dictionary<string, object> { ["name"] = issueType },
            ["subType"] = new Dictionary<string, object> { ["name"] = NullIfEmpty(SafeSubtype(fields)) ?? issueType },
            ["item"] = new Dictionary<string, object> { ["name"] = key },
            ["dateEntered"] = created,
            ["lastUpdated"] = updated,
            ["closedDate"] = resolved,
            ["closedFlag"] = IsClosedStatus(statusName),
            ["slaStatus"] = MapSla(fields, statusName)
        };
    }

    // ── JIRA-Native format (for source=jira) ─────────────────────

    private static Dictionary<string, object?> MapJiraToNative(JsonElement issue)
    {
        var fields = issue.GetProperty("fields");
        var key = issue.GetProperty("key").GetString()!;
        var statusName = SafeNestedString(fields, "status", "name") ?? "Open";
        var assigneeName = SafeNestedString(fields, "assignee", "displayName") ?? "Unassigned";
        var companyName = NullIfEmpty(SafeCustomField(fields, "Company Name")) ?? "Strong MSP";

        // JIRA-native uses nested objects for template compatibility (same .name pattern as CW)
        return new Dictionary<string, object?>
        {
            ["id"] = key,
            ["summary"] = SafeString(fields, "summary") ?? key,
            ["recordType"] = "ServiceTicket",
            ["board"] = new Dictionary<string, object> { ["id"] = 1, ["name"] = "MSP Service Desk" },
            ["status"] = new Dictionary<string, object> { ["id"] = 1, ["name"] = statusName },
            ["company"] = new Dictionary<string, object> { ["id"] = 1, ["name"] = companyName },
            ["contact"] = new Dictionary<string, object> { ["name"] = SafeNestedString(fields, "reporter", "displayName") ?? assigneeName },
            ["team"] = new Dictionary<string, object> { ["name"] = assigneeName },
            ["owner"] = new Dictionary<string, object> { ["name"] = assigneeName },
            ["priority"] = new Dictionary<string, object>
            {
                ["name"] = SafeNestedString(fields, "priority", "name") ?? "Medium",
                ["level"] = MapPriorityLevel(SafeNestedString(fields, "priority", "name") ?? "Medium")
            },
            ["type"] = new Dictionary<string, object> { ["name"] = SafeNestedString(fields, "issuetype", "name") ?? "Task" },
            ["subType"] = new Dictionary<string, object> { ["name"] = NullIfEmpty(SafeSubtype(fields)) ?? SafeNestedString(fields, "issuetype", "name") ?? "Task" },
            ["item"] = new Dictionary<string, object> { ["name"] = key },
            ["dateEntered"] = SafeString(fields, "created") ?? DateTime.UtcNow.ToString("o"),
            ["lastUpdated"] = SafeString(fields, "updated") ?? DateTime.UtcNow.ToString("o"),
            ["closedDate"] = SafeString(fields, "resolutiondate") ?? (IsClosedStatus(statusName) ? SafeString(fields, "updated") : null),
            ["closedFlag"] = IsClosedStatus(statusName),
            ["slaStatus"] = MapSla(fields, statusName),
            // Extra JIRA-native fields for power users
            ["jiraKey"] = key,
            ["issueType"] = SafeNestedString(fields, "issuetype", "name"),
            ["sla"] = NullIfEmpty(SafeCustomField(fields, "SLA Tier")) ?? "Silver",
            ["service"] = NullIfEmpty(SafeCustomField(fields, "M365 Service")) ?? "General",
        };
    }

    // ── Field Helpers ────────────────────────────────────────────

    private static readonly Dictionary<string, string> CustomFieldMap = new()
    {
        ["Company Name"] = "customfield_10039",
        ["Issue Subtype"] = "customfield_10043",
        ["SLA Tier"] = "customfield_10042",
        ["Source"] = "customfield_10047",
        ["Client Industry"] = "customfield_10048",
        ["User Contact Email"] = "customfield_10049",
        ["M365 Service"] = "customfield_10051"
    };

    private static string? SafeString(JsonElement el, string prop)
        => el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static string? SafeNestedString(JsonElement el, string outer, string inner)
        => el.TryGetProperty(outer, out var v) && v.ValueKind == JsonValueKind.Object &&
           v.TryGetProperty(inner, out var iv) && iv.ValueKind == JsonValueKind.String
           ? iv.GetString() : null;

    private static string SafeCustomField(JsonElement fields, string fieldName)
    {
        if (CustomFieldMap.TryGetValue(fieldName, out var cfId) && fields.TryGetProperty(cfId, out var cf))
        {
            if (cf.ValueKind == JsonValueKind.String) return cf.GetString()!;
            if (cf.ValueKind == JsonValueKind.Object && cf.TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.String)
                return v.GetString()!;
        }
        return "";
    }

    private static string SafeSubtype(JsonElement fields)
    {
        var raw = SafeCustomField(fields, "Issue Subtype");
        return raw.Contains("] ") ? raw.Split("] ", 2)[1] : raw;
    }

    private static string MapPriorityLevel(string? name) => name switch
    {
        "Highest" => "Critical",
        "High" => "High",
        "Medium" => "Medium",
        "Low" => "Low",
        "Lowest" => "Planning",
        _ => "Medium"
    };

    private static bool IsClosedStatus(string? name)
        => name is not null && (
            name.Equals("Closed", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Resolved", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Done", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Cancelled", StringComparison.OrdinalIgnoreCase));

    private static string MapSla(JsonElement fields, string statusName)
    {
        if (IsClosedStatus(statusName)) return "Met";
        var sla = SafeCustomField(fields, "SLA Tier");
        return sla switch { "Platinum" or "Gold" => "Watching", "Bronze" or "Best Effort" => "Approaching", _ => "Watching" };
    }

    private static string? NullIfEmpty(string value)
        => string.IsNullOrWhiteSpace(value) ? null : value;
}
