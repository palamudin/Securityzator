using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Securityzator.Web.Controllers;

[Authorize]
public class IntegrationController : Controller
{
    // Path to the AIMSP Python project — configurable via appsettings
    private static readonly string AimspRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        "..", "..", "usr", "local", "lib", "hermes-agent", "aimsp_review", "aimsp_extracted", "AIMSP");

    private static readonly string ChaosScript = "generators/m365_chaos.py";
    private static readonly string PythonExe = "python3";

    [HttpGet]
    public IActionResult Jira()
    {
        ViewBag.StatusMessage = TempData["StatusMessage"] as string;
        ViewBag.ErrorMessage = TempData["ErrorMessage"] as string;

        // Load portfolio companies for the dropdown
        ViewBag.Companies = GetPortfolioCompanies();

        // Load provisioned company state
        ViewBag.Provisioned = GetProvisionedCompanies();

        // Load recent events
        ViewBag.Events = GetRecentEvents();

        // Load Secure Score
        ViewBag.SecureScore = GetSecureScore();

        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult ProvisionCompany(string companyName, int userCount = 5)
    {
        if (string.IsNullOrWhiteSpace(companyName))
        {
            TempData["ErrorMessage"] = "Select a company to provision.";
            return RedirectToAction(nameof(Jira));
        }

        var result = RunPython(ChaosScript, "provision", "--company", companyName, "--users", userCount.ToString());

        if (result.ExitCode == 0)
        {
            TempData["StatusMessage"] = $"Provisioned '{companyName}' with {userCount} users. {result.StdOutSnippet}";
        }
        else
        {
            TempData["ErrorMessage"] = $"Provision failed for '{companyName}'. {result.StdErrSnippet}";
        }

        return RedirectToAction(nameof(Jira));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult ProvisionAll(int maxUsers = 5)
    {
        var result = RunPython(ChaosScript, "provision", "--all", "--users", maxUsers.ToString());

        if (result.ExitCode == 0)
        {
            TempData["StatusMessage"] = $"Bulk provision started. {result.StdOutSnippet}";
        }
        else
        {
            TempData["ErrorMessage"] = $"Bulk provision failed. {result.StdErrSnippet}";
        }

        return RedirectToAction(nameof(Jira));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult TriggerChaos(string companyName, string chaosType)
    {
        if (string.IsNullOrWhiteSpace(companyName))
        {
            TempData["ErrorMessage"] = "Select a company to trigger chaos on.";
            return RedirectToAction(nameof(Jira));
        }

        var result = RunPython(ChaosScript, "chaos", "--company", companyName, "--type", chaosType);

        if (result.ExitCode == 0)
        {
            TempData["StatusMessage"] = $"Chaos '{chaosType}' triggered on '{companyName}'. {result.StdOutSnippet}";
        }
        else
        {
            TempData["ErrorMessage"] = $"Chaos failed for '{companyName}'. {result.StdErrSnippet}";
        }

        return RedirectToAction(nameof(Jira));
    }

    // ── Helpers ────────────────────────────────────────────────────

    private static (int ExitCode, string StdOutSnippet, string StdErrSnippet) RunPython(params string[] args)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = PythonExe,
            WorkingDirectory = AimspRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        foreach (var arg in args)
        {
            startInfo.ArgumentList.Add(arg);
        }

        try
        {
            using var process = Process.Start(startInfo);
            if (process == null)
            {
                return (-1, "", "Could not start Python process.");
            }

            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit(TimeSpan.FromSeconds(60));

            return (
                process.ExitCode,
                Truncate(stdout),
                Truncate(stderr)
            );
        }
        catch (Exception ex)
        {
            return (-1, "", ex.Message);
        }
    }

    private static string Truncate(string text, int maxLen = 250)
    {
        if (string.IsNullOrWhiteSpace(text)) return "";
        var trimmed = text.Trim();
        return trimmed.Length <= maxLen ? trimmed : trimmed[..maxLen] + "...";
    }

    private List<string> GetPortfolioCompanies()
    {
        var result = RunPython("generators/portfolio_manager.py", "stats");
        // Parse stderr/stdout for company names — fall back to hardcoded list
        try
        {
            var portfolioPath = Path.Combine(AimspRoot, "data", "companies", "portfolio.json");
            if (System.IO.File.Exists(portfolioPath))
            {
                var json = System.IO.File.ReadAllText(portfolioPath);
                var doc = System.Text.Json.JsonDocument.Parse(json);
                var companies = new List<string>();
                foreach (var item in doc.RootElement.EnumerateArray())
                {
                    var status = item.GetProperty("status").GetString();
                    if (status == "Active")
                    {
                        companies.Add(item.GetProperty("company_name").GetString()!);
                    }
                }
                return companies.Take(30).ToList();
            }
        }
        catch { /* fall through to empty */ }

        return new List<string> { "(no portfolio loaded — run portfolio_manager.py generate first)" };
    }

    private List<Dictionary<string, object>> GetProvisionedCompanies()
    {
        try
        {
            var statePath = Path.Combine(AimspRoot, "data", "m365_state.json");
            if (System.IO.File.Exists(statePath))
            {
                var json = System.IO.File.ReadAllText(statePath);
                var doc = System.Text.Json.JsonDocument.Parse(json);
                var companies = new List<Dictionary<string, object>>();
                if (doc.RootElement.TryGetProperty("companies", out var comps))
                {
                    foreach (var prop in comps.EnumerateObject())
                    {
                        var c = prop.Value;
                        companies.Add(new Dictionary<string, object>
                        {
                            ["name"] = prop.Name,
                            ["users"] = c.TryGetProperty("user_count", out var uc) ? uc.GetInt32() : 0,
                            ["group"] = c.TryGetProperty("group_name", out var gn) ? gn.GetString()! : "-",
                            ["provisioned"] = c.TryGetProperty("provisioned_at", out var pa) ? pa.GetString()![..10] : "-",
                        });
                    }
                }
                return companies;
            }
        }
        catch { }

        return new List<Dictionary<string, object>>();
    }

    private List<Dictionary<string, object>> GetRecentEvents()
    {
        try
        {
            var statePath = Path.Combine(AimspRoot, "data", "m365_state.json");
            if (System.IO.File.Exists(statePath))
            {
                var json = System.IO.File.ReadAllText(statePath);
                var doc = System.Text.Json.JsonDocument.Parse(json);
                var events = new List<Dictionary<string, object>>();
                if (doc.RootElement.TryGetProperty("events", out var evts))
                {
                    foreach (var e in evts.EnumerateArray().Reverse().Take(15))
                    {
                        events.Add(new Dictionary<string, object>
                        {
                            ["time"] = e.TryGetProperty("timestamp", out var ts) ? ts.GetString()![..19] : "-",
                            ["event"] = e.TryGetProperty("event", out var ev) ? ev.GetString()! : "-",
                            ["company"] = e.TryGetProperty("company", out var co) ? co.GetString()! : "-",
                            ["detail"] = e.TryGetProperty("detail", out var dt) ? Truncate(dt.GetString()!, 80) : "-",
                        });
                    }
                }
                return events;
            }
        }
        catch { }

        return new List<Dictionary<string, object>>();
    }

    private Dictionary<string, object> GetSecureScore()
    {
        var result = RunPython(ChaosScript, "score");
        if (result.ExitCode == 0 && result.StdOutSnippet.Contains("Secure Score"))
        {
            return new Dictionary<string, object>
            {
                ["raw"] = result.StdOutSnippet,
                ["available"] = true,
            };
        }
        return new Dictionary<string, object> { ["available"] = false };
    }
}
