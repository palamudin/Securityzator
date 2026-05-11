using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Securityzator.Application.Jobs;
using Securityzator.Application.Remediations;
using Securityzator.Infrastructure.DependencyInjection;
using Securityzator.Infrastructure.Storage;

var templateKey = ResolveTemplateKey(args);
var launchMode = ResolveLaunchMode(args, templateKey);
var approvalJustification = ResolveApprovalJustification(args, templateKey);
var includeGroupId = ResolveOptionalArgument(args, "--includeGroupId") ?? string.Empty;
var excludeGroupId = ResolveOptionalArgument(args, "--excludeGroupId");
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
        services.AddSecurityzatorInfrastructure(context.Configuration, new SmokeHostEnvironment(contentRoot));
    })
    .Build();

var stateStore = host.Services.GetRequiredService<JsonFileSecurityzatorStateStore>();
var jobService = host.Services.GetRequiredService<IRemediationJobService>();
var remediationService = host.Services.GetRequiredService<IRemediationService>();

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
    throw new InvalidOperationException("No saved Azure connection was found for the smoke run.");
}

var job = await jobService.EnqueueQueueableTemplateAsync(
    new EnqueueQueueableTemplateJobRequest(
        connection.Id,
        connection.OwnerOperatorId,
        connection.OwnerOperatorId,
        "Securityzator Smoke Runner",
        approvalJustification,
        launchMode,
        templateKey,
        includeGroupId,
        excludeGroupId));

Console.WriteLine($"Queued job {job.Id} for {job.ConnectionDisplayName}.");

var outcome = await remediationService.ExecuteQueueableTemplateAsync(
    new QueueableRemediationTemplateRequest(
        job.ConnectionId,
        job.OwnerOperatorId,
        job.OwnerOperatorId,
        job.RequestedByOperatorName,
        job.ApprovalJustification,
        job.LaunchMode,
        job.TemplateKey,
        job.IncludeGroupId ?? string.Empty,
        job.ExcludeGroupId,
        job.AllUsersAssignment));

if (outcome.Succeeded)
{
    await jobService.MarkSucceededAsync(
        job.Id,
        outcome.RunId,
        outcome.Message,
        outcome.PolicyId,
        outcome.PolicyState);
}
else
{
    await jobService.MarkFailedAsync(job.Id, outcome.Message);
}

var report = await stateStore.ReadAsync(state =>
{
    var storedJob = state.RemediationJobs.FirstOrDefault(item => item.Id == job.Id);
    var storedRun = state.RemediationRuns.FirstOrDefault(item => item.Id == outcome.RunId);

    return new SmokeRunnerReport(
        templateKey,
        storedJob?.TemplateName ?? ResolveTemplateName(templateKey),
        connection.Id,
        connection.DisplayName,
        launchMode.ToString(),
        job.Id,
        outcome.RunId,
        outcome.Status.ToString(),
        outcome.Succeeded,
        outcome.AlreadyExists,
        outcome.Message,
        outcome.CompletedUtc,
        outcome.PolicyId,
        outcome.PolicyState,
        includeGroupId,
        excludeGroupId,
        storedJob is null
            ? null
            : new SmokeRunnerJobSnapshot(
                storedJob.Status.ToString(),
                storedJob.AttemptCount,
                storedJob.MaxAttempts,
                storedJob.NextAttemptUtc,
                storedJob.LastError,
                storedJob.Logs.ToArray()),
        storedRun is null
            ? null
            : new SmokeRunnerRunSnapshot(
                storedRun.Status.ToString(),
                storedRun.Summary,
                storedRun.StartedUtc,
                storedRun.CompletedUtc,
                storedRun.PolicyId,
                storedRun.PolicyState,
                storedRun.Logs.ToArray()));
});

Console.WriteLine($"Outcome: {outcome.Status}");
Console.WriteLine($"Message: {outcome.Message}");
Console.WriteLine($"Launch mode: {launchMode}");
Console.WriteLine($"Policy/Target: {outcome.PolicyId ?? "(none)"}");
Console.WriteLine($"State: {outcome.PolicyState ?? "(none)"}");

if (emitJson || !string.IsNullOrWhiteSpace(jsonPath))
{
    var json = JsonSerializer.Serialize(report, new JsonSerializerOptions(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    });

    if (!string.IsNullOrWhiteSpace(jsonPath))
    {
        var fullJsonPath = Path.GetFullPath(jsonPath);
        var directory = Path.GetDirectoryName(fullJsonPath);

        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.WriteAllTextAsync(fullJsonPath, json);
        Console.WriteLine($"JSON report: {fullJsonPath}");
    }

    if (emitJson)
    {
        Console.WriteLine(json);
    }
}

static string ResolveTemplateKey(IReadOnlyList<string> args)
{
    var namedTemplateKey = ResolveOptionalArgument(args, "--templateKey");
    if (!string.IsNullOrWhiteSpace(namedTemplateKey))
    {
        return namedTemplateKey;
    }

    if (args.Count == 0)
    {
        return "teams-meeting-hardening";
    }

    return args[0].Trim();
}

static string ResolveApprovalJustification(IReadOnlyList<string> args, string templateKey)
{
    var explicitJustification = ResolveOptionalArgument(args, "--approvalJustification");
    if (!string.IsNullOrWhiteSpace(explicitJustification))
    {
        return explicitJustification;
    }

    return templateKey switch
    {
        "mdo-anti-malware-baseline" => "Live smoke test for the Defender for Office anti-malware baseline from the local worker harness.",
        "mdo-safe-links-and-attachments" => "Live smoke test for the Defender for Office Safe Links and attachments baseline from the local worker harness.",
        "mdo-spam-and-forwarding-baseline" => "Live smoke test for the Defender for Office spam and forwarding baseline from the local worker harness.",
        "exchange-online-collaboration-and-mailbox" => "Live smoke test for the Exchange Online collaboration and mailbox hardening baseline from the local worker harness.",
        "teams-meeting-hardening" => "Live smoke test for Teams meeting hardening baseline from the local worker harness.",
        "entra-identity-hygiene-baseline" => "Live smoke test for the Entra admin and consent hygiene assessment from the local worker harness.",
        "entra-daily-use-hardening" => "Live smoke test for the Entra daily-use consent and password hardening baseline from the local worker harness.",
        "entra-low-impact-app-consent" => "Live smoke test for the Entra low-impact app consent baseline from the local worker harness.",
        "defender-endpoint-bitlocker-baseline" => "Live smoke test for the Intune-backed Defender BitLocker startup baseline from the local worker harness.",
        "defender-endpoint-browser-and-adobe-policy-surface-readiness" => "Live smoke test for the Intune-backed Defender browser and Adobe policy-surface readiness assessment from the local worker harness.",
        "defender-endpoint-browser-hardening" => "Live smoke test for the Intune-backed Defender browser hardening baseline from the local worker harness.",
        "defender-endpoint-credential-and-elevation-hardening" => "Live smoke test for the Intune-backed Defender credential and elevation hardening baseline from the local worker harness.",
        "defender-endpoint-remote-access-and-network-hardening" => "Live smoke test for the Intune-backed Defender remote access and network hardening baseline from the local worker harness.",
        "defender-endpoint-core-protection" => "Live smoke test for the Intune-backed Defender for Endpoint core protection baseline from the local worker harness.",
        "defender-endpoint-exploit-protection" => "Live smoke test for the Intune-backed Defender exploit protection baseline from the local worker harness.",
        "defender-endpoint-firewall-and-smartscreen" => "Live smoke test for the Intune-backed Defender Firewall and SmartScreen baseline from the local worker harness.",
        "defender-endpoint-sensor-and-agent-health" => "Live smoke test for the Intune-backed Defender for Endpoint onboarding, sensor, and agent health assessment from the local worker harness.",
        "defender-endpoint-os-security-baseline" => "Live smoke test for the Intune-backed Defender for Endpoint OS security baseline from the local worker harness.",
        "defender-endpoint-attack-surface-reduction" => "Live smoke test for the Intune-backed Defender for Endpoint attack surface reduction baseline from the local worker harness.",
        _ => $"Live smoke test for '{templateKey}' from the local worker harness."
    };
}

static RemediationLaunchMode ResolveLaunchMode(IReadOnlyList<string> args, string templateKey)
{
    var explicitLaunchMode = ResolveOptionalArgument(args, "--launchMode");
    if (!string.IsNullOrWhiteSpace(explicitLaunchMode))
    {
        if (Enum.TryParse<RemediationLaunchMode>(explicitLaunchMode, ignoreCase: true, out var parsedLaunchMode))
        {
            return parsedLaunchMode;
        }

        throw new ArgumentOutOfRangeException(
            nameof(args),
            explicitLaunchMode,
            "Launch mode must be ReportOnly, Enabled, or DirectApply.");
    }

    return templateKey switch
    {
        "mdo-anti-malware-baseline" => RemediationLaunchMode.DirectApply,
        "mdo-anti-phishing-and-impersonation" => RemediationLaunchMode.DirectApply,
        "mdo-safe-links-and-attachments" => RemediationLaunchMode.DirectApply,
        "mdo-spam-and-forwarding-baseline" => RemediationLaunchMode.DirectApply,
        "exchange-online-collaboration-and-mailbox" => RemediationLaunchMode.DirectApply,
        "teams-meeting-hardening" => RemediationLaunchMode.DirectApply,
        "entra-daily-use-hardening" => RemediationLaunchMode.DirectApply,
        "entra-low-impact-app-consent" => RemediationLaunchMode.DirectApply,
        "defender-endpoint-bitlocker-baseline" => RemediationLaunchMode.DirectApply,
        "defender-endpoint-browser-hardening" => RemediationLaunchMode.DirectApply,
        "defender-endpoint-credential-and-elevation-hardening" => RemediationLaunchMode.DirectApply,
        "defender-endpoint-remote-access-and-network-hardening" => RemediationLaunchMode.DirectApply,
        "defender-endpoint-core-protection" => RemediationLaunchMode.DirectApply,
        "defender-endpoint-exploit-protection" => RemediationLaunchMode.DirectApply,
        "defender-endpoint-firewall-and-smartscreen" => RemediationLaunchMode.DirectApply,
        "defender-endpoint-os-security-baseline" => RemediationLaunchMode.DirectApply,
        "defender-endpoint-attack-surface-reduction" => RemediationLaunchMode.DirectApply,
        _ => RemediationLaunchMode.ReportOnly
    };
}

static string? ResolveOptionalArgument(IReadOnlyList<string> args, string argumentName)
{
    for (var index = 0; index < args.Count - 1; index++)
    {
        if (string.Equals(args[index], argumentName, StringComparison.OrdinalIgnoreCase))
        {
            var value = args[index + 1].Trim();
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }
    }

    return null;
}

static bool HasFlag(IReadOnlyList<string> args, string flagName)
{
    return args.Any(argument => string.Equals(argument, flagName, StringComparison.OrdinalIgnoreCase));
}

static string ResolveTemplateName(string templateKey)
{
    return templateKey.Trim() switch
    {
        "block-legacy-auth" => "Block legacy authentication",
        "require-mfa-admins" => "Require MFA for privileged admins",
        "mfa-all-users" => "Require MFA for all users",
        "entra-risk-policies" => "Enable Entra risk policies",
        "entra-identity-hygiene-baseline" => "Entra admin and consent hygiene",
        "entra-daily-use-hardening" => "Entra daily-use consent and password hardening",
        "entra-low-impact-app-consent" => "Entra low-impact app consent",
        "require-mfa-guest-access" => "Require MFA for guest access",
        "require-mfa-admin-portals" => "Require MFA for Microsoft admin portals",
        "require-mfa-azure-management" => "Require MFA for Azure management",
        "secure-security-info-registration" => "Secure security info registration",
        "require-mfa-risky-sign-ins" => "Require MFA when risky sign-ins are detected",
        "require-password-change-high-risk-users" => "Require password change for high-risk users",
        "require-phishing-resistant-mfa-admins" => "Require phishing-resistant MFA for privileged admins",
        "mdo-anti-phishing-and-impersonation" => "Defender for Office anti-phishing and impersonation",
        "mdo-anti-malware-baseline" => "Defender for Office anti-malware hardening",
        "mdo-safe-links-and-attachments" => "Defender for Office Safe Links and attachments",
        "mdo-spam-and-forwarding-baseline" => "Defender for Office spam and forwarding hardening",
        "exchange-online-collaboration-and-mailbox" => "Exchange Online collaboration and mailbox hardening",
        "teams-meeting-hardening" => "Teams meeting hardening baseline",
        "defender-endpoint-bitlocker-baseline" => "Defender BitLocker startup baseline",
        "defender-endpoint-browser-and-adobe-policy-surface-readiness" => "Defender browser and Adobe policy-surface readiness",
        "defender-endpoint-browser-hardening" => "Defender browser hardening baseline",
        "defender-endpoint-credential-and-elevation-hardening" => "Defender credential and elevation hardening",
        "defender-endpoint-remote-access-and-network-hardening" => "Defender remote access and network hardening",
        "defender-endpoint-core-protection" => "Defender for Endpoint core protection baseline",
        "defender-endpoint-exploit-protection" => "Defender exploit protection baseline",
        "defender-endpoint-firewall-and-smartscreen" => "Defender Firewall and SmartScreen baseline",
        "defender-endpoint-sensor-and-agent-health" => "Defender for Endpoint sensor and agent health",
        "defender-endpoint-os-security-baseline" => "Endpoint OS and platform security baseline",
        "defender-endpoint-attack-surface-reduction" => "Defender for Endpoint attack surface reduction",
        _ => templateKey.Trim()
    };
}

internal sealed class SmokeHostEnvironment : IHostEnvironment
{
    public SmokeHostEnvironment(string contentRootPath)
    {
        ApplicationName = "Securityzator.SmokeRunner";
        EnvironmentName = Environments.Development;
        ContentRootPath = contentRootPath;
        ContentRootFileProvider = new PhysicalFileProvider(contentRootPath);
    }

    public string EnvironmentName { get; set; }

    public string ApplicationName { get; set; }

    public string ContentRootPath { get; set; }

    public IFileProvider ContentRootFileProvider { get; set; }
}

internal sealed record SmokeRunnerReport(
    string TemplateKey,
    string TemplateName,
    Guid ConnectionId,
    string ConnectionDisplayName,
    string LaunchMode,
    Guid JobId,
    Guid RunId,
    string OutcomeStatus,
    bool Succeeded,
    bool AlreadyExists,
    string Message,
    DateTimeOffset CompletedUtc,
    string? PolicyId,
    string? PolicyState,
    string IncludeGroupId,
    string? ExcludeGroupId,
    SmokeRunnerJobSnapshot? Job,
    SmokeRunnerRunSnapshot? Run);

internal sealed record SmokeRunnerJobSnapshot(
    string Status,
    int AttemptCount,
    int MaxAttempts,
    DateTimeOffset? NextAttemptUtc,
    string? LastError,
    IReadOnlyList<string> Logs);

internal sealed record SmokeRunnerRunSnapshot(
    string Status,
    string Summary,
    DateTimeOffset StartedUtc,
    DateTimeOffset CompletedUtc,
    string? PolicyId,
    string? PolicyState,
    IReadOnlyList<string> Logs);
