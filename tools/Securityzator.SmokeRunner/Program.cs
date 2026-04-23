using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.FileProviders;
using Securityzator.Application.Jobs;
using Securityzator.Application.Remediations;
using Securityzator.Infrastructure.DependencyInjection;
using Securityzator.Infrastructure.Storage;

var templateKey = ResolveTemplateKey(args);
var launchMode = ResolveLaunchMode(templateKey);
var approvalJustification = ResolveApprovalJustification(templateKey);
var includeGroupId = ResolveOptionalArgument(args, "--includeGroupId") ?? string.Empty;
var excludeGroupId = ResolveOptionalArgument(args, "--excludeGroupId");
var selectedConnectionId = ResolveOptionalArgument(args, "--connectionId");

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
        job.ExcludeGroupId));

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

Console.WriteLine($"Outcome: {outcome.Status}");
Console.WriteLine($"Message: {outcome.Message}");
Console.WriteLine($"Launch mode: {launchMode}");
Console.WriteLine($"Policy/Target: {outcome.PolicyId ?? "(none)"}");
Console.WriteLine($"State: {outcome.PolicyState ?? "(none)"}");

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

static string ResolveApprovalJustification(string templateKey)
{
    return templateKey switch
    {
        "mdo-safe-links-and-attachments" => "Live smoke test for the Defender for Office Safe Links and attachments baseline from the local worker harness.",
        "mdo-spam-and-forwarding-baseline" => "Live smoke test for the Defender for Office spam and forwarding baseline from the local worker harness.",
        "teams-meeting-hardening" => "Live smoke test for Teams meeting hardening baseline from the local worker harness.",
        "entra-identity-hygiene-baseline" => "Live smoke test for the Entra admin and consent hygiene assessment from the local worker harness.",
        "entra-daily-use-hardening" => "Live smoke test for the Entra daily-use consent and password hardening baseline from the local worker harness.",
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

static RemediationLaunchMode ResolveLaunchMode(string templateKey)
{
    return templateKey switch
    {
        "mdo-safe-links-and-attachments" => RemediationLaunchMode.DirectApply,
        "mdo-spam-and-forwarding-baseline" => RemediationLaunchMode.DirectApply,
        "teams-meeting-hardening" => RemediationLaunchMode.DirectApply,
        "entra-daily-use-hardening" => RemediationLaunchMode.DirectApply,
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
