using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Net;
using Securityzator.Application.Accounts;
using Securityzator.Application.Blueprints;
using Securityzator.Application.Connections;
using Securityzator.Application.Jobs;
using Securityzator.Application.Recommendations;
using Securityzator.Application.Remediations;
using Securityzator.Application.Workers;
using Securityzator.Infrastructure.Accounts;
using Securityzator.Infrastructure.Blueprints;
using Securityzator.Infrastructure.Connections;
using Securityzator.Infrastructure.Graph;
using Securityzator.Infrastructure.Jobs;
using Securityzator.Infrastructure.Pathing;
using Securityzator.Infrastructure.Recommendations;
using Securityzator.Infrastructure.Remediations;
using Securityzator.Infrastructure.Security;
using Securityzator.Infrastructure.Storage;
using Securityzator.Infrastructure.Teams;
using Securityzator.Infrastructure.Workers;
using Securityzator.Infrastructure.Automation;
using Securityzator.Infrastructure.Exchange;
using Securityzator.Infrastructure.Intune;

namespace Securityzator.Infrastructure.DependencyInjection;

public static class InfrastructureServiceCollectionExtensions
{
    public static IServiceCollection AddSecurityzatorInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment hostEnvironment)
    {
        services.Configure<SecurityzatorStorageOptions>(configuration.GetSection("Securityzator:Storage"));
        services.Configure<SecurityzatorGraphOptions>(configuration.GetSection("Securityzator"));
        services.Configure<SecurityzatorDataProtectionOptions>(configuration.GetSection("Securityzator:DataProtection"));
        services.Configure<WorkerMonitorOptions>(configuration.GetSection("Securityzator:Worker"));

        var configuredKeyRingPath = configuration["Securityzator:DataProtection:KeyRingPath"];
        var keyRingPath = string.IsNullOrWhiteSpace(configuredKeyRingPath)
            ? Path.Combine(hostEnvironment.ContentRootPath, "App_Data", "keyring")
            : SecurityzatorPathResolver.ResolveDirectoryPath(
                configuredKeyRingPath,
                hostEnvironment.ContentRootPath);

        Directory.CreateDirectory(keyRingPath);

        services.AddDataProtection()
            .SetApplicationName("Securityzator")
            .PersistKeysToFileSystem(new DirectoryInfo(keyRingPath));
        services.AddHttpClient<GraphAccessTokenService>()
            .ConfigurePrimaryHttpMessageHandler(() => CreateGraphHttpMessageHandler(configuration));
        services.AddHttpClient<DirectoryGraphClient>()
            .ConfigurePrimaryHttpMessageHandler(() => CreateGraphHttpMessageHandler(configuration));
        services.AddHttpClient<ConditionalAccessGraphClient>()
            .ConfigurePrimaryHttpMessageHandler(() => CreateGraphHttpMessageHandler(configuration));
        services.AddHttpClient<SecureScoreGraphClient>()
            .ConfigurePrimaryHttpMessageHandler(() => CreateGraphHttpMessageHandler(configuration));
        services.AddHttpClient<IntuneManagementGraphClient>()
            .ConfigurePrimaryHttpMessageHandler(() => CreateGraphHttpMessageHandler(configuration));
        services.AddHttpClient<IntuneEndpointAutomationClient>()
            .ConfigurePrimaryHttpMessageHandler(() => CreateGraphHttpMessageHandler(configuration));

        services.AddSingleton<JsonFileSecurityzatorStateStore>();
        services.AddSingleton<WindowsPowerShellRunner>();
        services.AddSingleton<ClientSecretProtector>();
        services.AddSingleton<DefenderForOfficeAutomationClient>();
        services.AddSingleton<IntuneEndpointAutomationClient>();
        services.AddSingleton<TeamsMeetingPolicyAutomationClient>();
        services.AddSingleton<IProductBlueprintService, StaticProductBlueprintService>();
        services.AddSingleton<IOperatorAccountService, FileBackedOperatorAccountService>();
        services.AddSingleton<IAzureConnectionService, FileBackedAzureConnectionService>();
        services.AddSingleton<IRemediationJobService, FileBackedRemediationJobService>();
        services.AddSingleton<IRecommendationService, SecureScoreRecommendationService>();
        services.AddSingleton<IRemediationService, ConditionalAccessRemediationService>();
        services.AddSingleton<IWorkerMonitorService, FileBackedWorkerMonitorService>();

        return services;
    }

    private static HttpMessageHandler CreateGraphHttpMessageHandler(IConfiguration configuration)
    {
        var useEnvironmentProxy = configuration.GetValue<bool>("Securityzator:UseEnvironmentProxy");

        return new HttpClientHandler
        {
            UseProxy = useEnvironmentProxy,
            Proxy = useEnvironmentProxy ? WebRequest.DefaultWebProxy : null
        };
    }
}
