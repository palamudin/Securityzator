using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Securityzator.Infrastructure.DependencyInjection;
using Securityzator.Worker;

IHost host = Host.CreateDefaultBuilder(args)
    .UseWindowsService(options =>
    {
        options.ServiceName = "Securityzator.Worker";
    })
    .ConfigureServices((context, services) =>
    {
        services.AddSecurityzatorInfrastructure(context.Configuration, context.HostingEnvironment);
        services.Configure<WorkerOptions>(context.Configuration.GetSection("Securityzator:Worker"));
        services.AddHostedService<Worker>();
    })
    .Build();

await host.RunAsync();
