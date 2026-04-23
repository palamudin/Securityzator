using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Securityzator.Infrastructure.Security;
using Securityzator.Infrastructure.Storage;

namespace Securityzator.Infrastructure.Health;

public sealed class StorageAndProtectionHealthCheck : IHealthCheck
{
    private readonly SecurityzatorStorageOptions _storageOptions;
    private readonly SecurityzatorDataProtectionOptions _dataProtectionOptions;
    private readonly IHostEnvironment _hostEnvironment;

    public StorageAndProtectionHealthCheck(
        IOptions<SecurityzatorStorageOptions> storageOptions,
        IOptions<SecurityzatorDataProtectionOptions> dataProtectionOptions,
        IHostEnvironment hostEnvironment)
    {
        _storageOptions = storageOptions.Value;
        _dataProtectionOptions = dataProtectionOptions.Value;
        _hostEnvironment = hostEnvironment;
    }

    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var stateFilePath = ResolvePath(_storageOptions.DataFilePath, "App_Data/securityzator-state.json");
            var keyRingPath = ResolvePath(_dataProtectionOptions.KeyRingPath, "App_Data/keyring");

            var stateDirectory = Path.GetDirectoryName(stateFilePath);
            if (string.IsNullOrWhiteSpace(stateDirectory))
            {
                return Task.FromResult(HealthCheckResult.Unhealthy("The state file path does not resolve to a valid directory."));
            }

            Directory.CreateDirectory(stateDirectory);
            Directory.CreateDirectory(keyRingPath);

            var data = new Dictionary<string, object>
            {
                ["stateFilePath"] = stateFilePath,
                ["keyRingPath"] = keyRingPath,
                ["stateFileExists"] = File.Exists(stateFilePath)
            };

            return Task.FromResult(HealthCheckResult.Healthy("State and key ring paths are available.", data));
        }
        catch (Exception ex)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("State or key ring paths are not available.", ex));
        }
    }

    private string ResolvePath(string? configuredPath, string fallback)
    {
        var value = string.IsNullOrWhiteSpace(configuredPath) ? fallback : configuredPath.Trim();
        return Path.IsPathRooted(value)
            ? value
            : Path.Combine(_hostEnvironment.ContentRootPath, value);
    }
}
