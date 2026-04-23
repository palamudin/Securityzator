namespace Securityzator.Infrastructure.Storage;

public sealed class SecurityzatorStorageOptions
{
    public string DataFilePath { get; set; } = "App_Data/securityzator-state.json";

    public string MutexName { get; set; } = "Local\\Securityzator.StateStore";
}
