namespace Securityzator.Infrastructure.Pathing;

internal static class SecurityzatorPathResolver
{
    internal static string ResolveFilePath(string configuredPath, string contentRootPath)
    {
        return ResolvePath(configuredPath, contentRootPath, File.Exists);
    }

    internal static string ResolveDirectoryPath(string configuredPath, string contentRootPath)
    {
        return ResolvePath(configuredPath, contentRootPath, Directory.Exists);
    }

    private static string ResolvePath(
        string configuredPath,
        string contentRootPath,
        Func<string, bool> exists)
    {
        if (Path.IsPathRooted(configuredPath))
        {
            return configuredPath;
        }

        var candidates = new List<string>
        {
            Path.GetFullPath(Path.Combine(contentRootPath, configuredPath))
        };

        var currentDirectory = Directory.GetCurrentDirectory();
        if (!string.Equals(currentDirectory, contentRootPath, StringComparison.OrdinalIgnoreCase))
        {
            candidates.Add(Path.GetFullPath(Path.Combine(currentDirectory, configuredPath)));
        }

        var appBaseDirectory = AppContext.BaseDirectory;
        if (!string.Equals(appBaseDirectory, contentRootPath, StringComparison.OrdinalIgnoreCase))
        {
            candidates.Add(Path.GetFullPath(Path.Combine(appBaseDirectory, configuredPath)));
        }

        if (configuredPath.StartsWith("..\\", StringComparison.Ordinal)
            || configuredPath.StartsWith("../", StringComparison.Ordinal))
        {
            var trimmedUpLevelPath = configuredPath.TrimStart('.', '\\', '/');
            candidates.Add(Path.GetFullPath(Path.Combine(contentRootPath, "src", trimmedUpLevelPath)));
        }

        foreach (var candidate in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (exists(candidate))
            {
                return candidate;
            }
        }

        return candidates[0];
    }
}
