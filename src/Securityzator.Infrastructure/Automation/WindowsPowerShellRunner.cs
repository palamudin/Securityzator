using System.Diagnostics;
using System.Text;

namespace Securityzator.Infrastructure.Automation;

public sealed class WindowsPowerShellRunner
{
    private static readonly string PreferredPowerShellExecutable = ResolvePowerShellExecutable();

    public async Task<PowerShellExecutionResult> ExecuteScriptAsync(
        string script,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(script))
        {
            throw new InvalidOperationException("The PowerShell script content cannot be empty.");
        }

        var tempScriptPath = Path.Combine(
            Path.GetTempPath(),
            $"securityzator-{Guid.NewGuid():N}.ps1");

        await File.WriteAllTextAsync(tempScriptPath, script, new UTF8Encoding(false), cancellationToken);

        var startInfo = new ProcessStartInfo
        {
            FileName = PreferredPowerShellExecutable,
            Arguments = $"-NoLogo -NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass -File \"{tempScriptPath}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        try
        {
            using var process = new Process { StartInfo = startInfo };

            if (!process.Start())
            {
                throw new InvalidOperationException("Securityzator could not start the Windows PowerShell process.");
            }

            var standardOutputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var standardErrorTask = process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);

            return new PowerShellExecutionResult(
                process.ExitCode,
                await standardOutputTask,
                await standardErrorTask);
        }
        finally
        {
            try
            {
                if (File.Exists(tempScriptPath))
                {
                    File.Delete(tempScriptPath);
                }
            }
            catch
            {
                // Temporary script cleanup should never hide the real PowerShell execution result.
            }
        }
    }

    private static string ResolvePowerShellExecutable()
    {
        var preferredCandidates = new[]
        {
            "pwsh",
            "powershell"
        };

        foreach (var candidate in preferredCandidates)
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = candidate,
                    Arguments = "-NoLogo -NoProfile -NonInteractive -Command \"$PSVersionTable.PSVersion.ToString()\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);

                if (process is null)
                {
                    continue;
                }

                process.WaitForExit(5000);

                if (process.HasExited && process.ExitCode == 0)
                {
                    return candidate;
                }
            }
            catch
            {
                // Ignore startup failures and fall back to the next shell candidate.
            }
        }

        return "powershell";
    }
}
