namespace Securityzator.Infrastructure.Automation;

public sealed record PowerShellExecutionResult(
    int ExitCode,
    string StandardOutput,
    string StandardError)
{
    public bool Succeeded => ExitCode == 0;
}
