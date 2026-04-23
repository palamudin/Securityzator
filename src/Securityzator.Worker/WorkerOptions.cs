namespace Securityzator.Worker;

public sealed class WorkerOptions
{
    public int PollIntervalSeconds { get; set; } = 5;

    public int IdleDelaySeconds { get; set; } = 3;
}
