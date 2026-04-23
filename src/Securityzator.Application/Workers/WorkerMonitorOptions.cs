namespace Securityzator.Application.Workers;

public sealed class WorkerMonitorOptions
{
    public int HeartbeatStaleAfterSeconds { get; set; } = 30;
}
