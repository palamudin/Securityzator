namespace Securityzator.Application.Portal;

public sealed record Milestone(
    string Key,
    string Name,
    string Goal,
    string ExitCriteria,
    string Status);
