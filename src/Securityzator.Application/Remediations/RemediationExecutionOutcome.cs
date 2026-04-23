namespace Securityzator.Application.Remediations;

public sealed record RemediationExecutionOutcome(
    Guid RunId,
    string TemplateKey,
    Guid ConnectionId,
    string ConnectionDisplayName,
    RemediationRunStatus Status,
    bool Succeeded,
    bool AlreadyExists,
    string Message,
    DateTimeOffset CompletedUtc,
    string? PolicyId,
    string? PolicyState);
