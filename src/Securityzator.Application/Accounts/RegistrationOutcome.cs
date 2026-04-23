namespace Securityzator.Application.Accounts;

public sealed record RegistrationOutcome(
    bool Succeeded,
    string? ErrorMessage,
    AuthenticatedOperator? Operator);
