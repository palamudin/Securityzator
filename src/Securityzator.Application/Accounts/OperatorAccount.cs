namespace Securityzator.Application.Accounts;

public sealed record OperatorAccount(
    Guid Id,
    string Email,
    string DisplayName,
    string WorkspaceName,
    string Role,
    DateTimeOffset CreatedUtc);
