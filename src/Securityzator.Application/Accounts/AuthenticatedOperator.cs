namespace Securityzator.Application.Accounts;

public sealed record AuthenticatedOperator(
    Guid Id,
    string Email,
    string DisplayName,
    string WorkspaceName,
    string Role);
