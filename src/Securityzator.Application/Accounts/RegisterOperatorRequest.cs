namespace Securityzator.Application.Accounts;

public sealed record RegisterOperatorRequest(
    string Email,
    string DisplayName,
    string WorkspaceName,
    string Password);
