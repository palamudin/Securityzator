using Securityzator.Application.Accounts;

namespace Securityzator.Infrastructure.Storage;

public sealed class StoredOperatorAccount
{
    public Guid Id { get; set; }

    public string Email { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string WorkspaceName { get; set; } = string.Empty;

    public string Role { get; set; } = OperatorRole.WorkspaceAdmin;

    public string PasswordHash { get; set; } = string.Empty;

    public DateTimeOffset CreatedUtc { get; set; }
}
