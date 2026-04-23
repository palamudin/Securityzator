using System.Security.Claims;
using Securityzator.Application.Accounts;

namespace Securityzator.Web.Infrastructure;

public static class ClaimsPrincipalExtensions
{
    public static Guid GetOperatorId(this ClaimsPrincipal user)
    {
        var rawValue = user.FindFirstValue(ClaimTypes.NameIdentifier);

        return Guid.TryParse(rawValue, out var operatorId)
            ? operatorId
            : throw new InvalidOperationException("The current operator identity is missing a valid identifier.");
    }

    public static string GetWorkspaceName(this ClaimsPrincipal user)
    {
        return user.FindFirstValue("workspace") ?? "Default workspace";
    }

    public static string GetOperatorRole(this ClaimsPrincipal user)
    {
        return user.FindFirstValue(ClaimTypes.Role) ?? "Unknown";
    }

    public static bool IsWorkspaceAdmin(this ClaimsPrincipal user)
    {
        return string.Equals(user.GetOperatorRole(), OperatorRole.WorkspaceAdmin, StringComparison.Ordinal);
    }
}
