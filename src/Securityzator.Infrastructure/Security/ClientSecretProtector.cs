using Microsoft.AspNetCore.DataProtection;

namespace Securityzator.Infrastructure.Security;

public sealed class ClientSecretProtector
{
    private readonly IDataProtector _protector;

    public ClientSecretProtector(IDataProtectionProvider dataProtectionProvider)
    {
        _protector = dataProtectionProvider.CreateProtector("Securityzator.AzureConnections.ClientSecret");
    }

    public string Protect(string plaintextSecret)
    {
        return _protector.Protect(plaintextSecret);
    }

    public string Unprotect(string protectedSecret)
    {
        return _protector.Unprotect(protectedSecret);
    }
}
