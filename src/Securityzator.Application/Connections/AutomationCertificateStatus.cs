namespace Securityzator.Application.Connections;

public enum AutomationCertificateStatus
{
    NotConfigured = 0,
    Ready = 1,
    NotFound = 2,
    MissingPrivateKey = 3,
    Expired = 4,
    Error = 5
}
