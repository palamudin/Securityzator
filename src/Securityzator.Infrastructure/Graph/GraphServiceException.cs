namespace Securityzator.Infrastructure.Graph;

public sealed class GraphServiceException : Exception
{
    public GraphServiceException(string message)
        : base(message)
    {
    }
}
