namespace Securityzator.Application.Connections;

public interface IAzureConnectionService
{
    Task<IReadOnlyList<AzureConnectionProfile>> ListForOperatorAsync(
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default);

    Task<AzureConnectionProfile?> GetForOperatorAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default);

    Task<AzureConnectionProfile> CreateAsync(
        CreateAzureConnectionRequest request,
        CancellationToken cancellationToken = default);

    Task<AzureConnectionProfile?> UpdateAsync(
        UpdateAzureConnectionRequest request,
        CancellationToken cancellationToken = default);

    Task<AzureConnectionValidationOutcome> ValidateAsync(
        Guid connectionId,
        Guid ownerOperatorId,
        CancellationToken cancellationToken = default);
}
