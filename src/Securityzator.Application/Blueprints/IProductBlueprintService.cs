namespace Securityzator.Application.Blueprints;

public interface IProductBlueprintService
{
    Task<PortalBlueprint> GetPortalBlueprintAsync(CancellationToken cancellationToken = default);
}
