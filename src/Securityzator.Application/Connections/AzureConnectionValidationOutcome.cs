namespace Securityzator.Application.Connections;

public sealed record AzureConnectionValidationOutcome(
    Guid ConnectionId,
    string ConnectionDisplayName,
    AzureConnectionValidationStatus ValidationStatus,
    bool Succeeded,
    string Message,
    DateTimeOffset AttemptedUtc,
    bool CanReadGroups,
    bool CanReadConditionalAccess,
    bool CanReadRecommendations);
