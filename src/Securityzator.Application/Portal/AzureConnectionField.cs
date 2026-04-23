namespace Securityzator.Application.Portal;

public sealed record AzureConnectionField(
    string Key,
    string Label,
    string Placeholder,
    bool Required,
    bool IsSecret,
    string HelpText);
