namespace Securityzator.Application.Accounts;

public interface IOperatorAccountService
{
    Task<bool> HasOperatorsAsync(CancellationToken cancellationToken = default);

    Task<RegistrationOutcome> RegisterInitialOperatorAsync(
        RegisterOperatorRequest request,
        CancellationToken cancellationToken = default);

    Task<AuthenticatedOperator?> AuthenticateAsync(
        string email,
        string password,
        CancellationToken cancellationToken = default);

    Task<OperatorAccount?> GetOperatorAsync(Guid operatorId, CancellationToken cancellationToken = default);
}
