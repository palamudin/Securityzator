using Microsoft.AspNetCore.Identity;
using Securityzator.Application.Accounts;
using Securityzator.Infrastructure.Storage;

namespace Securityzator.Infrastructure.Accounts;

public sealed class FileBackedOperatorAccountService : IOperatorAccountService
{
    private readonly JsonFileSecurityzatorStateStore _stateStore;
    private readonly PasswordHasher<StoredOperatorAccount> _passwordHasher = new();

    public FileBackedOperatorAccountService(JsonFileSecurityzatorStateStore stateStore)
    {
        _stateStore = stateStore;
    }

    public Task<bool> HasOperatorsAsync(CancellationToken cancellationToken = default)
    {
        return _stateStore.ReadAsync(state => state.Operators.Count > 0, cancellationToken);
    }

    public async Task<RegistrationOutcome> RegisterInitialOperatorAsync(
        RegisterOperatorRequest request,
        CancellationToken cancellationToken = default)
    {
        var normalizedEmail = NormalizeEmail(request.Email);

        return await _stateStore.WriteAsync(state =>
        {
            if (state.Operators.Count > 0)
            {
                return new RegistrationOutcome(
                    false,
                    "The initial workspace has already been created. Sign in with the existing operator account.",
                    null);
            }

            if (state.Operators.Any(existing => existing.Email == normalizedEmail))
            {
                return new RegistrationOutcome(false, "An operator account with that email already exists.", null);
            }

            var createdUtc = DateTimeOffset.UtcNow;
            var stored = new StoredOperatorAccount
            {
                Id = Guid.NewGuid(),
                Email = normalizedEmail,
                DisplayName = request.DisplayName.Trim(),
                WorkspaceName = request.WorkspaceName.Trim(),
                Role = OperatorRole.WorkspaceAdmin,
                CreatedUtc = createdUtc
            };

            stored.PasswordHash = _passwordHasher.HashPassword(stored, request.Password);
            state.Operators.Add(stored);

            return new RegistrationOutcome(true, null, ToAuthenticatedOperator(stored));
        }, cancellationToken);
    }

    public async Task<AuthenticatedOperator?> AuthenticateAsync(
        string email,
        string password,
        CancellationToken cancellationToken = default)
    {
        var normalizedEmail = NormalizeEmail(email);

        var stored = await _stateStore.ReadAsync(
            state => state.Operators.FirstOrDefault(existing => existing.Email == normalizedEmail),
            cancellationToken);

        if (stored is null)
        {
            return null;
        }

        var verificationResult = _passwordHasher.VerifyHashedPassword(stored, stored.PasswordHash, password);

        if (verificationResult == PasswordVerificationResult.Failed)
        {
            return null;
        }

        if (verificationResult == PasswordVerificationResult.SuccessRehashNeeded)
        {
            await _stateStore.WriteAsync(state =>
            {
                var existing = state.Operators.First(operatorAccount => operatorAccount.Id == stored.Id);
                existing.PasswordHash = _passwordHasher.HashPassword(existing, password);
                return 0;
            }, cancellationToken);
        }

        return ToAuthenticatedOperator(stored);
    }

    public async Task<OperatorAccount?> GetOperatorAsync(Guid operatorId, CancellationToken cancellationToken = default)
    {
        var stored = await _stateStore.ReadAsync(
            state => state.Operators.FirstOrDefault(existing => existing.Id == operatorId),
            cancellationToken);

        return stored is null ? null : ToOperatorAccount(stored);
    }

    private static string NormalizeEmail(string email)
    {
        return email.Trim().ToLowerInvariant();
    }

    private static AuthenticatedOperator ToAuthenticatedOperator(StoredOperatorAccount stored)
    {
        return new AuthenticatedOperator(stored.Id, stored.Email, stored.DisplayName, stored.WorkspaceName, stored.Role);
    }

    private static OperatorAccount ToOperatorAccount(StoredOperatorAccount stored)
    {
        return new OperatorAccount(stored.Id, stored.Email, stored.DisplayName, stored.WorkspaceName, stored.Role, stored.CreatedUtc);
    }
}
