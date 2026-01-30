using ClaimLedger.Application.Primitives;
using ClaimLedger.Domain.Identity;
using Shared.Crypto;

namespace ClaimLedger.Application.Identity;

/// <summary>
/// Command to create a new researcher identity with Ed25519 keypair.
/// </summary>
public sealed record CreateResearcherIdentityCommand(string? DisplayName);

/// <summary>
/// Handles creation of researcher identities.
/// </summary>
public sealed class CreateResearcherIdentityHandler
{
    private readonly IKeyVault _keyVault;
    private readonly IResearcherIdentityRepository _identityRepository;
    private readonly IClock _clock;

    public CreateResearcherIdentityHandler(
        IKeyVault keyVault,
        IResearcherIdentityRepository identityRepository,
        IClock clock)
    {
        _keyVault = keyVault;
        _identityRepository = identityRepository;
        _clock = clock;
    }

    public async Task<ResearcherIdentity> HandleAsync(
        CreateResearcherIdentityCommand command,
        CancellationToken ct = default)
    {
        // Generate new Ed25519 keypair
        var keypair = Ed25519KeyPair.Generate();

        // Create identity from public key
        var identity = ResearcherIdentity.Create(
            keypair.PublicKey,
            command.DisplayName,
            _clock.UtcNow);

        // Store private key securely
        await _keyVault.StoreAsync(identity.Id, keypair.PrivateKey, ct);

        // Persist identity
        await _identityRepository.SaveAsync(identity, ct);

        return identity;
    }
}
