using ClaimLedger.Application.Export;
using ClaimLedger.Application.Primitives;
using ClaimLedger.Domain.Attestations;
using ClaimLedger.Domain.Identity;
using ClaimLedger.Domain.Primitives;
using Shared.Crypto;

namespace ClaimLedger.Application.Attestations;

/// <summary>
/// Command to create an attestation about a claim.
/// </summary>
public sealed record CreateAttestationCommand(
    ClaimBundle ClaimBundle,
    ResearcherId AttestorId,
    string AttestationType,
    string Statement,
    DateTimeOffset? ExpiresAtUtc = null);

/// <summary>
/// Handles creation of attestations.
/// </summary>
public sealed class CreateAttestationHandler
{
    private readonly IKeyVault _keyVault;
    private readonly IResearcherIdentityRepository _identityRepository;
    private readonly IClock _clock;

    public CreateAttestationHandler(
        IKeyVault keyVault,
        IResearcherIdentityRepository identityRepository,
        IClock clock)
    {
        _keyVault = keyVault;
        _identityRepository = identityRepository;
        _clock = clock;
    }

    public async Task<Attestation> HandleAsync(
        CreateAttestationCommand command,
        CancellationToken ct = default)
    {
        // Validate attestation type
        if (!Domain.Attestations.AttestationType.IsValid(command.AttestationType))
            throw new ArgumentException($"Invalid attestation type: {command.AttestationType}");

        // Validate statement
        if (string.IsNullOrWhiteSpace(command.Statement))
            throw new ArgumentException("Statement cannot be empty");

        // Get attestor identity
        var attestor = await _identityRepository.GetByIdAsync(command.AttestorId, ct)
            ?? throw new InvalidOperationException($"Attestor not found: {command.AttestorId}");

        // Get private key for signing
        var privateKey = await _keyVault.RetrieveAsync(command.AttestorId, ct)
            ?? throw new InvalidOperationException($"Private key not found for attestor: {command.AttestorId}");

        // Compute claim_core_digest
        var claimCoreDigest = ClaimCoreDigest.Compute(command.ClaimBundle);

        // Create attestation ID and timestamp
        var attestationId = AttestationId.New();
        var issuedAt = _clock.UtcNow;

        // Build signable and sign
        var signable = new AttestationSignable
        {
            Contract = "AttestationSignable.v1",
            AttestationId = attestationId.ToString(),
            ClaimCoreDigest = claimCoreDigest.ToString(),
            Attestor = new AttestorIdentity
            {
                ResearcherId = command.AttestorId.ToString(),
                PublicKey = attestor.PublicKey.ToString(),
                DisplayName = attestor.DisplayName
            },
            AttestationType = command.AttestationType,
            Statement = command.Statement,
            IssuedAtUtc = issuedAt.ToString("O"),
            ExpiresAtUtc = command.ExpiresAtUtc?.ToString("O"),
            Policy = null
        };

        var bytes = CanonicalJson.SerializeToBytes(signable);
        var signature = privateKey.Sign(bytes);

        // Create attestation
        return new Attestation(
            attestationId,
            claimCoreDigest,
            command.AttestorId,
            attestor.PublicKey,
            attestor.DisplayName,
            command.AttestationType,
            command.Statement,
            issuedAt,
            command.ExpiresAtUtc,
            signature);
    }
}
