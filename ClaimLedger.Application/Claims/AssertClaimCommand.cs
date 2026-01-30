using ClaimLedger.Application.Primitives;
using ClaimLedger.Domain.Claims;
using ClaimLedger.Domain.Evidence;
using ClaimLedger.Domain.Identity;
using ClaimLedger.Domain.Primitives;
using Shared.Crypto;

namespace ClaimLedger.Application.Claims;

/// <summary>
/// Command to assert a new scientific claim.
/// </summary>
public sealed record AssertClaimCommand(
    string Statement,
    ResearcherId ResearcherId,
    IReadOnlyList<EvidenceInput> Evidence);

/// <summary>
/// Input for evidence to include with a claim.
/// </summary>
public sealed record EvidenceInput(
    string Type,
    ContentHash Hash,
    string? Locator = null);

/// <summary>
/// Handles assertion of scientific claims.
/// </summary>
public sealed class AssertClaimHandler
{
    private readonly IKeyVault _keyVault;
    private readonly IResearcherIdentityRepository _identityRepository;
    private readonly IClaimRepository _claimRepository;
    private readonly IClock _clock;

    public AssertClaimHandler(
        IKeyVault keyVault,
        IResearcherIdentityRepository identityRepository,
        IClaimRepository claimRepository,
        IClock clock)
    {
        _keyVault = keyVault;
        _identityRepository = identityRepository;
        _claimRepository = claimRepository;
        _clock = clock;
    }

    public async Task<ClaimAssertion> HandleAsync(
        AssertClaimCommand command,
        CancellationToken ct = default)
    {
        // Validate statement
        if (string.IsNullOrWhiteSpace(command.Statement))
            throw new ArgumentException("Claim statement cannot be empty");

        // Get researcher identity
        var identity = await _identityRepository.GetByIdAsync(command.ResearcherId, ct)
            ?? throw new InvalidOperationException($"Researcher not found: {command.ResearcherId}");

        // Get private key for signing
        var privateKey = await _keyVault.RetrieveAsync(command.ResearcherId, ct)
            ?? throw new InvalidOperationException($"Private key not found for researcher: {command.ResearcherId}");

        // Build evidence artifacts
        var evidence = command.Evidence
            .Select(e => EvidenceArtifact.Create(e.Type, e.Hash, e.Locator))
            .ToList();

        // Create claim ID and timestamp
        var claimId = ClaimId.New();
        var assertedAt = _clock.UtcNow;

        // Build signable and sign
        var signable = new ClaimSignable
        {
            Version = "claim.v1",
            ClaimId = claimId.ToString(),
            Statement = command.Statement,
            ResearcherId = command.ResearcherId.ToString(),
            ResearcherPublicKey = identity.PublicKey.ToString(),
            Evidence = evidence.Select(e => new EvidenceSignable
            {
                Type = e.Type,
                Hash = e.Hash.ToString(),
                Locator = e.Locator
            }).ToList(),
            AssertedAtUtc = assertedAt.ToString("O")
        };

        var bytes = CanonicalJson.SerializeToBytes(signable);
        var signature = privateKey.Sign(bytes);

        // Create claim assertion
        var claim = new ClaimAssertion(
            claimId,
            command.Statement,
            command.ResearcherId,
            identity.PublicKey,
            assertedAt,
            evidence,
            signature);

        // Persist claim
        await _claimRepository.SaveAsync(claim, ct);

        return claim;
    }
}
