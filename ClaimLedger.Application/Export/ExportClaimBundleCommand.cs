using ClaimLedger.Domain.Claims;
using ClaimLedger.Domain.Identity;
using ClaimLedger.Domain.Primitives;

namespace ClaimLedger.Application.Export;

/// <summary>
/// Command to export a claim as a self-contained bundle.
/// </summary>
public sealed record ExportClaimBundleCommand(ClaimId ClaimId);

/// <summary>
/// Handles exporting claims as bundles.
/// </summary>
public sealed class ExportClaimBundleHandler
{
    private readonly IClaimRepository _claimRepository;
    private readonly IResearcherIdentityRepository _identityRepository;

    public ExportClaimBundleHandler(
        IClaimRepository claimRepository,
        IResearcherIdentityRepository identityRepository)
    {
        _claimRepository = claimRepository;
        _identityRepository = identityRepository;
    }

    public async Task<ClaimBundle> HandleAsync(
        ExportClaimBundleCommand command,
        CancellationToken ct = default)
    {
        // Get claim
        var claim = await _claimRepository.GetByIdAsync(command.ClaimId, ct)
            ?? throw new InvalidOperationException($"Claim not found: {command.ClaimId}");

        // Get researcher identity
        var researcher = await _identityRepository.GetByIdAsync(claim.ResearcherId, ct)
            ?? throw new InvalidOperationException($"Researcher not found: {claim.ResearcherId}");

        // Build bundle
        return new ClaimBundle
        {
            Version = "claim-bundle.v1",
            Algorithms = new AlgorithmsInfo
            {
                Signature = "Ed25519",
                Hash = "SHA-256",
                Encoding = "UTF-8"
            },
            Claim = new ClaimInfo
            {
                ClaimId = claim.Id.ToString(),
                Statement = claim.Statement,
                AssertedAtUtc = claim.AssertedAtUtc.ToString("O"),
                Evidence = claim.Evidence.Select(e => new EvidenceInfo
                {
                    Type = e.Type,
                    Hash = e.Hash.ToString(),
                    Locator = e.Locator
                }).ToList(),
                Signature = claim.Signature.ToString()
            },
            Researcher = new ResearcherInfo
            {
                ResearcherId = researcher.Id.ToString(),
                PublicKey = researcher.PublicKey.ToString(),
                DisplayName = researcher.DisplayName
            }
        };
    }
}
