using ClaimLedger.Domain.Evidence;
using ClaimLedger.Domain.Primitives;
using Shared.Crypto;

namespace ClaimLedger.Domain.Claims;

/// <summary>
/// A cryptographically signed scientific claim with evidence references.
///
/// This is not a paper. It is a signed statement with referenced evidence.
/// The signature covers the claim statement, researcher identity, and evidence hashes.
/// </summary>
public sealed class ClaimAssertion
{
    public ClaimId Id { get; }
    public string Statement { get; }
    public ResearcherId ResearcherId { get; }
    public Ed25519PublicKey ResearcherPublicKey { get; }
    public DateTimeOffset AssertedAtUtc { get; }
    public IReadOnlyList<EvidenceArtifact> Evidence { get; }
    public Ed25519Signature Signature { get; }

    public ClaimAssertion(
        ClaimId id,
        string statement,
        ResearcherId researcherId,
        Ed25519PublicKey researcherPublicKey,
        DateTimeOffset assertedAtUtc,
        IReadOnlyList<EvidenceArtifact> evidence,
        Ed25519Signature signature)
    {
        if (string.IsNullOrWhiteSpace(statement))
            throw new ArgumentException("Statement cannot be empty", nameof(statement));

        Id = id;
        Statement = statement;
        ResearcherId = researcherId;
        ResearcherPublicKey = researcherPublicKey ?? throw new ArgumentNullException(nameof(researcherPublicKey));
        AssertedAtUtc = assertedAtUtc;
        Evidence = evidence ?? throw new ArgumentNullException(nameof(evidence));
        Signature = signature;
    }

    /// <summary>
    /// Builds the signable DTO for this claim.
    /// Used for both signing and verification.
    /// </summary>
    public ClaimSignable ToSignable()
    {
        return new ClaimSignable
        {
            Version = "claim.v1",
            ClaimId = Id.ToString(),
            Statement = Statement,
            ResearcherId = ResearcherId.ToString(),
            ResearcherPublicKey = ResearcherPublicKey.ToString(),
            Evidence = Evidence.Select(e => new EvidenceSignable
            {
                Type = e.Type,
                Hash = e.Hash.ToString(),
                Locator = e.Locator
            }).ToList(),
            AssertedAtUtc = AssertedAtUtc.ToString("O")
        };
    }

    /// <summary>
    /// Verifies the cryptographic signature of this claim.
    /// </summary>
    public bool VerifySignature()
    {
        var signable = ToSignable();
        var bytes = CanonicalJson.SerializeToBytes(signable);
        return ResearcherPublicKey.Verify(bytes, Signature);
    }
}
