using ClaimLedger.Domain.Identity;
using ClaimLedger.Domain.Primitives;
using Shared.Crypto;

namespace ClaimLedger.Domain.Citations;

/// <summary>
/// A citation linking one claim to another.
/// Citations are signed by the claim author and become part of the claim_core_digest.
/// </summary>
public sealed class Citation
{
    public CitationId Id { get; }
    public Digest256 CitedClaimCoreDigest { get; }
    public string Relation { get; }
    public string? Locator { get; }
    public string? Notes { get; }
    public DateTimeOffset IssuedAtUtc { get; }
    public ResearcherId SignerId { get; }
    public Ed25519PublicKey SignerPublicKey { get; }
    public Ed25519Signature Signature { get; }

    private readonly CitationSignable _signable;

    private Citation(
        CitationId id,
        Digest256 citedClaimCoreDigest,
        string relation,
        string? locator,
        string? notes,
        DateTimeOffset issuedAtUtc,
        ResearcherId signerId,
        Ed25519PublicKey signerPublicKey,
        Ed25519Signature signature,
        CitationSignable signable)
    {
        Id = id;
        CitedClaimCoreDigest = citedClaimCoreDigest;
        Relation = relation;
        Locator = locator;
        Notes = notes;
        IssuedAtUtc = issuedAtUtc;
        SignerId = signerId;
        SignerPublicKey = signerPublicKey;
        Signature = signature;
        _signable = signable;
    }

    /// <summary>
    /// Creates and signs a new citation.
    /// </summary>
    public static Citation Create(
        Digest256 citedClaimCoreDigest,
        string relation,
        string? locator,
        string? notes,
        ResearcherIdentity signer,
        Ed25519PrivateKey privateKey,
        DateTimeOffset issuedAtUtc)
    {
        if (!CitationRelation.IsValid(relation))
            throw new ArgumentException($"Invalid citation relation: {relation}", nameof(relation));

        var id = CitationId.New();

        var signable = new CitationSignable
        {
            CitationId = id.ToString(),
            CitedClaimCoreDigest = citedClaimCoreDigest.ToString(),
            Relation = relation,
            Locator = locator,
            Notes = notes,
            IssuedAt = issuedAtUtc.ToString("O")
        };

        var bytes = CanonicalJson.SerializeToBytes(signable);
        var signature = privateKey.Sign(bytes);

        return new Citation(
            id,
            citedClaimCoreDigest,
            relation,
            locator,
            notes,
            issuedAtUtc,
            signer.Id,
            signer.PublicKey,
            signature,
            signable);
    }

    /// <summary>
    /// Reconstructs a citation from stored data for verification.
    /// </summary>
    public static Citation Reconstitute(
        CitationId id,
        Digest256 citedClaimCoreDigest,
        string relation,
        string? locator,
        string? notes,
        DateTimeOffset issuedAtUtc,
        ResearcherId signerId,
        Ed25519PublicKey signerPublicKey,
        Ed25519Signature signature)
    {
        var signable = new CitationSignable
        {
            CitationId = id.ToString(),
            CitedClaimCoreDigest = citedClaimCoreDigest.ToString(),
            Relation = relation,
            Locator = locator,
            Notes = notes,
            IssuedAt = issuedAtUtc.ToString("O")
        };

        return new Citation(
            id,
            citedClaimCoreDigest,
            relation,
            locator,
            notes,
            issuedAtUtc,
            signerId,
            signerPublicKey,
            signature,
            signable);
    }

    /// <summary>
    /// Verifies the citation signature.
    /// </summary>
    public bool VerifySignature()
    {
        var bytes = CanonicalJson.SerializeToBytes(_signable);
        return SignerPublicKey.Verify(bytes, Signature);
    }
}
