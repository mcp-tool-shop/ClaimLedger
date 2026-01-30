using ClaimLedger.Domain.Identity;
using ClaimLedger.Domain.Primitives;
using Shared.Crypto;

namespace ClaimLedger.Domain.Attestations;

/// <summary>
/// A cryptographically signed attestation about a claim.
///
/// "I examined claim X and I attest Y" — cryptographically bound to the exact bytes of X.
/// </summary>
public sealed class Attestation
{
    public AttestationId Id { get; }
    public Digest256 ClaimCoreDigest { get; }
    public ResearcherId AttestorId { get; }
    public Ed25519PublicKey AttestorPublicKey { get; }
    public string? AttestorDisplayName { get; }
    public string Type { get; }
    public string Statement { get; }
    public DateTimeOffset IssuedAtUtc { get; }
    public DateTimeOffset? ExpiresAtUtc { get; }
    public Ed25519Signature Signature { get; }

    public Attestation(
        AttestationId id,
        Digest256 claimCoreDigest,
        ResearcherId attestorId,
        Ed25519PublicKey attestorPublicKey,
        string? attestorDisplayName,
        string type,
        string statement,
        DateTimeOffset issuedAtUtc,
        DateTimeOffset? expiresAtUtc,
        Ed25519Signature signature)
    {
        if (string.IsNullOrWhiteSpace(statement))
            throw new ArgumentException("Statement cannot be empty", nameof(statement));

        if (!AttestationType.IsValid(type))
            throw new ArgumentException($"Invalid attestation type: {type}", nameof(type));

        Id = id;
        ClaimCoreDigest = claimCoreDigest;
        AttestorId = attestorId;
        AttestorPublicKey = attestorPublicKey ?? throw new ArgumentNullException(nameof(attestorPublicKey));
        AttestorDisplayName = attestorDisplayName;
        Type = type;
        Statement = statement;
        IssuedAtUtc = issuedAtUtc;
        ExpiresAtUtc = expiresAtUtc;
        Signature = signature;
    }

    /// <summary>
    /// Builds the signable DTO for this attestation.
    /// Used for both signing and verification.
    /// </summary>
    public AttestationSignable ToSignable()
    {
        return new AttestationSignable
        {
            Contract = "AttestationSignable.v1",
            AttestationId = Id.ToString(),
            ClaimCoreDigest = ClaimCoreDigest.ToString(),
            Attestor = new AttestorIdentity
            {
                ResearcherId = AttestorId.ToString(),
                PublicKey = AttestorPublicKey.ToString(),
                DisplayName = AttestorDisplayName
            },
            AttestationType = Type,
            Statement = Statement,
            IssuedAtUtc = IssuedAtUtc.ToString("O"),
            ExpiresAtUtc = ExpiresAtUtc?.ToString("O"),
            Policy = null
        };
    }

    /// <summary>
    /// Verifies the cryptographic signature of this attestation.
    /// </summary>
    public bool VerifySignature()
    {
        var signable = ToSignable();
        var bytes = CanonicalJson.SerializeToBytes(signable);
        return AttestorPublicKey.Verify(bytes, Signature);
    }

    /// <summary>
    /// Checks if this attestation has expired.
    /// </summary>
    public bool IsExpired(DateTimeOffset asOf) =>
        ExpiresAtUtc.HasValue && ExpiresAtUtc.Value <= asOf;
}
