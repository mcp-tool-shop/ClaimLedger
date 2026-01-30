using ClaimLedger.Domain.Primitives;
using Shared.Crypto;

namespace ClaimLedger.Domain.Revocations;

/// <summary>
/// A key revocation statement.
/// Revokes a specific public key as of a given time.
/// </summary>
public sealed class Revocation
{
    public RevocationId Id { get; }
    public ResearcherId ResearcherId { get; }
    public Ed25519PublicKey RevokedPublicKey { get; }
    public DateTimeOffset RevokedAtUtc { get; }
    public string Reason { get; }
    public string IssuerMode { get; }
    public Ed25519PublicKey? SuccessorPublicKey { get; }
    public string? Notes { get; }
    public Ed25519PublicKey SignerPublicKey { get; }
    public Ed25519Signature Signature { get; }

    private readonly RevocationSignable _signable;

    private Revocation(
        RevocationId id,
        ResearcherId researcherId,
        Ed25519PublicKey revokedPublicKey,
        DateTimeOffset revokedAtUtc,
        string reason,
        string issuerMode,
        Ed25519PublicKey? successorPublicKey,
        string? notes,
        Ed25519PublicKey signerPublicKey,
        Ed25519Signature signature,
        RevocationSignable signable)
    {
        Id = id;
        ResearcherId = researcherId;
        RevokedPublicKey = revokedPublicKey;
        RevokedAtUtc = revokedAtUtc;
        Reason = reason;
        IssuerMode = issuerMode;
        SuccessorPublicKey = successorPublicKey;
        Notes = notes;
        SignerPublicKey = signerPublicKey;
        Signature = signature;
        _signable = signable;
    }

    /// <summary>
    /// Creates a self-signed revocation (the revoked key signs its own revocation).
    /// </summary>
    public static Revocation CreateSelfSigned(
        ResearcherId researcherId,
        Ed25519PublicKey revokedPublicKey,
        Ed25519PrivateKey revokedPrivateKey,
        DateTimeOffset revokedAtUtc,
        string reason,
        Ed25519PublicKey? successorPublicKey = null,
        string? notes = null)
    {
        ValidateReason(reason);

        var id = RevocationId.New();

        var signable = new RevocationSignable
        {
            RevocationId = id.ToString(),
            ResearcherId = researcherId.ToString(),
            RevokedPublicKey = revokedPublicKey.ToString(),
            RevokedAt = revokedAtUtc.ToString("O"),
            Reason = reason,
            IssuerMode = Revocations.IssuerMode.Self,
            SuccessorPublicKey = successorPublicKey?.ToString(),
            Notes = notes
        };

        var bytes = CanonicalJson.SerializeToBytes(signable);
        var signature = revokedPrivateKey.Sign(bytes);

        return new Revocation(
            id,
            researcherId,
            revokedPublicKey,
            revokedAtUtc,
            reason,
            Revocations.IssuerMode.Self,
            successorPublicKey,
            notes,
            revokedPublicKey, // signer is the revoked key
            signature,
            signable);
    }

    /// <summary>
    /// Creates a successor-signed revocation (the new key signs the revocation of the old key).
    /// </summary>
    public static Revocation CreateSuccessorSigned(
        ResearcherId researcherId,
        Ed25519PublicKey revokedPublicKey,
        Ed25519PublicKey successorPublicKey,
        Ed25519PrivateKey successorPrivateKey,
        DateTimeOffset revokedAtUtc,
        string reason,
        string? notes = null)
    {
        ValidateReason(reason);

        var id = RevocationId.New();

        var signable = new RevocationSignable
        {
            RevocationId = id.ToString(),
            ResearcherId = researcherId.ToString(),
            RevokedPublicKey = revokedPublicKey.ToString(),
            RevokedAt = revokedAtUtc.ToString("O"),
            Reason = reason,
            IssuerMode = Revocations.IssuerMode.Successor,
            SuccessorPublicKey = successorPublicKey.ToString(),
            Notes = notes
        };

        var bytes = CanonicalJson.SerializeToBytes(signable);
        var signature = successorPrivateKey.Sign(bytes);

        return new Revocation(
            id,
            researcherId,
            revokedPublicKey,
            revokedAtUtc,
            reason,
            Revocations.IssuerMode.Successor,
            successorPublicKey,
            notes,
            successorPublicKey, // signer is the successor key
            signature,
            signable);
    }

    /// <summary>
    /// Reconstructs a revocation from stored data for verification.
    /// </summary>
    public static Revocation Reconstitute(
        RevocationId id,
        ResearcherId researcherId,
        Ed25519PublicKey revokedPublicKey,
        DateTimeOffset revokedAtUtc,
        string reason,
        string issuerMode,
        Ed25519PublicKey? successorPublicKey,
        string? notes,
        Ed25519Signature signature)
    {
        // Determine signer based on issuer mode
        Ed25519PublicKey signerPublicKey;
        if (issuerMode == Revocations.IssuerMode.Self)
        {
            signerPublicKey = revokedPublicKey;
        }
        else if (issuerMode == Revocations.IssuerMode.Successor)
        {
            if (successorPublicKey == null)
                throw new ArgumentException("Successor-signed revocation requires successor_public_key");
            signerPublicKey = successorPublicKey;
        }
        else
        {
            throw new ArgumentException($"Invalid issuer mode: {issuerMode}");
        }

        var signable = new RevocationSignable
        {
            RevocationId = id.ToString(),
            ResearcherId = researcherId.ToString(),
            RevokedPublicKey = revokedPublicKey.ToString(),
            RevokedAt = revokedAtUtc.ToString("O"),
            Reason = reason,
            IssuerMode = issuerMode,
            SuccessorPublicKey = successorPublicKey?.ToString(),
            Notes = notes
        };

        return new Revocation(
            id,
            researcherId,
            revokedPublicKey,
            revokedAtUtc,
            reason,
            issuerMode,
            successorPublicKey,
            notes,
            signerPublicKey,
            signature,
            signable);
    }

    /// <summary>
    /// Verifies the revocation signature according to its issuer mode.
    /// </summary>
    public bool VerifySignature()
    {
        var bytes = CanonicalJson.SerializeToBytes(_signable);
        return SignerPublicKey.Verify(bytes, Signature);
    }

    /// <summary>
    /// Checks if this revocation invalidates a signature made at the given time.
    /// Returns true if the signature is invalidated (revoked_at &lt;= signed_at).
    /// </summary>
    public bool Invalidates(DateTimeOffset signedAtUtc)
    {
        return RevokedAtUtc <= signedAtUtc;
    }

    private static void ValidateReason(string reason)
    {
        if (!RevocationReason.IsValid(reason))
            throw new ArgumentException($"Invalid revocation reason: {reason}", nameof(reason));
    }
}
