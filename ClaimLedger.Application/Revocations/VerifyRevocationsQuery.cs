using System.Globalization;
using ClaimLedger.Application.Export;
using ClaimLedger.Domain.Primitives;
using ClaimLedger.Domain.Revocations;
using Shared.Crypto;

namespace ClaimLedger.Application.Revocations;

/// <summary>
/// Query to verify a claim bundle against a set of revocations.
/// </summary>
public sealed record VerifyAgainstRevocationsQuery(
    ClaimBundle Bundle,
    RevocationRegistry Registry,
    bool StrictMode = false);

/// <summary>
/// Result of revocation verification.
/// </summary>
public sealed class RevocationVerificationResult
{
    public required bool IsValid { get; init; }
    public required IReadOnlyList<RevocationCheckResult> Checks { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
}

/// <summary>
/// Result of checking a single signature against revocations.
/// </summary>
public sealed class RevocationCheckResult
{
    public required string SignatureType { get; init; }  // "Claim", "Citation", "Attestation"
    public required string SignerId { get; init; }
    public required string SignerPublicKey { get; init; }
    public required string SignedAtUtc { get; init; }
    public required bool IsRevoked { get; init; }
    public string? RevokedAtUtc { get; init; }
    public string? RevocationReason { get; init; }

    public static class SignatureTypes
    {
        public const string Claim = "Claim";
        public const string Citation = "Citation";
        public const string Attestation = "Attestation";
    }
}

/// <summary>
/// Registry of revocations, keyed by public key.
/// </summary>
public sealed class RevocationRegistry
{
    private readonly Dictionary<string, List<Revocation>> _byPublicKey = new(StringComparer.Ordinal);

    public static RevocationRegistry Empty => new();

    /// <summary>
    /// Adds a revocation to the registry.
    /// </summary>
    public void Add(Revocation revocation)
    {
        var key = revocation.RevokedPublicKey.ToString();
        if (!_byPublicKey.TryGetValue(key, out var list))
        {
            list = new List<Revocation>();
            _byPublicKey[key] = list;
        }
        list.Add(revocation);
    }

    /// <summary>
    /// Gets the earliest revocation for a public key, if any.
    /// </summary>
    public Revocation? GetEarliestRevocation(Ed25519PublicKey publicKey)
    {
        var key = publicKey.ToString();
        if (!_byPublicKey.TryGetValue(key, out var list) || list.Count == 0)
            return null;

        return list.OrderBy(r => r.RevokedAtUtc).First();
    }

    /// <summary>
    /// Gets all revocations for a public key.
    /// </summary>
    public IReadOnlyList<Revocation> GetRevocations(Ed25519PublicKey publicKey)
    {
        var key = publicKey.ToString();
        if (!_byPublicKey.TryGetValue(key, out var list))
            return Array.Empty<Revocation>();
        return list;
    }

    /// <summary>
    /// Gets all revocations in the registry.
    /// </summary>
    public IReadOnlyList<Revocation> GetAll()
    {
        return _byPublicKey.Values.SelectMany(x => x).ToList();
    }

    /// <summary>
    /// Checks if a signature made at a given time by a given key is revoked.
    /// </summary>
    public bool IsRevoked(Ed25519PublicKey publicKey, DateTimeOffset signedAtUtc)
    {
        var earliest = GetEarliestRevocation(publicKey);
        return earliest != null && earliest.Invalidates(signedAtUtc);
    }

    /// <summary>
    /// Loads a revocation from a bundle, validating its signature.
    /// Returns null if the bundle is invalid.
    /// </summary>
    public static Revocation? LoadFromBundle(RevocationBundle bundle)
    {
        try
        {
            var info = bundle.Revocation;

            var id = RevocationId.Parse(info.RevocationId);
            var researcherId = ResearcherId.Parse(info.ResearcherId);
            var revokedPublicKey = Ed25519PublicKey.Parse(info.RevokedPublicKey);
            var revokedAt = DateTimeOffset.Parse(info.RevokedAtUtc, CultureInfo.InvariantCulture);
            var signature = Ed25519Signature.Parse(info.Signature);

            Ed25519PublicKey? successorPublicKey = null;
            if (!string.IsNullOrEmpty(info.SuccessorPublicKey))
            {
                successorPublicKey = Ed25519PublicKey.Parse(info.SuccessorPublicKey);
            }

            var revocation = Revocation.Reconstitute(
                id,
                researcherId,
                revokedPublicKey,
                revokedAt,
                info.Reason,
                info.IssuerMode,
                successorPublicKey,
                info.Notes,
                signature);

            // Verify signature
            if (!revocation.VerifySignature())
                return null;

            return revocation;
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>
/// Handler for verifying a claim bundle against revocations.
/// </summary>
public static class VerifyAgainstRevocationsHandler
{
    public static RevocationVerificationResult Handle(VerifyAgainstRevocationsQuery query)
    {
        var bundle = query.Bundle;
        var registry = query.Registry;
        var checks = new List<RevocationCheckResult>();
        var warnings = new List<string>();

        // Check claim signature
        var claimPublicKey = Ed25519PublicKey.Parse(bundle.Researcher.PublicKey);
        var claimSignedAt = DateTimeOffset.Parse(bundle.Claim.AssertedAtUtc, CultureInfo.InvariantCulture);

        var claimCheck = CheckSignature(
            RevocationCheckResult.SignatureTypes.Claim,
            bundle.Researcher.ResearcherId,
            claimPublicKey,
            claimSignedAt,
            registry);
        checks.Add(claimCheck);

        // Check citation signatures
        if (bundle.Citations != null)
        {
            foreach (var citation in bundle.Citations)
            {
                var citationSignedAt = DateTimeOffset.Parse(citation.IssuedAtUtc, CultureInfo.InvariantCulture);

                // Citations are signed by the claim author
                var citationCheck = CheckSignature(
                    RevocationCheckResult.SignatureTypes.Citation,
                    bundle.Researcher.ResearcherId,
                    claimPublicKey,
                    citationSignedAt,
                    registry);
                checks.Add(citationCheck);
            }
        }

        // Check attestation signatures
        if (bundle.Attestations != null)
        {
            foreach (var attestation in bundle.Attestations)
            {
                var attestorPublicKey = Ed25519PublicKey.Parse(attestation.Attestor.PublicKey);
                var attestationSignedAt = DateTimeOffset.Parse(attestation.IssuedAtUtc, CultureInfo.InvariantCulture);

                var attestationCheck = CheckSignature(
                    RevocationCheckResult.SignatureTypes.Attestation,
                    attestation.Attestor.ResearcherId,
                    attestorPublicKey,
                    attestationSignedAt,
                    registry);
                checks.Add(attestationCheck);
            }
        }

        var revokedChecks = checks.Where(c => c.IsRevoked).ToList();

        bool isValid;
        if (query.StrictMode)
        {
            // Strict mode: any revoked signature = failure
            isValid = revokedChecks.Count == 0;
        }
        else
        {
            // Non-strict mode: warn but don't fail
            isValid = true;
            foreach (var revoked in revokedChecks)
            {
                warnings.Add($"{revoked.SignatureType} signer key was revoked at {revoked.RevokedAtUtc} ({revoked.RevocationReason})");
            }
        }

        return new RevocationVerificationResult
        {
            IsValid = isValid,
            Checks = checks,
            Warnings = warnings
        };
    }

    private static RevocationCheckResult CheckSignature(
        string signatureType,
        string signerId,
        Ed25519PublicKey signerPublicKey,
        DateTimeOffset signedAtUtc,
        RevocationRegistry registry)
    {
        var earliest = registry.GetEarliestRevocation(signerPublicKey);
        var isRevoked = earliest != null && earliest.Invalidates(signedAtUtc);

        return new RevocationCheckResult
        {
            SignatureType = signatureType,
            SignerId = signerId,
            SignerPublicKey = signerPublicKey.ToString(),
            SignedAtUtc = signedAtUtc.ToString("O"),
            IsRevoked = isRevoked,
            RevokedAtUtc = isRevoked ? earliest!.RevokedAtUtc.ToString("O") : null,
            RevocationReason = isRevoked ? earliest!.Reason : null
        };
    }
}
