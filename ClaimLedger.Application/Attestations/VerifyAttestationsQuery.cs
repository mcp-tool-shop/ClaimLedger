using ClaimLedger.Application.Export;
using ClaimLedger.Application.Primitives;
using ClaimLedger.Domain.Attestations;
using Shared.Crypto;

namespace ClaimLedger.Application.Attestations;

/// <summary>
/// Query to verify all attestations in a claim bundle.
/// </summary>
public sealed record VerifyAttestationsQuery(ClaimBundle Bundle, DateTimeOffset AsOf);

/// <summary>
/// Result of attestation verification.
/// </summary>
public sealed class AttestationVerificationResult
{
    public bool AllValid { get; }
    public IReadOnlyList<AttestationCheckResult> Results { get; }

    private AttestationVerificationResult(bool allValid, IReadOnlyList<AttestationCheckResult> results)
    {
        AllValid = allValid;
        Results = results;
    }

    public static AttestationVerificationResult Success(IReadOnlyList<AttestationCheckResult> results)
        => new(true, results);

    public static AttestationVerificationResult Failure(IReadOnlyList<AttestationCheckResult> results)
        => new(false, results);

    public static AttestationVerificationResult NoAttestations()
        => new(true, Array.Empty<AttestationCheckResult>());
}

/// <summary>
/// Result of checking a single attestation.
/// </summary>
public sealed class AttestationCheckResult
{
    public string AttestationId { get; }
    public bool IsValid { get; }
    public string? FailureReason { get; }
    public bool IsExpired { get; }

    private AttestationCheckResult(string attestationId, bool isValid, string? failureReason, bool isExpired)
    {
        AttestationId = attestationId;
        IsValid = isValid;
        FailureReason = failureReason;
        IsExpired = isExpired;
    }

    public static AttestationCheckResult Valid(string attestationId, bool isExpired = false)
        => new(attestationId, true, null, isExpired);

    public static AttestationCheckResult Invalid(string attestationId, string reason)
        => new(attestationId, false, reason, false);

    public static class Reasons
    {
        public const string SignatureInvalid = "Signature verification failed";
        public const string DigestMismatch = "claim_core_digest does not match bundle";
        public const string InvalidPublicKey = "Invalid attestor public key";
        public const string InvalidSignature = "Invalid signature format";
        public const string Expired = "Attestation has expired";
        public const string InvalidType = "Invalid attestation type";
    }
}

/// <summary>
/// Handles verification of attestations.
/// </summary>
public sealed class VerifyAttestationsHandler
{
    /// <summary>
    /// Verifies all attestations in a claim bundle.
    ///
    /// For each attestation:
    /// 1. Recompute claim_core_digest from bundle
    /// 2. Check attestation.claim_core_digest matches
    /// 3. Verify attestor signature (Ed25519)
    /// 4. Check expiration if present
    ///
    /// No network calls. No trust ranking. Just validity.
    /// </summary>
    public static AttestationVerificationResult Handle(VerifyAttestationsQuery query)
    {
        var bundle = query.Bundle;

        // No attestations = valid (Phase 1 compatibility)
        if (bundle.Attestations == null || bundle.Attestations.Count == 0)
        {
            return AttestationVerificationResult.NoAttestations();
        }

        // Compute expected claim_core_digest
        var expectedDigest = ClaimCoreDigest.Compute(bundle);
        var results = new List<AttestationCheckResult>();
        var allValid = true;

        foreach (var attestation in bundle.Attestations)
        {
            var result = VerifyAttestation(attestation, expectedDigest, query.AsOf);
            results.Add(result);

            if (!result.IsValid)
            {
                allValid = false;
            }
        }

        return allValid
            ? AttestationVerificationResult.Success(results)
            : AttestationVerificationResult.Failure(results);
    }

    private static AttestationCheckResult VerifyAttestation(
        AttestationInfo attestation,
        Digest256 expectedDigest,
        DateTimeOffset asOf)
    {
        // Check attestation type
        if (!AttestationType.IsValid(attestation.AttestationType))
        {
            return AttestationCheckResult.Invalid(
                attestation.AttestationId,
                AttestationCheckResult.Reasons.InvalidType);
        }

        // Check claim_core_digest matches
        if (attestation.ClaimCoreDigest != expectedDigest.ToString())
        {
            return AttestationCheckResult.Invalid(
                attestation.AttestationId,
                AttestationCheckResult.Reasons.DigestMismatch);
        }

        // Parse public key
        Ed25519PublicKey publicKey;
        try
        {
            publicKey = Ed25519PublicKey.Parse(attestation.Attestor.PublicKey);
        }
        catch
        {
            return AttestationCheckResult.Invalid(
                attestation.AttestationId,
                AttestationCheckResult.Reasons.InvalidPublicKey);
        }

        // Parse signature
        Ed25519Signature signature;
        try
        {
            signature = Ed25519Signature.Parse(attestation.Signature);
        }
        catch
        {
            return AttestationCheckResult.Invalid(
                attestation.AttestationId,
                AttestationCheckResult.Reasons.InvalidSignature);
        }

        // Build signable for verification
        var signable = new AttestationSignable
        {
            Contract = "AttestationSignable.v1",
            AttestationId = attestation.AttestationId,
            ClaimCoreDigest = attestation.ClaimCoreDigest,
            Attestor = new AttestorIdentity
            {
                ResearcherId = attestation.Attestor.ResearcherId,
                PublicKey = attestation.Attestor.PublicKey,
                DisplayName = attestation.Attestor.DisplayName
            },
            AttestationType = attestation.AttestationType,
            Statement = attestation.Statement,
            IssuedAtUtc = attestation.IssuedAtUtc,
            ExpiresAtUtc = attestation.ExpiresAtUtc,
            Policy = null
        };

        // Verify signature
        var bytes = CanonicalJson.SerializeToBytes(signable);
        if (!publicKey.Verify(bytes, signature))
        {
            return AttestationCheckResult.Invalid(
                attestation.AttestationId,
                AttestationCheckResult.Reasons.SignatureInvalid);
        }

        // Check expiration
        var isExpired = false;
        if (!string.IsNullOrEmpty(attestation.ExpiresAtUtc))
        {
            if (DateTimeOffset.TryParse(attestation.ExpiresAtUtc, out var expiresAt))
            {
                isExpired = expiresAt <= asOf;
                if (isExpired)
                {
                    return AttestationCheckResult.Invalid(
                        attestation.AttestationId,
                        AttestationCheckResult.Reasons.Expired);
                }
            }
        }

        return AttestationCheckResult.Valid(attestation.AttestationId, isExpired);
    }
}
