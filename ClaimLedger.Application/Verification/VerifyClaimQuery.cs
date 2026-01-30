using ClaimLedger.Domain.Claims;
using Shared.Crypto;

namespace ClaimLedger.Application.Verification;

/// <summary>
/// Query to verify a claim's cryptographic validity.
/// </summary>
public sealed record VerifyClaimQuery(ClaimAssertion Claim);

/// <summary>
/// Handles verification of claim assertions.
/// </summary>
public sealed class VerifyClaimHandler
{
    /// <summary>
    /// Verifies the cryptographic validity of a claim.
    ///
    /// Checks:
    /// 1. Signature is valid for the signable bytes
    /// 2. Public key is structurally valid
    /// 3. Signable reconstructs exactly
    ///
    /// Does NOT evaluate truth or correctness of the claim.
    /// </summary>
    public static VerificationResult Handle(VerifyClaimQuery query)
    {
        var claim = query.Claim;

        // Build signable and verify signature
        var signable = claim.ToSignable();

        // Verify version
        if (signable.Version != "claim.v1")
        {
            return VerificationResult.Invalid(VerificationResult.Reasons.VersionUnsupported);
        }

        // Verify signature
        var bytes = CanonicalJson.SerializeToBytes(signable);
        var isValid = claim.ResearcherPublicKey.Verify(bytes, claim.Signature);

        if (!isValid)
        {
            return VerificationResult.Invalid(VerificationResult.Reasons.SignatureInvalid);
        }

        // Check for any warnings
        var warnings = new List<string>();

        if (claim.Evidence.Count == 0)
        {
            warnings.Add("Claim has no evidence references");
        }

        return VerificationResult.Valid(warnings);
    }
}
