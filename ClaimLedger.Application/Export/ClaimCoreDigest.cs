using System.Text.Json.Serialization;
using Shared.Crypto;

namespace ClaimLedger.Application.Export;

/// <summary>
/// Computes the claim_core_digest from a claim bundle.
///
/// DEFINITION (frozen):
/// The digest is SHA-256 of the canonical JSON of { Claim, Evidence }
/// with attestations EXCLUDED.
///
/// This allows attestations to be appended/removed without changing
/// what they're attesting to.
/// </summary>
public static class ClaimCoreDigest
{
    /// <summary>
    /// Computes the claim_core_digest from a full bundle.
    /// Excludes attestations from the digest computation.
    /// </summary>
    public static Digest256 Compute(ClaimBundle bundle)
    {
        var core = new ClaimCore
        {
            Claim = bundle.Claim
        };

        return CanonicalJson.HashOf(core);
    }

    /// <summary>
    /// Computes the claim_core_digest from claim info directly.
    /// </summary>
    public static Digest256 Compute(ClaimInfo claim)
    {
        var core = new ClaimCore
        {
            Claim = claim
        };

        return CanonicalJson.HashOf(core);
    }
}

/// <summary>
/// The "core" of a claim bundle that attestations bind to.
/// This structure is hashed to produce claim_core_digest.
/// </summary>
internal sealed class ClaimCore
{
    [JsonPropertyOrder(0)]
    public required ClaimInfo Claim { get; init; }
}
