using System.Text.Json.Serialization;
using Shared.Crypto;

namespace ClaimLedger.Application.Export;

/// <summary>
/// Computes the claim_core_digest from a claim bundle.
///
/// DEFINITION (frozen, Phase 3):
/// The digest is SHA-256 of the canonical JSON of { Claim, Citations }
/// where:
/// - Claim includes the claim signature
/// - Citations are sorted by cited_claim_core_digest then citation_id
/// - Attestations are EXCLUDED (append-only)
///
/// Missing citations are treated as empty array for backwards compatibility.
/// </summary>
public static class ClaimCoreDigest
{
    /// <summary>
    /// Computes the claim_core_digest from a full bundle.
    /// Includes citations (sorted), excludes attestations.
    /// </summary>
    public static Digest256 Compute(ClaimBundle bundle)
    {
        // Sort citations for deterministic ordering
        var sortedCitations = GetSortedCitations(bundle.Citations);

        var core = new ClaimCore
        {
            Claim = bundle.Claim,
            Citations = sortedCitations
        };

        return CanonicalJson.HashOf(core);
    }

    /// <summary>
    /// Computes the claim_core_digest from claim info with citations.
    /// </summary>
    public static Digest256 Compute(ClaimInfo claim, IReadOnlyList<CitationCoreInfo>? citations = null)
    {
        var sortedCitations = citations != null
            ? citations.OrderBy(c => c.CitedClaimCoreDigest).ThenBy(c => c.CitationId).ToList()
            : new List<CitationCoreInfo>();

        var core = new ClaimCore
        {
            Claim = claim,
            Citations = sortedCitations
        };

        return CanonicalJson.HashOf(core);
    }

    private static List<CitationCoreInfo> GetSortedCitations(IReadOnlyList<CitationInfo>? citations)
    {
        if (citations == null || citations.Count == 0)
            return new List<CitationCoreInfo>();

        return citations
            .Select(c => new CitationCoreInfo
            {
                CitationId = c.CitationId,
                CitedClaimCoreDigest = c.CitedClaimCoreDigest,
                Relation = c.Relation,
                Locator = c.Locator,
                Notes = c.Notes,
                IssuedAtUtc = c.IssuedAtUtc,
                Signature = c.Signature
            })
            .OrderBy(c => c.CitedClaimCoreDigest)
            .ThenBy(c => c.CitationId)
            .ToList();
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

    /// <summary>
    /// Citations sorted by cited_claim_core_digest then citation_id.
    /// Empty array for Phase 1/2 bundles (backwards compatible).
    /// </summary>
    [JsonPropertyOrder(1)]
    public required List<CitationCoreInfo> Citations { get; init; }
}

/// <summary>
/// Citation info included in claim_core_digest computation.
/// Excludes the optional Embedded field since that's not part of the signature.
/// </summary>
public sealed class CitationCoreInfo
{
    [JsonPropertyOrder(0)]
    public required string CitationId { get; init; }

    [JsonPropertyOrder(1)]
    public required string CitedClaimCoreDigest { get; init; }

    [JsonPropertyOrder(2)]
    public required string Relation { get; init; }

    [JsonPropertyOrder(3)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Locator { get; init; }

    [JsonPropertyOrder(4)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Notes { get; init; }

    [JsonPropertyOrder(5)]
    public required string IssuedAtUtc { get; init; }

    [JsonPropertyOrder(6)]
    public required string Signature { get; init; }
}
