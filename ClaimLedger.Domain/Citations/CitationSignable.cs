using System.Text.Json.Serialization;

namespace ClaimLedger.Domain.Citations;

/// <summary>
/// Frozen signable contract for claim citations.
/// Version: ClaimCitation.v1
///
/// FROZEN: Any change to field names, order, or semantics requires a version bump to ClaimCitation.v2.
/// The canonical JSON of this object is what gets signed.
/// </summary>
public sealed class CitationSignable
{
    /// <summary>
    /// Contract version identifier. Always "ClaimCitation.v1" for this version.
    /// </summary>
    [JsonPropertyOrder(0)]
    [JsonPropertyName("contract")]
    public string Contract { get; init; } = "ClaimCitation.v1";

    /// <summary>
    /// Unique identifier for this citation.
    /// </summary>
    [JsonPropertyOrder(1)]
    [JsonPropertyName("citation_id")]
    public required string CitationId { get; init; }

    /// <summary>
    /// The claim_core_digest of the cited claim (hex SHA-256).
    /// </summary>
    [JsonPropertyOrder(2)]
    [JsonPropertyName("cited_claim_core_digest")]
    public required string CitedClaimCoreDigest { get; init; }

    /// <summary>
    /// The relationship between the citing claim and the cited claim.
    /// </summary>
    [JsonPropertyOrder(3)]
    [JsonPropertyName("relation")]
    public required string Relation { get; init; }

    /// <summary>
    /// Optional locator for the cited claim (filename, URL, DOI, etc.).
    /// Verifier never fetches this - it's informational only.
    /// </summary>
    [JsonPropertyOrder(4)]
    [JsonPropertyName("locator")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Locator { get; init; }

    /// <summary>
    /// Optional notes about this citation.
    /// </summary>
    [JsonPropertyOrder(5)]
    [JsonPropertyName("notes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Notes { get; init; }

    /// <summary>
    /// When this citation was created (RFC 3339 UTC).
    /// </summary>
    [JsonPropertyOrder(6)]
    [JsonPropertyName("issued_at")]
    public required string IssuedAt { get; init; }
}
