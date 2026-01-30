using System.Text.Json.Serialization;

namespace ClaimLedger.Domain.Revocations;

/// <summary>
/// Frozen signable contract for key revocations.
/// Version: IdentityRevocation.v1
///
/// FROZEN: Any change to field names, order, or semantics requires a version bump to IdentityRevocation.v2.
/// The canonical JSON of this object is what gets signed.
/// </summary>
public sealed class RevocationSignable
{
    /// <summary>
    /// Contract version identifier. Always "IdentityRevocation.v1" for this version.
    /// </summary>
    [JsonPropertyOrder(0)]
    [JsonPropertyName("contract")]
    public string Contract { get; init; } = "IdentityRevocation.v1";

    /// <summary>
    /// Unique identifier for this revocation.
    /// </summary>
    [JsonPropertyOrder(1)]
    [JsonPropertyName("revocation_id")]
    public required string RevocationId { get; init; }

    /// <summary>
    /// The identity whose key is being revoked.
    /// </summary>
    [JsonPropertyOrder(2)]
    [JsonPropertyName("researcher_id")]
    public required string ResearcherId { get; init; }

    /// <summary>
    /// The specific public key being revoked (ed25519:base64).
    /// </summary>
    [JsonPropertyOrder(3)]
    [JsonPropertyName("revoked_public_key")]
    public required string RevokedPublicKey { get; init; }

    /// <summary>
    /// Effective revocation time (RFC 3339 UTC).
    /// Claims signed at or after this time are invalid.
    /// </summary>
    [JsonPropertyOrder(4)]
    [JsonPropertyName("revoked_at")]
    public required string RevokedAt { get; init; }

    /// <summary>
    /// Why the key is being revoked.
    /// </summary>
    [JsonPropertyOrder(5)]
    [JsonPropertyName("reason")]
    public required string Reason { get; init; }

    /// <summary>
    /// Who signed this revocation: SELF or SUCCESSOR.
    /// </summary>
    [JsonPropertyOrder(6)]
    [JsonPropertyName("issuer_mode")]
    public required string IssuerMode { get; init; }

    /// <summary>
    /// The new public key that replaces this one (ed25519:base64).
    /// Required if issuer_mode == SUCCESSOR. Optional otherwise.
    /// </summary>
    [JsonPropertyOrder(7)]
    [JsonPropertyName("successor_public_key")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SuccessorPublicKey { get; init; }

    /// <summary>
    /// Optional notes about this revocation.
    /// </summary>
    [JsonPropertyOrder(8)]
    [JsonPropertyName("notes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Notes { get; init; }
}
