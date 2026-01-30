using System.Text.Json.Serialization;

namespace ClaimLedger.Domain.Attestations;

/// <summary>
/// FROZEN CONTRACT: AttestationSignable.v1
///
/// This DTO defines the exact bytes that get signed for an attestation.
/// Any change requires incrementing to AttestationSignable.v2.
///
/// The claim_core_digest binds this attestation to a specific claim bundle
/// (computed from canonical JSON of claim + evidence, excluding attestations).
/// </summary>
public sealed class AttestationSignable
{
    [JsonPropertyOrder(0)]
    public string Contract { get; init; } = "AttestationSignable.v1";

    [JsonPropertyOrder(1)]
    public required string AttestationId { get; init; }

    [JsonPropertyOrder(2)]
    public required string ClaimCoreDigest { get; init; }

    [JsonPropertyOrder(3)]
    public required AttestorIdentity Attestor { get; init; }

    [JsonPropertyOrder(4)]
    public required string AttestationType { get; init; }

    [JsonPropertyOrder(5)]
    public required string Statement { get; init; }

    [JsonPropertyOrder(6)]
    public required string IssuedAtUtc { get; init; }

    [JsonPropertyOrder(7)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ExpiresAtUtc { get; init; }

    [JsonPropertyOrder(8)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AttestationPolicy? Policy { get; init; }
}

/// <summary>
/// Attestor identity as included in the signable contract.
/// </summary>
public sealed class AttestorIdentity
{
    [JsonPropertyOrder(0)]
    public required string ResearcherId { get; init; }

    [JsonPropertyOrder(1)]
    public required string PublicKey { get; init; }

    [JsonPropertyOrder(2)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DisplayName { get; init; }
}

/// <summary>
/// Policy constraints for attestations (future extension point).
/// Empty for Phase 2.
/// </summary>
public sealed class AttestationPolicy
{
    // Reserved for future use
}
