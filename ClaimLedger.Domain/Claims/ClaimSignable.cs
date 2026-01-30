using System.Text.Json.Serialization;

namespace ClaimLedger.Domain.Claims;

/// <summary>
/// FROZEN CONTRACT: claim.v1
///
/// This DTO defines the exact bytes that get signed.
/// Any change requires incrementing to claim.v2.
///
/// Rules:
/// - Canonical JSON only (via Shared.Crypto.CanonicalJson)
/// - Field order is explicit via JsonPropertyOrder
/// - UTF-8 encoding, no whitespace
/// - All fields required for signing included
/// </summary>
public sealed class ClaimSignable
{
    [JsonPropertyOrder(0)]
    public string Version { get; init; } = "claim.v1";

    [JsonPropertyOrder(1)]
    public required string ClaimId { get; init; }

    [JsonPropertyOrder(2)]
    public required string Statement { get; init; }

    [JsonPropertyOrder(3)]
    public required string ResearcherId { get; init; }

    [JsonPropertyOrder(4)]
    public required string ResearcherPublicKey { get; init; }

    [JsonPropertyOrder(5)]
    public required IReadOnlyList<EvidenceSignable> Evidence { get; init; }

    [JsonPropertyOrder(6)]
    public required string AssertedAtUtc { get; init; }
}

/// <summary>
/// Evidence reference as included in the signable contract.
/// </summary>
public sealed class EvidenceSignable
{
    [JsonPropertyOrder(0)]
    public required string Type { get; init; }

    [JsonPropertyOrder(1)]
    public required string Hash { get; init; }

    [JsonPropertyOrder(2)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Locator { get; init; }
}
