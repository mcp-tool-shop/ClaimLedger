using System.Text.Json.Serialization;

namespace ClaimLedger.Application.Revocations;

/// <summary>
/// Self-contained bundle for verifying a key revocation without a database.
/// Version: revocation-bundle.v1
/// </summary>
public sealed class RevocationBundle
{
    [JsonPropertyOrder(0)]
    public string Version { get; init; } = "revocation-bundle.v1";

    [JsonPropertyOrder(1)]
    public required RevocationInfo Revocation { get; init; }

    [JsonPropertyOrder(2)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IdentityInfo? Identity { get; init; }
}

/// <summary>
/// Revocation information in the bundle.
/// </summary>
public sealed class RevocationInfo
{
    [JsonPropertyOrder(0)]
    public required string RevocationId { get; init; }

    [JsonPropertyOrder(1)]
    public required string ResearcherId { get; init; }

    [JsonPropertyOrder(2)]
    public required string RevokedPublicKey { get; init; }

    [JsonPropertyOrder(3)]
    public required string RevokedAtUtc { get; init; }

    [JsonPropertyOrder(4)]
    public required string Reason { get; init; }

    [JsonPropertyOrder(5)]
    public required string IssuerMode { get; init; }

    [JsonPropertyOrder(6)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SuccessorPublicKey { get; init; }

    [JsonPropertyOrder(7)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Notes { get; init; }

    [JsonPropertyOrder(8)]
    public required string Signature { get; init; }
}

/// <summary>
/// Identity information in the revocation bundle.
/// </summary>
public sealed class IdentityInfo
{
    [JsonPropertyOrder(0)]
    public required string ResearcherId { get; init; }

    [JsonPropertyOrder(1)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DisplayName { get; init; }
}
