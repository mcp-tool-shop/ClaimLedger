using System.Text.Json.Serialization;

namespace ClaimLedger.Application.Export;

/// <summary>
/// Self-contained bundle for verifying a claim without a database.
/// Version: claim-bundle.v1
/// </summary>
public sealed class ClaimBundle
{
    [JsonPropertyOrder(0)]
    public string Version { get; init; } = "claim-bundle.v1";

    [JsonPropertyOrder(1)]
    public required AlgorithmsInfo Algorithms { get; init; }

    [JsonPropertyOrder(2)]
    public required ClaimInfo Claim { get; init; }

    [JsonPropertyOrder(3)]
    public required ResearcherInfo Researcher { get; init; }
}

/// <summary>
/// Algorithm declarations for the bundle.
/// </summary>
public sealed class AlgorithmsInfo
{
    [JsonPropertyOrder(0)]
    public string Signature { get; init; } = "Ed25519";

    [JsonPropertyOrder(1)]
    public string Hash { get; init; } = "SHA-256";

    [JsonPropertyOrder(2)]
    public string Encoding { get; init; } = "UTF-8";
}

/// <summary>
/// Claim information in the bundle.
/// </summary>
public sealed class ClaimInfo
{
    [JsonPropertyOrder(0)]
    public required string ClaimId { get; init; }

    [JsonPropertyOrder(1)]
    public required string Statement { get; init; }

    [JsonPropertyOrder(2)]
    public required string AssertedAtUtc { get; init; }

    [JsonPropertyOrder(3)]
    public required IReadOnlyList<EvidenceInfo> Evidence { get; init; }

    [JsonPropertyOrder(4)]
    public required string Signature { get; init; }
}

/// <summary>
/// Evidence reference in the bundle.
/// </summary>
public sealed class EvidenceInfo
{
    [JsonPropertyOrder(0)]
    public required string Type { get; init; }

    [JsonPropertyOrder(1)]
    public required string Hash { get; init; }

    [JsonPropertyOrder(2)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Locator { get; init; }
}

/// <summary>
/// Researcher information in the bundle.
/// </summary>
public sealed class ResearcherInfo
{
    [JsonPropertyOrder(0)]
    public required string ResearcherId { get; init; }

    [JsonPropertyOrder(1)]
    public required string PublicKey { get; init; }

    [JsonPropertyOrder(2)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DisplayName { get; init; }
}
