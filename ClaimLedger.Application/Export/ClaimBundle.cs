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

    /// <summary>
    /// Citations to other claims (Phase 3).
    /// Part of claim_core_digest - cannot be modified after signing.
    /// Can be absent or empty for Phase 1/2 bundles.
    /// </summary>
    [JsonPropertyOrder(4)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<CitationInfo>? Citations { get; init; }

    /// <summary>
    /// Attestations about this claim (Phase 2).
    /// Can be absent or empty for Phase 1 bundles.
    /// NOT part of claim_core_digest - append-only.
    /// </summary>
    [JsonPropertyOrder(5)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<AttestationInfo>? Attestations { get; init; }
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

/// <summary>
/// Citation information in the bundle.
/// Citations are part of claim_core_digest and cannot be modified after signing.
/// </summary>
public sealed class CitationInfo
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

    /// <summary>
    /// Optional embedded cited claim bundle for offline verification.
    /// Not part of the citation signature - purely for convenience.
    /// </summary>
    [JsonPropertyOrder(7)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ClaimBundle? Embedded { get; init; }
}

/// <summary>
/// Attestation information in the bundle.
/// </summary>
public sealed class AttestationInfo
{
    [JsonPropertyOrder(0)]
    public required string AttestationId { get; init; }

    [JsonPropertyOrder(1)]
    public required string ClaimCoreDigest { get; init; }

    [JsonPropertyOrder(2)]
    public required AttestorInfo Attestor { get; init; }

    [JsonPropertyOrder(3)]
    public required string AttestationType { get; init; }

    [JsonPropertyOrder(4)]
    public required string Statement { get; init; }

    [JsonPropertyOrder(5)]
    public required string IssuedAtUtc { get; init; }

    [JsonPropertyOrder(6)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ExpiresAtUtc { get; init; }

    [JsonPropertyOrder(7)]
    public required string Signature { get; init; }
}

/// <summary>
/// Attestor identity in the bundle.
/// </summary>
public sealed class AttestorInfo
{
    [JsonPropertyOrder(0)]
    public required string ResearcherId { get; init; }

    [JsonPropertyOrder(1)]
    public required string PublicKey { get; init; }

    [JsonPropertyOrder(2)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DisplayName { get; init; }
}
