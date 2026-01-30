using System.Text.Json.Serialization;

namespace ClaimLedger.Domain.Registry;

/// <summary>
/// Local registry index for offline resolution of claims and bundles.
/// Contract: ClaimRegistryIndex.v1
/// </summary>
public sealed class ClaimRegistryIndex
{
    public const string ContractVersion = "ClaimRegistryIndex.v1";

    [JsonPropertyOrder(0)]
    public string Contract { get; init; } = ContractVersion;

    [JsonPropertyOrder(1)]
    public required string RegistryId { get; init; }

    [JsonPropertyOrder(2)]
    public required string CreatedAt { get; init; }

    [JsonPropertyOrder(3)]
    public required string UpdatedAt { get; set; }

    [JsonPropertyOrder(4)]
    public List<PackEntry> Packs { get; set; } = new();

    /// <summary>
    /// Maps claim_core_digest (hex) to pack locations.
    /// </summary>
    [JsonPropertyOrder(5)]
    public Dictionary<string, List<ClaimLocation>> Claims { get; init; } = new();

    /// <summary>
    /// Maps CreatorLedger bundle_digest (hex) to pack locations.
    /// </summary>
    [JsonPropertyOrder(6)]
    public Dictionary<string, List<BundleLocation>> CreatorLedgerBundles { get; init; } = new();
}

/// <summary>
/// Entry for an indexed pack.
/// </summary>
public sealed class PackEntry
{
    [JsonPropertyOrder(0)]
    public required string PackId { get; init; }

    /// <summary>
    /// Path to the pack (relative to registry or absolute).
    /// </summary>
    [JsonPropertyOrder(1)]
    public required string Path { get; init; }

    [JsonPropertyOrder(2)]
    public required PackKind Kind { get; init; }

    [JsonPropertyOrder(3)]
    public required string RootClaimCoreDigest { get; init; }

    [JsonPropertyOrder(4)]
    public required string ManifestSha256Hex { get; init; }

    [JsonPropertyOrder(5)]
    public required bool ManifestSigned { get; init; }

    [JsonPropertyOrder(6)]
    public required bool HasClaimsDir { get; init; }

    [JsonPropertyOrder(7)]
    public required bool HasCreatorLedgerDir { get; init; }

    [JsonPropertyOrder(8)]
    public required bool HasRevocationsDir { get; init; }

    [JsonPropertyOrder(9)]
    public required bool HasTsaTrustDir { get; init; }

    /// <summary>
    /// Hash of the sorted file inventory for quick staleness detection.
    /// </summary>
    [JsonPropertyOrder(10)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FileInventorySha256Hex { get; init; }

    /// <summary>
    /// When this pack was added to the registry.
    /// </summary>
    [JsonPropertyOrder(11)]
    public required string AddedAt { get; init; }
}

/// <summary>
/// Kind of pack storage.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum PackKind
{
    Directory,
    Zip
}

/// <summary>
/// Location of a claim within a pack.
/// </summary>
public sealed class ClaimLocation
{
    [JsonPropertyOrder(0)]
    public required string PackId { get; init; }

    [JsonPropertyOrder(1)]
    public required string RelativePath { get; init; }
}

/// <summary>
/// Location of a CreatorLedger bundle within a pack.
/// </summary>
public sealed class BundleLocation
{
    [JsonPropertyOrder(0)]
    public required string PackId { get; init; }

    [JsonPropertyOrder(1)]
    public required string RelativePath { get; init; }
}
