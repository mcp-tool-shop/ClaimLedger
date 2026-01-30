using System.Text.Json.Serialization;

namespace ClaimLedger.Domain.Packs;

/// <summary>
/// ClaimPack manifest - the integrity and routing index.
/// CONTRACT: ClaimPackManifest.v1 (frozen)
/// </summary>
public sealed class ClaimPackManifest
{
    /// <summary>
    /// Contract version. Frozen.
    /// </summary>
    public const string ContractVersion = "ClaimPackManifest.v1";

    [JsonPropertyOrder(0)]
    public string Contract { get; init; } = ContractVersion;

    /// <summary>
    /// Unique identifier for this pack.
    /// </summary>
    [JsonPropertyOrder(1)]
    public required string PackId { get; init; }

    /// <summary>
    /// When the pack was created.
    /// </summary>
    [JsonPropertyOrder(2)]
    public required string CreatedAt { get; init; }

    /// <summary>
    /// Path to the root claim bundle (always "claim.json").
    /// </summary>
    [JsonPropertyOrder(3)]
    public string RootClaimPath { get; init; } = "claim.json";

    /// <summary>
    /// The claim_core_digest of the root claim.
    /// Used to verify root claim integrity.
    /// </summary>
    [JsonPropertyOrder(4)]
    public required string RootClaimCoreDigest { get; init; }

    /// <summary>
    /// Directory configuration for pack contents.
    /// </summary>
    [JsonPropertyOrder(5)]
    public required PackIncludeConfig Include { get; init; }

    /// <summary>
    /// Complete inventory of files in the pack.
    /// </summary>
    [JsonPropertyOrder(6)]
    public required IReadOnlyList<PackFileEntry> Files { get; init; }

    /// <summary>
    /// Manifest signatures (append-only, optional).
    /// </summary>
    [JsonPropertyOrder(7)]
    [JsonPropertyName("manifest_signatures")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<ManifestSignatureEntry>? ManifestSignatures { get; init; }
}

/// <summary>
/// Directory configuration for pack contents.
/// </summary>
public sealed record PackIncludeConfig
{
    [JsonPropertyOrder(0)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClaimsDir { get; init; }

    [JsonPropertyOrder(1)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EvidenceDir { get; init; }

    [JsonPropertyOrder(2)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RevocationsDir { get; init; }

    [JsonPropertyOrder(3)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TsaTrustDir { get; init; }

    /// <summary>
    /// Directory containing CreatorLedger proof bundles (Phase 10).
    /// </summary>
    [JsonPropertyOrder(4)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CreatorLedgerDir { get; init; }
}

/// <summary>
/// A file entry in the pack manifest.
/// </summary>
public sealed class PackFileEntry
{
    /// <summary>
    /// Relative path from pack root (forward slashes).
    /// </summary>
    [JsonPropertyOrder(0)]
    public required string Path { get; init; }

    /// <summary>
    /// MIME type of the file.
    /// </summary>
    [JsonPropertyOrder(1)]
    public required string MediaType { get; init; }

    /// <summary>
    /// SHA-256 hash of the file contents (hex).
    /// </summary>
    [JsonPropertyOrder(2)]
    public required string Sha256Hex { get; init; }

    /// <summary>
    /// Size of the file in bytes.
    /// </summary>
    [JsonPropertyOrder(3)]
    public required long SizeBytes { get; init; }
}

/// <summary>
/// Signable view of the manifest for container authenticity.
/// CONTRACT: ClaimPackManifestSignable.v1 (frozen)
/// </summary>
public sealed class ClaimPackManifestSignable
{
    /// <summary>
    /// Contract version. Frozen.
    /// </summary>
    public const string ContractVersion = "ClaimPackManifestSignable.v1";

    [JsonPropertyOrder(0)]
    [JsonPropertyName("contract")]
    public string Contract { get; init; } = ContractVersion;

    /// <summary>
    /// SHA-256 of the canonical manifest JSON (excluding manifest_signatures).
    /// </summary>
    [JsonPropertyOrder(1)]
    [JsonPropertyName("manifest_sha256_hex")]
    public required string ManifestSha256Hex { get; init; }

    /// <summary>
    /// Pack identifier (from manifest).
    /// </summary>
    [JsonPropertyOrder(2)]
    [JsonPropertyName("pack_id")]
    public required string PackId { get; init; }

    /// <summary>
    /// Root claim digest (from manifest).
    /// </summary>
    [JsonPropertyOrder(3)]
    [JsonPropertyName("root_claim_core_digest")]
    public required string RootClaimCoreDigest { get; init; }

    /// <summary>
    /// When the manifest was created.
    /// </summary>
    [JsonPropertyOrder(4)]
    [JsonPropertyName("created_at")]
    public required string CreatedAt { get; init; }
}

/// <summary>
/// A manifest signature entry.
/// </summary>
public sealed class ManifestSignatureEntry
{
    /// <summary>
    /// The signable content that was signed.
    /// </summary>
    [JsonPropertyOrder(0)]
    [JsonPropertyName("signable")]
    public required ClaimPackManifestSignable Signable { get; init; }

    /// <summary>
    /// The cryptographic signature.
    /// </summary>
    [JsonPropertyOrder(1)]
    [JsonPropertyName("signature")]
    public required ManifestSignature Signature { get; init; }

    /// <summary>
    /// Information about the signer.
    /// </summary>
    [JsonPropertyOrder(2)]
    [JsonPropertyName("signer")]
    public required ManifestSigner Signer { get; init; }
}

/// <summary>
/// Cryptographic signature on the manifest.
/// </summary>
public sealed class ManifestSignature
{
    [JsonPropertyOrder(0)]
    [JsonPropertyName("alg")]
    public string Algorithm { get; init; } = "Ed25519";

    [JsonPropertyOrder(1)]
    [JsonPropertyName("public_key")]
    public required string PublicKey { get; init; }

    [JsonPropertyOrder(2)]
    [JsonPropertyName("sig")]
    public required string Sig { get; init; }
}

/// <summary>
/// Information about the manifest signer.
/// </summary>
public sealed class ManifestSigner
{
    /// <summary>
    /// Kind of signer.
    /// </summary>
    [JsonPropertyOrder(0)]
    [JsonPropertyName("kind")]
    public required string Kind { get; init; }

    /// <summary>
    /// Signer identity information.
    /// </summary>
    [JsonPropertyOrder(1)]
    [JsonPropertyName("identity")]
    public required ManifestSignerIdentity Identity { get; init; }
}

/// <summary>
/// Signer identity in manifest signature.
/// </summary>
public sealed class ManifestSignerIdentity
{
    [JsonPropertyOrder(0)]
    [JsonPropertyName("researcher_id")]
    public required string ResearcherId { get; init; }

    [JsonPropertyOrder(1)]
    [JsonPropertyName("display_name")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DisplayName { get; init; }

    [JsonPropertyOrder(2)]
    [JsonPropertyName("public_key")]
    public required string PublicKey { get; init; }
}

/// <summary>
/// Signer kind constants.
/// </summary>
public static class ManifestSignerKind
{
    public const string ClaimAuthor = "CLAIM_AUTHOR";
    public const string Publisher = "PUBLISHER";

    public static bool IsValid(string kind) =>
        kind == ClaimAuthor || kind == Publisher;
}
