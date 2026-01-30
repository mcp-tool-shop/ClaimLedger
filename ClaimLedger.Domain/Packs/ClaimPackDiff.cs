using System.Text.Json.Serialization;

namespace ClaimLedger.Domain.Packs;

/// <summary>
/// ClaimPack diff report - structured comparison between two pack versions.
/// CONTRACT: ClaimPackDiffReport.v1 (frozen)
/// </summary>
public sealed class ClaimPackDiffReport
{
    /// <summary>
    /// Contract version. Frozen.
    /// </summary>
    public const string ContractVersion = "ClaimPackDiffReport.v1";

    [JsonPropertyOrder(0)]
    public string Contract { get; init; } = ContractVersion;

    /// <summary>
    /// Timestamp of diff generation.
    /// </summary>
    [JsonPropertyOrder(1)]
    public required string GeneratedAt { get; init; }

    /// <summary>
    /// Identifier for pack A (base/old version).
    /// </summary>
    [JsonPropertyOrder(2)]
    public required PackReference PackA { get; init; }

    /// <summary>
    /// Identifier for pack B (new version).
    /// </summary>
    [JsonPropertyOrder(3)]
    public required PackReference PackB { get; init; }

    /// <summary>
    /// Computed update classification.
    /// </summary>
    [JsonPropertyOrder(4)]
    public required string UpdateClass { get; init; }

    /// <summary>
    /// File inventory changes.
    /// </summary>
    [JsonPropertyOrder(5)]
    public required FileInventoryDiff Files { get; init; }

    /// <summary>
    /// Semantic changes to claim content.
    /// </summary>
    [JsonPropertyOrder(6)]
    public required SemanticDiff Semantics { get; init; }
}

/// <summary>
/// Reference to a pack in the diff report.
/// </summary>
public sealed class PackReference
{
    [JsonPropertyOrder(0)]
    public required string PackId { get; init; }

    [JsonPropertyOrder(1)]
    public required string RootClaimCoreDigest { get; init; }

    [JsonPropertyOrder(2)]
    public required string CreatedAt { get; init; }

    [JsonPropertyOrder(3)]
    public required int FileCount { get; init; }
}

/// <summary>
/// File inventory changes between packs.
/// </summary>
public sealed class FileInventoryDiff
{
    /// <summary>
    /// Files added in pack B.
    /// </summary>
    [JsonPropertyOrder(0)]
    public required IReadOnlyList<FileChange> Added { get; init; }

    /// <summary>
    /// Files removed from pack A.
    /// </summary>
    [JsonPropertyOrder(1)]
    public required IReadOnlyList<FileChange> Removed { get; init; }

    /// <summary>
    /// Files with different content (same path, different hash).
    /// </summary>
    [JsonPropertyOrder(2)]
    public required IReadOnlyList<FileModification> Modified { get; init; }

    /// <summary>
    /// Files unchanged.
    /// </summary>
    [JsonPropertyOrder(3)]
    public required int UnchangedCount { get; init; }
}

/// <summary>
/// A file change entry.
/// </summary>
public sealed class FileChange
{
    [JsonPropertyOrder(0)]
    public required string Path { get; init; }

    [JsonPropertyOrder(1)]
    public required string Sha256Hex { get; init; }

    [JsonPropertyOrder(2)]
    public required long SizeBytes { get; init; }
}

/// <summary>
/// A file modification (content changed).
/// </summary>
public sealed class FileModification
{
    [JsonPropertyOrder(0)]
    public required string Path { get; init; }

    [JsonPropertyOrder(1)]
    public required string OldSha256Hex { get; init; }

    [JsonPropertyOrder(2)]
    public required string NewSha256Hex { get; init; }

    [JsonPropertyOrder(3)]
    public required long OldSizeBytes { get; init; }

    [JsonPropertyOrder(4)]
    public required long NewSizeBytes { get; init; }
}

/// <summary>
/// Semantic changes to claim content.
/// </summary>
public sealed class SemanticDiff
{
    /// <summary>
    /// Whether the root claim core digest changed.
    /// </summary>
    [JsonPropertyOrder(0)]
    public required bool RootDigestChanged { get; init; }

    /// <summary>
    /// Attestation changes (keyed by attestation_id).
    /// </summary>
    [JsonPropertyOrder(1)]
    public required ElementDiff<AttestationRef> Attestations { get; init; }

    /// <summary>
    /// RFC 3161 timestamp changes (keyed by receipt_id).
    /// </summary>
    [JsonPropertyOrder(2)]
    public required ElementDiff<TimestampRef> Timestamps { get; init; }

    /// <summary>
    /// Manifest signature changes (keyed by manifest_sha256 + signer_pubkey).
    /// </summary>
    [JsonPropertyOrder(3)]
    public required ElementDiff<ManifestSignatureRef> ManifestSignatures { get; init; }

    /// <summary>
    /// Revocation changes (keyed by revocation_id).
    /// </summary>
    [JsonPropertyOrder(4)]
    public required ElementDiff<RevocationRef> Revocations { get; init; }

    /// <summary>
    /// Citation changes (keyed by citation_id).
    /// </summary>
    [JsonPropertyOrder(5)]
    public required ElementDiff<CitationRef> Citations { get; init; }
}

/// <summary>
/// Generic diff for semantic elements.
/// </summary>
public sealed class ElementDiff<T>
{
    [JsonPropertyOrder(0)]
    public required IReadOnlyList<T> Added { get; init; }

    [JsonPropertyOrder(1)]
    public required IReadOnlyList<T> Removed { get; init; }

    [JsonPropertyOrder(2)]
    public required IReadOnlyList<T> Modified { get; init; }

    [JsonPropertyOrder(3)]
    public required int UnchangedCount { get; init; }
}

/// <summary>
/// Reference to an attestation for diff reporting.
/// </summary>
public sealed class AttestationRef
{
    [JsonPropertyOrder(0)]
    public required string AttestationId { get; init; }

    [JsonPropertyOrder(1)]
    public required string AttestorPublicKey { get; init; }

    [JsonPropertyOrder(2)]
    public required string AttestationType { get; init; }
}

/// <summary>
/// Reference to a timestamp receipt for diff reporting.
/// </summary>
public sealed class TimestampRef
{
    [JsonPropertyOrder(0)]
    public required string ReceiptId { get; init; }

    [JsonPropertyOrder(1)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TsaPolicyOid { get; init; }

    [JsonPropertyOrder(2)]
    public required string GenTime { get; init; }
}

/// <summary>
/// Reference to a manifest signature for diff reporting.
/// </summary>
public sealed class ManifestSignatureRef
{
    [JsonPropertyOrder(0)]
    public required string ManifestSha256Hex { get; init; }

    [JsonPropertyOrder(1)]
    public required string SignerPublicKey { get; init; }

    [JsonPropertyOrder(2)]
    public required string SignerKind { get; init; }
}

/// <summary>
/// Reference to a revocation for diff reporting.
/// </summary>
public sealed class RevocationRef
{
    [JsonPropertyOrder(0)]
    public required string RevocationId { get; init; }

    [JsonPropertyOrder(1)]
    public required string RevokedPublicKey { get; init; }

    [JsonPropertyOrder(2)]
    public required string Reason { get; init; }
}

/// <summary>
/// Reference to a citation for diff reporting.
/// </summary>
public sealed class CitationRef
{
    [JsonPropertyOrder(0)]
    public required string CitationId { get; init; }

    [JsonPropertyOrder(1)]
    public required string CitedClaimCoreDigest { get; init; }

    [JsonPropertyOrder(2)]
    public required string Relation { get; init; }
}

/// <summary>
/// Update classification constants.
/// </summary>
public static class UpdateClass
{
    /// <summary>
    /// No changes at all.
    /// </summary>
    public const string Identical = "IDENTICAL";

    /// <summary>
    /// Only additions, no removals or modifications.
    /// Allowed append locations only.
    /// </summary>
    public const string AppendOnly = "APPEND_ONLY";

    /// <summary>
    /// Changes present but not destructive.
    /// </summary>
    public const string Modified = "MODIFIED";

    /// <summary>
    /// Root claim core digest changed, or removals/modifications present.
    /// </summary>
    public const string Breaking = "BREAKING";
}

/// <summary>
/// Update policy for pack validation.
/// </summary>
public static class PackUpdatePolicy
{
    /// <summary>
    /// Only allow append-only changes.
    /// </summary>
    public const string AppendOnly = "APPEND_ONLY";

    /// <summary>
    /// Allow any non-breaking changes.
    /// </summary>
    public const string AllowModified = "ALLOW_MODIFIED";

    public static bool IsValid(string policy) =>
        policy == AppendOnly || policy == AllowModified;
}

/// <summary>
/// Policy violation types.
/// </summary>
public static class PolicyViolationType
{
    public const string RootDigestChanged = "ROOT_DIGEST_CHANGED";
    public const string FileRemoved = "FILE_REMOVED";
    public const string FileModified = "FILE_MODIFIED";
    public const string ExistingAttestationModified = "EXISTING_ATTESTATION_MODIFIED";
    public const string ExistingTimestampModified = "EXISTING_TIMESTAMP_MODIFIED";
    public const string ExistingManifestSignatureModified = "EXISTING_MANIFEST_SIGNATURE_MODIFIED";
    public const string CitationChanged = "CITATION_CHANGED";
    public const string UnreferencedFileAdded = "UNREFERENCED_FILE_ADDED";
    public const string AttestationRemoved = "ATTESTATION_REMOVED";
    public const string TimestampRemoved = "TIMESTAMP_REMOVED";
    public const string ManifestSignatureRemoved = "MANIFEST_SIGNATURE_REMOVED";
    public const string RevocationRemoved = "REVOCATION_REMOVED";
    public const string CitationRemoved = "CITATION_REMOVED";
}

/// <summary>
/// Policy validation result.
/// </summary>
public sealed class PolicyValidationResult
{
    /// <summary>
    /// Whether the policy passed.
    /// </summary>
    [JsonPropertyOrder(0)]
    public required bool Passed { get; init; }

    /// <summary>
    /// The policy that was evaluated.
    /// </summary>
    [JsonPropertyOrder(1)]
    public required string Policy { get; init; }

    /// <summary>
    /// The computed update class.
    /// </summary>
    [JsonPropertyOrder(2)]
    public required string UpdateClass { get; init; }

    /// <summary>
    /// List of violations (empty if passed).
    /// </summary>
    [JsonPropertyOrder(3)]
    public required IReadOnlyList<PolicyViolation> Violations { get; init; }
}

/// <summary>
/// A policy violation.
/// </summary>
public sealed class PolicyViolation
{
    [JsonPropertyOrder(0)]
    public required string Type { get; init; }

    [JsonPropertyOrder(1)]
    public required string Path { get; init; }

    [JsonPropertyOrder(2)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Details { get; init; }
}
