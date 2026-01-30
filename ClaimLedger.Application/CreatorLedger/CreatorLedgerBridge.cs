using System.Text.Json;
using System.Text.Json.Serialization;
using Shared.Crypto;

namespace ClaimLedger.Application.CreatorLedger;

/// <summary>
/// Interface for verifying CreatorLedger proof bundles.
/// Abstraction allows ClaimLedger to verify bundles without tight coupling.
/// </summary>
public interface ICreatorLedgerVerifier
{
    /// <summary>
    /// Verifies a CreatorLedger proof bundle from its JSON bytes.
    /// </summary>
    /// <param name="bundleBytes">UTF-8 JSON bytes of the proof bundle.</param>
    /// <returns>Verification result.</returns>
    CreatorLedgerVerificationResult Verify(byte[] bundleBytes);

    /// <summary>
    /// Computes the canonical digest of a bundle.
    /// Used for evidence binding verification.
    /// </summary>
    /// <param name="bundleBytes">UTF-8 JSON bytes of the proof bundle.</param>
    /// <returns>SHA-256 hex digest.</returns>
    string ComputeBundleDigest(byte[] bundleBytes);
}

/// <summary>
/// Result of CreatorLedger bundle verification.
/// </summary>
public sealed class CreatorLedgerVerificationResult
{
    public required bool IsValid { get; init; }
    public required string Status { get; init; }
    public string? Error { get; init; }
    public string? AssetId { get; init; }
    public string? ContentHash { get; init; }
    public string? TrustLevel { get; init; }
    public int AttestationsVerified { get; init; }
    public int SignaturesValid { get; init; }
    public int SignaturesFailed { get; init; }
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}

/// <summary>
/// CreatorLedger verification status constants.
/// </summary>
public static class CreatorLedgerStatus
{
    public const string Verified = "VERIFIED";
    public const string Broken = "BROKEN";
    public const string InvalidInput = "INVALID_INPUT";
}

/// <summary>
/// Default implementation of ICreatorLedgerVerifier.
/// Uses the proof.v1 format from CreatorLedger.
/// </summary>
public sealed class CreatorLedgerVerifier : ICreatorLedgerVerifier
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = false
    };

    public CreatorLedgerVerificationResult Verify(byte[] bundleBytes)
    {
        // Parse the bundle
        CreatorLedgerBundle bundle;
        try
        {
            var json = System.Text.Encoding.UTF8.GetString(bundleBytes);
            bundle = JsonSerializer.Deserialize<CreatorLedgerBundle>(json, JsonOptions)
                ?? throw new JsonException("Failed to deserialize proof bundle");
        }
        catch (JsonException ex)
        {
            return new CreatorLedgerVerificationResult
            {
                IsValid = false,
                Status = CreatorLedgerStatus.InvalidInput,
                Error = $"Invalid JSON in proof bundle: {ex.Message}"
            };
        }

        // Validate version
        if (bundle.Version != "proof.v1")
        {
            return new CreatorLedgerVerificationResult
            {
                IsValid = false,
                Status = CreatorLedgerStatus.InvalidInput,
                Error = $"Unsupported bundle version: {bundle.Version}"
            };
        }

        // Validate algorithms
        if (bundle.Algorithms?.Signature != "Ed25519" ||
            bundle.Algorithms?.Hash != "SHA-256" ||
            bundle.Algorithms?.Encoding != "UTF-8")
        {
            return new CreatorLedgerVerificationResult
            {
                IsValid = false,
                Status = CreatorLedgerStatus.InvalidInput,
                Error = "Unsupported cryptographic algorithms"
            };
        }

        // Check attestations exist
        if (bundle.Attestations == null || bundle.Attestations.Count == 0)
        {
            return new CreatorLedgerVerificationResult
            {
                IsValid = false,
                Status = CreatorLedgerStatus.Broken,
                Error = "No attestations found in bundle",
                AssetId = bundle.AssetId
            };
        }

        // Verify all signatures
        int signaturesValid = 0;
        int signaturesFailed = 0;
        var warnings = new List<string>();

        foreach (var attestation in bundle.Attestations)
        {
            if (VerifyAttestationSignature(attestation))
            {
                signaturesValid++;
            }
            else
            {
                signaturesFailed++;
                warnings.Add($"Signature verification failed for attestation {attestation.AttestationId}");
            }
        }

        if (signaturesFailed > 0)
        {
            return new CreatorLedgerVerificationResult
            {
                IsValid = false,
                Status = CreatorLedgerStatus.Broken,
                Error = "Signature verification failed - content may have been tampered",
                AssetId = bundle.AssetId,
                AttestationsVerified = bundle.Attestations.Count,
                SignaturesValid = signaturesValid,
                SignaturesFailed = signaturesFailed,
                Warnings = warnings
            };
        }

        // Find primary attestation
        var primaryAttestation = bundle.Attestations
            .Where(a => a.AssetId == bundle.AssetId)
            .OrderByDescending(a => a.AttestedAtUtc)
            .FirstOrDefault();

        if (primaryAttestation == null)
        {
            return new CreatorLedgerVerificationResult
            {
                IsValid = false,
                Status = CreatorLedgerStatus.Broken,
                Error = $"No attestation found for asset {bundle.AssetId}",
                AssetId = bundle.AssetId
            };
        }

        // Determine trust level
        var trustLevel = DetermineTrustLevel(primaryAttestation, bundle.Anchor);

        return new CreatorLedgerVerificationResult
        {
            IsValid = true,
            Status = CreatorLedgerStatus.Verified,
            AssetId = bundle.AssetId,
            ContentHash = primaryAttestation.ContentHash,
            TrustLevel = trustLevel,
            AttestationsVerified = bundle.Attestations.Count,
            SignaturesValid = signaturesValid,
            SignaturesFailed = 0,
            Warnings = warnings
        };
    }

    public string ComputeBundleDigest(byte[] bundleBytes)
    {
        // Compute SHA-256 of the raw bundle bytes
        // (The bundle is already canonical JSON from CreatorLedger)
        var digest = Digest256.Compute(bundleBytes);
        return digest.ToString();
    }

    private static bool VerifyAttestationSignature(CreatorLedgerAttestation attestation)
    {
        try
        {
            // Validate required fields exist
            if (string.IsNullOrEmpty(attestation.CreatorPublicKey) ||
                string.IsNullOrEmpty(attestation.AssetId) ||
                string.IsNullOrEmpty(attestation.ContentHash) ||
                string.IsNullOrEmpty(attestation.CreatorId) ||
                string.IsNullOrEmpty(attestation.AttestedAtUtc) ||
                string.IsNullOrEmpty(attestation.Signature))
            {
                return false;
            }

            var publicKey = Ed25519PublicKey.Parse(attestation.CreatorPublicKey);

            // Reconstruct the signable (same logic as CreatorLedger.Application.Signing.SigningService)
            var signable = new CreatorLedgerSignable
            {
                AssetId = attestation.AssetId,
                ContentHash = attestation.ContentHash,
                CreatorId = attestation.CreatorId,
                CreatorPublicKey = attestation.CreatorPublicKey,
                AttestedAtUtc = attestation.AttestedAtUtc,
                DerivedFromAssetId = attestation.DerivedFromAssetId,
                DerivedFromAttestationId = attestation.DerivedFromAttestationId
            };

            var signableBytes = CanonicalJson.SerializeToBytes(signable);
            var signature = Ed25519Signature.Parse(attestation.Signature);

            return publicKey.Verify(signableBytes, signature);
        }
        catch
        {
            return false;
        }
    }

    private static string DetermineTrustLevel(CreatorLedgerAttestation attestation, CreatorLedgerAnchor? anchor)
    {
        if (attestation.DerivedFromAssetId != null)
            return "Derived";

        if (anchor != null && anchor.ChainName != "null")
            return "Verified Original";

        return "Signed";
    }
}

#region DTOs for parsing CreatorLedger bundles

/// <summary>
/// CreatorLedger proof bundle format (proof.v1).
/// </summary>
public sealed class CreatorLedgerBundle
{
    [JsonPropertyName("Version")]
    public string? Version { get; init; }

    [JsonPropertyName("Algorithms")]
    public CreatorLedgerAlgorithms? Algorithms { get; init; }

    [JsonPropertyName("ExportedAtUtc")]
    public string? ExportedAtUtc { get; init; }

    [JsonPropertyName("AssetId")]
    public string? AssetId { get; init; }

    [JsonPropertyName("Attestations")]
    public List<CreatorLedgerAttestation>? Attestations { get; init; }

    [JsonPropertyName("Creators")]
    public List<CreatorLedgerCreator>? Creators { get; init; }

    [JsonPropertyName("Anchor")]
    public CreatorLedgerAnchor? Anchor { get; init; }

    [JsonPropertyName("LedgerTipHash")]
    public string? LedgerTipHash { get; init; }
}

public sealed class CreatorLedgerAlgorithms
{
    [JsonPropertyName("Signature")]
    public string? Signature { get; init; }

    [JsonPropertyName("Hash")]
    public string? Hash { get; init; }

    [JsonPropertyName("Encoding")]
    public string? Encoding { get; init; }
}

public sealed class CreatorLedgerAttestation
{
    [JsonPropertyName("AttestationId")]
    public string? AttestationId { get; init; }

    [JsonPropertyName("AssetId")]
    public string? AssetId { get; init; }

    [JsonPropertyName("ContentHash")]
    public string? ContentHash { get; init; }

    [JsonPropertyName("CreatorId")]
    public string? CreatorId { get; init; }

    [JsonPropertyName("CreatorPublicKey")]
    public string? CreatorPublicKey { get; init; }

    [JsonPropertyName("AttestedAtUtc")]
    public string? AttestedAtUtc { get; init; }

    [JsonPropertyName("Signature")]
    public string? Signature { get; init; }

    [JsonPropertyName("DerivedFromAssetId")]
    public string? DerivedFromAssetId { get; init; }

    [JsonPropertyName("DerivedFromAttestationId")]
    public string? DerivedFromAttestationId { get; init; }

    [JsonPropertyName("EventType")]
    public string? EventType { get; init; }
}

public sealed class CreatorLedgerCreator
{
    [JsonPropertyName("CreatorId")]
    public string? CreatorId { get; init; }

    [JsonPropertyName("PublicKey")]
    public string? PublicKey { get; init; }

    [JsonPropertyName("DisplayName")]
    public string? DisplayName { get; init; }
}

public sealed class CreatorLedgerAnchor
{
    [JsonPropertyName("ChainName")]
    public string? ChainName { get; init; }

    [JsonPropertyName("TransactionId")]
    public string? TransactionId { get; init; }

    [JsonPropertyName("LedgerRootHash")]
    public string? LedgerRootHash { get; init; }

    [JsonPropertyName("BlockNumber")]
    public long? BlockNumber { get; init; }

    [JsonPropertyName("AnchoredAtUtc")]
    public string? AnchoredAtUtc { get; init; }
}

/// <summary>
/// Signable format for attestation verification.
/// Must match CreatorLedger.Application.Signing.AttestationSignable exactly.
/// </summary>
internal sealed class CreatorLedgerSignable
{
    [JsonPropertyOrder(0)]
    [JsonPropertyName("asset_id")]
    public required string AssetId { get; init; }

    [JsonPropertyOrder(1)]
    [JsonPropertyName("content_hash")]
    public required string ContentHash { get; init; }

    [JsonPropertyOrder(2)]
    [JsonPropertyName("creator_id")]
    public required string CreatorId { get; init; }

    [JsonPropertyOrder(3)]
    [JsonPropertyName("creator_public_key")]
    public required string CreatorPublicKey { get; init; }

    [JsonPropertyOrder(4)]
    [JsonPropertyName("attested_at_utc")]
    public required string AttestedAtUtc { get; init; }

    [JsonPropertyOrder(5)]
    [JsonPropertyName("derived_from_asset_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DerivedFromAssetId { get; init; }

    [JsonPropertyOrder(6)]
    [JsonPropertyName("derived_from_attestation_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DerivedFromAttestationId { get; init; }
}

#endregion
