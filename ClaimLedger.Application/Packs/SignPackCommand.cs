using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using ClaimLedger.Domain.Identity;
using ClaimLedger.Domain.Packs;
using Shared.Crypto;

namespace ClaimLedger.Application.Packs;

/// <summary>
/// Command to sign a ClaimPack manifest.
/// </summary>
public sealed record SignPackCommand(
    string PackDirectory,
    Ed25519PrivateKey SignerPrivateKey,
    Ed25519PublicKey SignerPublicKey,
    string SignerKind,
    string SignerResearcherId,
    string? SignerDisplayName = null,
    string? OutputDirectory = null);

/// <summary>
/// Result of signing a pack manifest.
/// </summary>
public sealed class SignPackResult
{
    public required bool Success { get; init; }
    public string? Error { get; init; }
    public ClaimPackManifest? UpdatedManifest { get; init; }
    public int TotalSignatures { get; init; }
}

/// <summary>
/// Handles signing of ClaimPack manifests.
/// </summary>
public static class SignPackHandler
{
    private static readonly JsonSerializerOptions CanonicalOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private static readonly JsonSerializerOptions OutputOptions = new()
    {
        WriteIndented = true
    };

    /// <summary>
    /// Signs a pack manifest.
    /// </summary>
    public static async Task<SignPackResult> HandleAsync(SignPackCommand command)
    {
        var packDir = command.PackDirectory;
        var outputDir = command.OutputDirectory ?? packDir;

        // Validate signer kind
        if (!ManifestSignerKind.IsValid(command.SignerKind))
        {
            return new SignPackResult
            {
                Success = false,
                Error = $"Invalid signer kind: {command.SignerKind}. Must be {ManifestSignerKind.ClaimAuthor} or {ManifestSignerKind.Publisher}"
            };
        }

        // Load manifest
        var manifestPath = Path.Combine(packDir, "manifest.json");
        if (!File.Exists(manifestPath))
        {
            return new SignPackResult
            {
                Success = false,
                Error = "Pack missing manifest.json"
            };
        }

        ClaimPackManifest manifest;
        try
        {
            var manifestJson = await File.ReadAllTextAsync(manifestPath);
            manifest = JsonSerializer.Deserialize<ClaimPackManifest>(manifestJson)
                ?? throw new JsonException("Manifest is null");
        }
        catch (Exception ex)
        {
            return new SignPackResult
            {
                Success = false,
                Error = $"Invalid manifest: {ex.Message}"
            };
        }

        // Validate contract
        if (manifest.Contract != ClaimPackManifest.ContractVersion)
        {
            return new SignPackResult
            {
                Success = false,
                Error = $"Unknown manifest contract: {manifest.Contract}"
            };
        }

        try
        {
            // Canonicalize manifest (excluding existing signatures)
            var canonicalHash = ComputeCanonicalManifestHash(manifest);

            // Create signable
            var signable = new ClaimPackManifestSignable
            {
                ManifestSha256Hex = canonicalHash,
                PackId = manifest.PackId,
                RootClaimCoreDigest = manifest.RootClaimCoreDigest,
                CreatedAt = manifest.CreatedAt
            };

            // Sign the signable
            var signableBytes = CanonicalJson.SerializeToBytes(signable);
            var signature = command.SignerPrivateKey.Sign(signableBytes);

            // Create signature entry
            var signatureEntry = new ManifestSignatureEntry
            {
                Signable = signable,
                Signature = new ManifestSignature
                {
                    PublicKey = command.SignerPublicKey.ToString(),
                    Sig = signature.ToString()
                },
                Signer = new ManifestSigner
                {
                    Kind = command.SignerKind,
                    Identity = new ManifestSignerIdentity
                    {
                        ResearcherId = command.SignerResearcherId,
                        DisplayName = command.SignerDisplayName,
                        PublicKey = command.SignerPublicKey.ToString()
                    }
                }
            };

            // Append to existing signatures (append-only)
            var existingSignatures = manifest.ManifestSignatures?.ToList() ?? new List<ManifestSignatureEntry>();
            existingSignatures.Add(signatureEntry);

            // Create updated manifest
            var updatedManifest = new ClaimPackManifest
            {
                PackId = manifest.PackId,
                CreatedAt = manifest.CreatedAt,
                RootClaimPath = manifest.RootClaimPath,
                RootClaimCoreDigest = manifest.RootClaimCoreDigest,
                Include = manifest.Include,
                Files = manifest.Files,
                ManifestSignatures = existingSignatures
            };

            // Write updated manifest
            var outputManifestPath = Path.Combine(outputDir, "manifest.json");
            if (outputDir != packDir)
            {
                // Copy entire pack to output directory
                CopyDirectory(packDir, outputDir);
            }

            var updatedJson = JsonSerializer.Serialize(updatedManifest, OutputOptions);
            await File.WriteAllTextAsync(outputManifestPath, updatedJson);

            return new SignPackResult
            {
                Success = true,
                UpdatedManifest = updatedManifest,
                TotalSignatures = existingSignatures.Count
            };
        }
        catch (Exception ex)
        {
            return new SignPackResult
            {
                Success = false,
                Error = $"Failed to sign manifest: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Computes the SHA-256 hash of the canonical manifest JSON (excluding manifest_signatures).
    /// </summary>
    public static string ComputeCanonicalManifestHash(ClaimPackManifest manifest)
    {
        // Create a copy without signatures for canonicalization
        var forCanon = new ManifestForCanonicalization
        {
            Contract = manifest.Contract,
            PackId = manifest.PackId,
            CreatedAt = manifest.CreatedAt,
            RootClaimPath = manifest.RootClaimPath,
            RootClaimCoreDigest = manifest.RootClaimCoreDigest,
            Include = manifest.Include,
            Files = manifest.Files
        };

        var canonicalBytes = CanonicalJson.SerializeToBytes(forCanon);
        var hash = SHA256.HashData(canonicalBytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static void CopyDirectory(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);

        foreach (var file in Directory.GetFiles(sourceDir))
        {
            var destFile = Path.Combine(destDir, Path.GetFileName(file));
            File.Copy(file, destFile, overwrite: true);
        }

        foreach (var dir in Directory.GetDirectories(sourceDir))
        {
            var destSubDir = Path.Combine(destDir, Path.GetFileName(dir));
            CopyDirectory(dir, destSubDir);
        }
    }
}

/// <summary>
/// Manifest structure for canonicalization (excludes manifest_signatures).
/// </summary>
internal sealed class ManifestForCanonicalization
{
    [JsonPropertyOrder(0)]
    [JsonPropertyName("Contract")]
    public required string Contract { get; init; }

    [JsonPropertyOrder(1)]
    [JsonPropertyName("PackId")]
    public required string PackId { get; init; }

    [JsonPropertyOrder(2)]
    [JsonPropertyName("CreatedAt")]
    public required string CreatedAt { get; init; }

    [JsonPropertyOrder(3)]
    [JsonPropertyName("RootClaimPath")]
    public required string RootClaimPath { get; init; }

    [JsonPropertyOrder(4)]
    [JsonPropertyName("RootClaimCoreDigest")]
    public required string RootClaimCoreDigest { get; init; }

    [JsonPropertyOrder(5)]
    [JsonPropertyName("Include")]
    public required PackIncludeConfig Include { get; init; }

    [JsonPropertyOrder(6)]
    [JsonPropertyName("Files")]
    public required IReadOnlyList<PackFileEntry> Files { get; init; }
}
