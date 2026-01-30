using System.Security.Cryptography;
using System.Text.Json;
using ClaimLedger.Application.Export;
using ClaimLedger.Domain.Packs;
using Shared.Crypto;

namespace ClaimLedger.Application.Packs;

/// <summary>
/// Command to create a ClaimPack from a root claim bundle.
/// </summary>
public sealed record CreatePackCommand(
    ClaimBundle RootBundle,
    string OutputDirectory,
    bool IncludeCitations = false,
    string? EvidenceDirectory = null,
    string? RevocationsDirectory = null,
    string? TsaTrustDirectory = null,
    Dictionary<string, ClaimBundle>? ResolvedCitations = null,
    /// <summary>
    /// Directory containing CreatorLedger proof bundles to include.
    /// Bundles are matched by digest to CREATORLEDGER_BUNDLE evidence.
    /// </summary>
    string? CreatorLedgerDirectory = null,
    /// <summary>
    /// If true, fail when any CREATORLEDGER_BUNDLE evidence cannot be resolved.
    /// </summary>
    bool StrictCreatorLedger = false);

/// <summary>
/// Result of pack creation.
/// </summary>
public sealed class CreatePackResult
{
    public required bool Success { get; init; }
    public string? Error { get; init; }
    public ClaimPackManifest? Manifest { get; init; }
    public string? PackDirectory { get; init; }
    public int FilesWritten { get; init; }
}

/// <summary>
/// Handles creation of ClaimPacks.
/// </summary>
public static class CreatePackHandler
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    /// <summary>
    /// Creates a ClaimPack directory with manifest.
    /// </summary>
    public static async Task<CreatePackResult> HandleAsync(CreatePackCommand command)
    {
        var outputDir = command.OutputDirectory;
        var files = new List<PackFileEntry>();

        try
        {
            // Create output directory
            Directory.CreateDirectory(outputDir);

            // Write root claim
            var rootClaimPath = Path.Combine(outputDir, "claim.json");
            var rootClaimJson = JsonSerializer.Serialize(command.RootBundle, JsonOptions);
            await File.WriteAllTextAsync(rootClaimPath, rootClaimJson);

            var rootDigest = ClaimCoreDigest.Compute(command.RootBundle);

            files.Add(CreateFileEntry("claim.json", rootClaimPath));

            // Include configuration
            var include = new PackIncludeConfig();
            string? claimsDir = null;
            string? evidenceDir = null;
            string? revocationsDir = null;
            string? tsaTrustDir = null;

            // Process citations
            if (command.IncludeCitations)
            {
                claimsDir = "claims/";
                var claimsDirPath = Path.Combine(outputDir, "claims");
                Directory.CreateDirectory(claimsDirPath);

                // Collect cited bundles from embedded citations
                var citedBundles = new Dictionary<string, ClaimBundle>();

                if (command.RootBundle.Citations != null)
                {
                    foreach (var citation in command.RootBundle.Citations)
                    {
                        if (citation.Embedded != null)
                        {
                            var citedDigest = ClaimCoreDigest.Compute(citation.Embedded);
                            citedBundles[citedDigest.ToString()] = citation.Embedded;
                        }
                    }
                }

                // Add resolved citations if provided
                if (command.ResolvedCitations != null)
                {
                    foreach (var (digest, bundle) in command.ResolvedCitations)
                    {
                        citedBundles.TryAdd(digest, bundle);
                    }
                }

                // Write cited bundles
                foreach (var (digest, bundle) in citedBundles)
                {
                    var citedPath = Path.Combine(claimsDirPath, $"{digest}.json");
                    var citedJson = JsonSerializer.Serialize(bundle, JsonOptions);
                    await File.WriteAllTextAsync(citedPath, citedJson);

                    files.Add(CreateFileEntry($"claims/{digest}.json", citedPath));
                }

                include = include with { ClaimsDir = claimsDir };
            }

            // Copy evidence files
            if (!string.IsNullOrEmpty(command.EvidenceDirectory) && Directory.Exists(command.EvidenceDirectory))
            {
                evidenceDir = "evidence/";
                var evidenceDirPath = Path.Combine(outputDir, "evidence");
                Directory.CreateDirectory(evidenceDirPath);

                await CopyDirectoryAsync(command.EvidenceDirectory, evidenceDirPath, "evidence/", files);

                include = include with { EvidenceDir = evidenceDir };
            }

            // Copy revocations
            if (!string.IsNullOrEmpty(command.RevocationsDirectory) && Directory.Exists(command.RevocationsDirectory))
            {
                revocationsDir = "revocations/";
                var revocationsDirPath = Path.Combine(outputDir, "revocations");
                Directory.CreateDirectory(revocationsDirPath);

                await CopyDirectoryAsync(command.RevocationsDirectory, revocationsDirPath, "revocations/", files);

                include = include with { RevocationsDir = revocationsDir };
            }

            // Copy TSA trust anchors
            if (!string.IsNullOrEmpty(command.TsaTrustDirectory) && Directory.Exists(command.TsaTrustDirectory))
            {
                tsaTrustDir = "tsa-trust/";
                var tsaTrustDirPath = Path.Combine(outputDir, "tsa-trust");
                Directory.CreateDirectory(tsaTrustDirPath);

                await CopyDirectoryAsync(command.TsaTrustDirectory, tsaTrustDirPath, "tsa-trust/", files);

                include = include with { TsaTrustDir = tsaTrustDir };
            }

            // Copy CreatorLedger bundles
            string? creatorLedgerDir = null;
            if (!string.IsNullOrEmpty(command.CreatorLedgerDirectory) && Directory.Exists(command.CreatorLedgerDirectory))
            {
                creatorLedgerDir = "creatorledger/";
                var creatorLedgerDirPath = Path.Combine(outputDir, "creatorledger");
                Directory.CreateDirectory(creatorLedgerDirPath);

                // Find CREATORLEDGER_BUNDLE evidence and match to bundles
                var bundleResult = await CopyCreatorLedgerBundlesAsync(
                    command.RootBundle,
                    command.CreatorLedgerDirectory,
                    creatorLedgerDirPath,
                    files,
                    command.StrictCreatorLedger);

                if (!bundleResult.Success)
                {
                    return new CreatePackResult
                    {
                        Success = false,
                        Error = bundleResult.Error
                    };
                }

                if (bundleResult.BundlesCopied > 0)
                {
                    include = include with { CreatorLedgerDir = creatorLedgerDir };
                }
            }

            // Create manifest
            var manifest = new ClaimPackManifest
            {
                PackId = Guid.NewGuid().ToString(),
                CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
                RootClaimCoreDigest = rootDigest.ToString(),
                Include = include,
                Files = files
            };

            // Write manifest
            var manifestPath = Path.Combine(outputDir, "manifest.json");
            var manifestJson = JsonSerializer.Serialize(manifest, JsonOptions);
            await File.WriteAllTextAsync(manifestPath, manifestJson);

            return new CreatePackResult
            {
                Success = true,
                Manifest = manifest,
                PackDirectory = outputDir,
                FilesWritten = files.Count + 1 // +1 for manifest
            };
        }
        catch (Exception ex)
        {
            return new CreatePackResult
            {
                Success = false,
                Error = $"Failed to create pack: {ex.Message}"
            };
        }
    }

    private static async Task CopyDirectoryAsync(
        string sourceDir,
        string destDir,
        string pathPrefix,
        List<PackFileEntry> files)
    {
        foreach (var sourceFile in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            var relativePath = Path.GetRelativePath(sourceDir, sourceFile);
            var destPath = Path.Combine(destDir, relativePath);

            // Ensure destination directory exists
            var destFileDir = Path.GetDirectoryName(destPath);
            if (!string.IsNullOrEmpty(destFileDir))
            {
                Directory.CreateDirectory(destFileDir);
            }

            // Copy file
            File.Copy(sourceFile, destPath, overwrite: true);

            // Add to file list
            var packPath = pathPrefix + PackPathValidator.NormalizePath(relativePath);
            files.Add(CreateFileEntry(packPath, destPath));
        }
    }

    private static PackFileEntry CreateFileEntry(string packPath, string filePath)
    {
        var fileInfo = new FileInfo(filePath);
        var hash = ComputeFileHash(filePath);
        var mediaType = GetMediaType(filePath);

        return new PackFileEntry
        {
            Path = packPath,
            MediaType = mediaType,
            Sha256Hex = hash,
            SizeBytes = fileInfo.Length
        };
    }

    private static string ComputeFileHash(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string GetMediaType(string filePath)
    {
        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        return ext switch
        {
            ".json" => "application/json",
            ".cer" or ".crt" or ".der" => "application/x-x509-ca-cert",
            ".pem" => "application/x-pem-file",
            ".csv" => "text/csv",
            ".txt" => "text/plain",
            ".md" => "text/markdown",
            ".pdf" => "application/pdf",
            ".zip" => "application/zip",
            ".tar" => "application/x-tar",
            ".gz" => "application/gzip",
            _ => "application/octet-stream"
        };
    }

    /// <summary>
    /// Copies CreatorLedger bundles that are referenced as evidence.
    /// </summary>
    private static async Task<(bool Success, string? Error, int BundlesCopied)> CopyCreatorLedgerBundlesAsync(
        ClaimBundle bundle,
        string sourceDir,
        string destDir,
        List<PackFileEntry> files,
        bool strict)
    {
        var bundlesCopied = 0;

        // Find CREATORLEDGER_BUNDLE evidence
        var creatorLedgerEvidence = bundle.Claim.Evidence
            .Where(e => EvidenceKind.GetEffectiveKind(e.Kind) == EvidenceKind.CreatorLedgerBundle)
            .ToList();

        if (creatorLedgerEvidence.Count == 0)
        {
            return (true, null, 0);
        }

        // Build index of available bundles by digest
        var availableBundles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in Directory.GetFiles(sourceDir, "*.json", SearchOption.AllDirectories))
        {
            try
            {
                var bytes = await File.ReadAllBytesAsync(file);
                var digest = ComputeFileHash(file);
                availableBundles[digest] = file;
            }
            catch
            {
                // Skip files we can't read
            }
        }

        // Match and copy
        foreach (var evidence in creatorLedgerEvidence)
        {
            var digest = evidence.Hash.ToLowerInvariant();

            if (!availableBundles.TryGetValue(digest, out var sourcePath))
            {
                if (strict)
                {
                    return (false, $"CreatorLedger bundle not found for digest: {digest}", bundlesCopied);
                }
                // Non-strict: skip missing bundles
                continue;
            }

            // Copy to destination
            var destPath = Path.Combine(destDir, $"{digest}.json");
            File.Copy(sourcePath, destPath, overwrite: true);

            // Add to manifest
            files.Add(CreateFileEntry($"creatorledger/{digest}.json", destPath));
            bundlesCopied++;
        }

        return (true, null, bundlesCopied);
    }

    /// <summary>
    /// Result of EvidenceInfo for export, potentially with embedded path updated.
    /// </summary>
    public static EvidenceInfo CreateEvidenceInfoWithEmbeddedPath(EvidenceInfo original, string? embeddedPath)
    {
        return new EvidenceInfo
        {
            Type = original.Type,
            Hash = original.Hash,
            Locator = original.Locator,
            Kind = original.Kind,
            EmbeddedPath = embeddedPath ?? original.EmbeddedPath,
            BundleAssetId = original.BundleAssetId
        };
    }
}
