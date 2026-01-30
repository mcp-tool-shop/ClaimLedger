using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Packs;
using ClaimLedger.Domain.Packs;
using ClaimLedger.Domain.Publish;
using Shared.Crypto;

namespace ClaimLedger.Application.Publish;

/// <summary>
/// Command to publish a claim bundle as a ready-to-share ClaimPack.
/// </summary>
public sealed record PublishCommand(
    /// <summary>
    /// Path to the input claim bundle JSON file.
    /// </summary>
    string InputClaimPath,

    /// <summary>
    /// Output path (directory or .zip file).
    /// </summary>
    string OutputPath,

    /// <summary>
    /// If true, output as ZIP file. Auto-detected if OutputPath ends with .zip.
    /// </summary>
    bool Zip = false,

    /// <summary>
    /// Directory containing evidence files to include.
    /// </summary>
    string? EvidenceDirectory = null,

    /// <summary>
    /// Directory containing CreatorLedger proof bundles to include.
    /// </summary>
    string? CreatorLedgerDirectory = null,

    /// <summary>
    /// Directory containing revocation files to include.
    /// </summary>
    string? RevocationsDirectory = null,

    /// <summary>
    /// Directory containing TSA trust anchor certificates.
    /// </summary>
    string? TsaTrustDirectory = null,

    /// <summary>
    /// Include embedded citations in the pack. Default true.
    /// </summary>
    bool IncludeCitations = true,

    /// <summary>
    /// Include attestations in verification. Default true.
    /// </summary>
    bool IncludeAttestations = true,

    /// <summary>
    /// Include timestamp receipts in verification. Default true.
    /// </summary>
    bool IncludeTimestamps = true,

    /// <summary>
    /// Sign the pack manifest.
    /// </summary>
    bool SignPack = false,

    /// <summary>
    /// Path to publisher private key file (JSON with hex-encoded key).
    /// </summary>
    string? PublisherKeyPath = null,

    /// <summary>
    /// Path to publisher identity file (JSON with researcher_id, display_name, public_key).
    /// </summary>
    string? PublisherIdentityPath = null,

    /// <summary>
    /// Path to author private key file.
    /// </summary>
    string? AuthorKeyPath = null,

    /// <summary>
    /// Path to author identity file.
    /// </summary>
    string? AuthorIdentityPath = null,

    /// <summary>
    /// Run strict verification gate. Default true for publishing.
    /// </summary>
    bool Strict = true,

    /// <summary>
    /// Path to write the publish report JSON.
    /// </summary>
    string? ReportPath = null);

/// <summary>
/// Result of the publish operation.
/// </summary>
public sealed class PublishResult
{
    public required bool Success { get; init; }
    public int ExitCode { get; init; }
    public string? Error { get; init; }
    public PublishReport? Report { get; init; }
    public string? OutputPath { get; init; }
}

/// <summary>
/// Identity information for signing.
/// </summary>
public sealed class SignerIdentityInfo
{
    public required string ResearcherId { get; init; }
    public string? DisplayName { get; init; }
    public required string PublicKey { get; init; }
}

/// <summary>
/// Handles the publish command orchestration.
/// </summary>
public static class PublishHandler
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    /// <summary>
    /// Publishes a claim bundle as a ready-to-share ClaimPack.
    /// </summary>
    public static async Task<PublishResult> HandleAsync(PublishCommand command)
    {
        var notes = new List<string>();
        var publishedAt = DateTimeOffset.UtcNow;

        // Step 0: Validate inputs
        var validationResult = await ValidateInputsAsync(command);
        if (!validationResult.Success)
        {
            return new PublishResult
            {
                Success = false,
                ExitCode = 4,
                Error = validationResult.Error
            };
        }

        var rootBundle = validationResult.RootBundle!;
        var publisherKey = validationResult.PublisherKey;
        var publisherIdentity = validationResult.PublisherIdentity;
        var authorKey = validationResult.AuthorKey;
        var authorIdentity = validationResult.AuthorIdentity;

        // Determine output format
        var outputAsZip = command.Zip || command.OutputPath.EndsWith(".zip", StringComparison.OrdinalIgnoreCase);
        var outputKind = outputAsZip ? OutputKind.Zip : OutputKind.Directory;

        // Create temp workspace
        var tempDir = Path.Combine(Path.GetTempPath(), $"claimledger-publish-{Guid.NewGuid():N}");
        var workspaceDir = Path.Combine(tempDir, "pack");

        try
        {
            Directory.CreateDirectory(tempDir);

            // Step A: Build pack
            notes.Add("Building pack...");
            var createResult = await CreatePackHandler.HandleAsync(new CreatePackCommand(
                RootBundle: rootBundle,
                OutputDirectory: workspaceDir,
                IncludeCitations: command.IncludeCitations,
                EvidenceDirectory: command.EvidenceDirectory,
                RevocationsDirectory: command.RevocationsDirectory,
                TsaTrustDirectory: command.TsaTrustDirectory,
                CreatorLedgerDirectory: command.CreatorLedgerDirectory,
                StrictCreatorLedger: command.Strict));

            if (!createResult.Success)
            {
                return new PublishResult
                {
                    Success = false,
                    ExitCode = 4,
                    Error = $"Failed to create pack: {createResult.Error}"
                };
            }

            var manifest = createResult.Manifest!;
            notes.Add($"Pack created with {createResult.FilesWritten} files");

            // Step B: Sign manifest (if requested)
            var publisherSigned = false;
            var authorSigned = false;

            if (command.SignPack)
            {
                if (publisherKey != null && publisherIdentity != null)
                {
                    notes.Add("Signing manifest as publisher...");
                    var signResult = await SignPackHandler.HandleAsync(new SignPackCommand(
                        PackDirectory: workspaceDir,
                        SignerPrivateKey: publisherKey,
                        SignerPublicKey: Ed25519PublicKey.Parse(publisherIdentity.PublicKey),
                        SignerKind: ManifestSignerKind.Publisher,
                        SignerResearcherId: publisherIdentity.ResearcherId,
                        SignerDisplayName: publisherIdentity.DisplayName));

                    if (!signResult.Success)
                    {
                        return new PublishResult
                        {
                            Success = false,
                            ExitCode = 5,
                            Error = $"Failed to sign as publisher: {signResult.Error}"
                        };
                    }

                    manifest = signResult.UpdatedManifest!;
                    publisherSigned = true;
                    notes.Add("Publisher signature added");
                }

                if (authorKey != null && authorIdentity != null)
                {
                    notes.Add("Signing manifest as author...");
                    var signResult = await SignPackHandler.HandleAsync(new SignPackCommand(
                        PackDirectory: workspaceDir,
                        SignerPrivateKey: authorKey,
                        SignerPublicKey: Ed25519PublicKey.Parse(authorIdentity.PublicKey),
                        SignerKind: ManifestSignerKind.ClaimAuthor,
                        SignerResearcherId: authorIdentity.ResearcherId,
                        SignerDisplayName: authorIdentity.DisplayName));

                    if (!signResult.Success)
                    {
                        return new PublishResult
                        {
                            Success = false,
                            ExitCode = 5,
                            Error = $"Failed to sign as author: {signResult.Error}"
                        };
                    }

                    manifest = signResult.UpdatedManifest!;
                    authorSigned = true;
                    notes.Add("Author signature added");
                }
            }

            // Re-read manifest to get final state
            var finalManifestJson = await File.ReadAllTextAsync(Path.Combine(workspaceDir, "manifest.json"));
            manifest = JsonSerializer.Deserialize<ClaimPackManifest>(finalManifestJson)!;

            // Step C: Verification gate
            notes.Add("Running verification gate...");
            var verifyCommand = BuildVerifyCommand(workspaceDir, command, manifest);
            var verifyResult = await VerifyPackHandler.HandleAsync(verifyCommand);

            var gateExitCode = verifyResult.ExitCode;
            var gatePassed = verifyResult.IsValid;

            if (!gatePassed)
            {
                notes.Add($"Verification gate FAILED: {verifyResult.Error}");

                // Build failed report
                var failedReport = BuildReport(
                    command, manifest, rootBundle, publishedAt,
                    outputKind, command.OutputPath,
                    publisherSigned, authorSigned,
                    gateExitCode, false, notes);

                // Write report if requested
                if (!string.IsNullOrEmpty(command.ReportPath))
                {
                    await WriteReportAsync(command.ReportPath, failedReport);
                }

                return new PublishResult
                {
                    Success = false,
                    ExitCode = gateExitCode,
                    Error = verifyResult.Error,
                    Report = failedReport
                };
            }

            notes.Add("Verification gate PASSED");

            // Step D: Emit artifact
            string finalOutputPath;
            if (outputAsZip)
            {
                notes.Add("Creating ZIP archive...");
                finalOutputPath = command.OutputPath;

                // Ensure parent directory exists
                var parentDir = Path.GetDirectoryName(finalOutputPath);
                if (!string.IsNullOrEmpty(parentDir))
                {
                    Directory.CreateDirectory(parentDir);
                }

                // Delete existing file if present
                if (File.Exists(finalOutputPath))
                {
                    File.Delete(finalOutputPath);
                }

                ZipFile.CreateFromDirectory(workspaceDir, finalOutputPath);
                notes.Add($"ZIP created: {finalOutputPath}");
            }
            else
            {
                notes.Add("Moving pack to output directory...");
                finalOutputPath = command.OutputPath;

                // Ensure parent exists
                var parentDir = Path.GetDirectoryName(finalOutputPath);
                if (!string.IsNullOrEmpty(parentDir))
                {
                    Directory.CreateDirectory(parentDir);
                }

                // Delete existing if present
                if (Directory.Exists(finalOutputPath))
                {
                    Directory.Delete(finalOutputPath, recursive: true);
                }

                Directory.Move(workspaceDir, finalOutputPath);
                notes.Add($"Pack created: {finalOutputPath}");
            }

            // Step E: Build and emit report
            var report = BuildReport(
                command, manifest, rootBundle, publishedAt,
                outputKind, finalOutputPath,
                publisherSigned, authorSigned,
                0, true, notes);

            if (!string.IsNullOrEmpty(command.ReportPath))
            {
                await WriteReportAsync(command.ReportPath, report);
                notes.Add($"Report written: {command.ReportPath}");
            }

            return new PublishResult
            {
                Success = true,
                ExitCode = 0,
                Report = report,
                OutputPath = finalOutputPath
            };
        }
        catch (Exception ex)
        {
            return new PublishResult
            {
                Success = false,
                ExitCode = 5,
                Error = $"Publish failed: {ex.Message}"
            };
        }
        finally
        {
            // Cleanup temp directory
            try
            {
                if (Directory.Exists(tempDir))
                {
                    Directory.Delete(tempDir, recursive: true);
                }
            }
            catch
            {
                // Ignore cleanup failures
            }
        }
    }

    private static async Task<ValidationResult> ValidateInputsAsync(PublishCommand command)
    {
        // Validate input claim path
        if (!File.Exists(command.InputClaimPath))
        {
            return new ValidationResult { Success = false, Error = $"Input claim file not found: {command.InputClaimPath}" };
        }

        // Load root bundle
        ClaimBundle rootBundle;
        try
        {
            var json = await File.ReadAllTextAsync(command.InputClaimPath);
            rootBundle = JsonSerializer.Deserialize<ClaimBundle>(json, JsonOptions)
                ?? throw new JsonException("Claim bundle is null");
        }
        catch (Exception ex)
        {
            return new ValidationResult { Success = false, Error = $"Invalid claim bundle: {ex.Message}" };
        }

        // Validate directories exist if specified
        if (!string.IsNullOrEmpty(command.EvidenceDirectory) && !Directory.Exists(command.EvidenceDirectory))
        {
            return new ValidationResult { Success = false, Error = $"Evidence directory not found: {command.EvidenceDirectory}" };
        }

        if (!string.IsNullOrEmpty(command.CreatorLedgerDirectory) && !Directory.Exists(command.CreatorLedgerDirectory))
        {
            return new ValidationResult { Success = false, Error = $"CreatorLedger directory not found: {command.CreatorLedgerDirectory}" };
        }

        if (!string.IsNullOrEmpty(command.RevocationsDirectory) && !Directory.Exists(command.RevocationsDirectory))
        {
            return new ValidationResult { Success = false, Error = $"Revocations directory not found: {command.RevocationsDirectory}" };
        }

        if (!string.IsNullOrEmpty(command.TsaTrustDirectory) && !Directory.Exists(command.TsaTrustDirectory))
        {
            return new ValidationResult { Success = false, Error = $"TSA trust directory not found: {command.TsaTrustDirectory}" };
        }

        // Validate signing requirements
        Ed25519PrivateKey? publisherKey = null;
        SignerIdentityInfo? publisherIdentity = null;
        Ed25519PrivateKey? authorKey = null;
        SignerIdentityInfo? authorIdentity = null;

        if (command.SignPack)
        {
            // Must have at least one key pair
            var hasPublisher = !string.IsNullOrEmpty(command.PublisherKeyPath);
            var hasAuthor = !string.IsNullOrEmpty(command.AuthorKeyPath);

            if (!hasPublisher && !hasAuthor)
            {
                return new ValidationResult { Success = false, Error = "--sign-pack requires --publisher-key and/or --author-key" };
            }

            // Load publisher key/identity
            if (hasPublisher)
            {
                if (string.IsNullOrEmpty(command.PublisherIdentityPath))
                {
                    return new ValidationResult { Success = false, Error = "--publisher-key requires --publisher-identity" };
                }

                var keyResult = await LoadKeyAsync(command.PublisherKeyPath!);
                if (!keyResult.Success)
                {
                    return new ValidationResult { Success = false, Error = $"Invalid publisher key: {keyResult.Error}" };
                }
                publisherKey = keyResult.Key;

                var identityResult = await LoadIdentityAsync(command.PublisherIdentityPath);
                if (!identityResult.Success)
                {
                    return new ValidationResult { Success = false, Error = $"Invalid publisher identity: {identityResult.Error}" };
                }
                publisherIdentity = identityResult.Identity;
            }

            // Load author key/identity
            if (hasAuthor)
            {
                if (string.IsNullOrEmpty(command.AuthorIdentityPath))
                {
                    return new ValidationResult { Success = false, Error = "--author-key requires --author-identity" };
                }

                var keyResult = await LoadKeyAsync(command.AuthorKeyPath!);
                if (!keyResult.Success)
                {
                    return new ValidationResult { Success = false, Error = $"Invalid author key: {keyResult.Error}" };
                }
                authorKey = keyResult.Key;

                var identityResult = await LoadIdentityAsync(command.AuthorIdentityPath);
                if (!identityResult.Success)
                {
                    return new ValidationResult { Success = false, Error = $"Invalid author identity: {identityResult.Error}" };
                }
                authorIdentity = identityResult.Identity;
            }
        }

        return new ValidationResult
        {
            Success = true,
            RootBundle = rootBundle,
            PublisherKey = publisherKey,
            PublisherIdentity = publisherIdentity,
            AuthorKey = authorKey,
            AuthorIdentity = authorIdentity
        };
    }

    private static async Task<(bool Success, string? Error, Ed25519PrivateKey? Key)> LoadKeyAsync(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return (false, $"Key file not found: {path}", null);
            }

            var json = await File.ReadAllTextAsync(path);
            var keyDoc = JsonDocument.Parse(json);

            // Try different key formats
            string? keyHex = null;

            if (keyDoc.RootElement.TryGetProperty("private_key", out var pkProp))
            {
                keyHex = pkProp.GetString();
            }
            else if (keyDoc.RootElement.TryGetProperty("privateKey", out var pk2Prop))
            {
                keyHex = pk2Prop.GetString();
            }
            else if (keyDoc.RootElement.TryGetProperty("key", out var kProp))
            {
                keyHex = kProp.GetString();
            }

            if (string.IsNullOrEmpty(keyHex))
            {
                return (false, "Key file missing 'private_key', 'privateKey', or 'key' field", null);
            }

            var keyBytes = Convert.FromHexString(keyHex);
            var key = Ed25519PrivateKey.FromBytes(keyBytes);
            return (true, null, key);
        }
        catch (Exception ex)
        {
            return (false, ex.Message, null);
        }
    }

    private static async Task<(bool Success, string? Error, SignerIdentityInfo? Identity)> LoadIdentityAsync(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return (false, $"Identity file not found: {path}", null);
            }

            var json = await File.ReadAllTextAsync(path);
            var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // Extract researcher_id
            string? researcherId = null;
            if (root.TryGetProperty("researcher_id", out var ridProp))
            {
                researcherId = ridProp.GetString();
            }
            else if (root.TryGetProperty("researcherId", out var rid2Prop))
            {
                researcherId = rid2Prop.GetString();
            }

            if (string.IsNullOrEmpty(researcherId))
            {
                return (false, "Identity file missing 'researcher_id' or 'researcherId' field", null);
            }

            // Extract public_key
            string? publicKey = null;
            if (root.TryGetProperty("public_key", out var pkProp))
            {
                publicKey = pkProp.GetString();
            }
            else if (root.TryGetProperty("publicKey", out var pk2Prop))
            {
                publicKey = pk2Prop.GetString();
            }

            if (string.IsNullOrEmpty(publicKey))
            {
                return (false, "Identity file missing 'public_key' or 'publicKey' field", null);
            }

            // Extract optional display_name
            string? displayName = null;
            if (root.TryGetProperty("display_name", out var dnProp))
            {
                displayName = dnProp.GetString();
            }
            else if (root.TryGetProperty("displayName", out var dn2Prop))
            {
                displayName = dn2Prop.GetString();
            }

            return (true, null, new SignerIdentityInfo
            {
                ResearcherId = researcherId,
                PublicKey = publicKey,
                DisplayName = displayName
            });
        }
        catch (Exception ex)
        {
            return (false, ex.Message, null);
        }
    }

    private static VerifyPackCommand BuildVerifyCommand(
        string packDir,
        PublishCommand command,
        ClaimPackManifest manifest)
    {
        var hasRevocations = manifest.Include.RevocationsDir != null;
        var hasTsaTrust = manifest.Include.TsaTrustDir != null;
        var hasCreatorLedger = manifest.Include.CreatorLedgerDir != null;
        var hasSignatures = manifest.ManifestSignatures?.Count > 0;

        return new VerifyPackCommand(
            PackDirectory: packDir,
            Strict: command.Strict,
            VerifyCitations: command.IncludeCitations,
            StrictCitations: command.Strict && command.IncludeCitations,
            VerifyAttestations: command.IncludeAttestations,
            VerifyTsa: command.IncludeTimestamps,
            StrictTsa: command.Strict && command.IncludeTimestamps && hasTsaTrust,
            StrictRevocations: command.Strict && hasRevocations,
            VerifyCreatorLedger: hasCreatorLedger,
            StrictCreatorLedger: command.Strict && hasCreatorLedger,
            VerifyManifestSignatures: hasSignatures,
            StrictManifestSignatures: command.Strict && hasSignatures);
    }

    private static PublishReport BuildReport(
        PublishCommand command,
        ClaimPackManifest manifest,
        ClaimBundle rootBundle,
        DateTimeOffset publishedAt,
        string outputKind,
        string outputPath,
        bool publisherSigned,
        bool authorSigned,
        int gateExitCode,
        bool gatePassed,
        List<string> notes)
    {
        // Count components
        var claimsCount = 1; // Root claim
        var evidenceCount = 0;
        var creatorLedgerCount = 0;
        var revocationsCount = 0;
        var timestampCount = rootBundle.TimestampReceipts?.Count ?? 0;
        var attestationsCount = rootBundle.Attestations?.Count ?? 0;

        // Count from manifest files
        foreach (var file in manifest.Files)
        {
            if (file.Path.StartsWith("claims/", StringComparison.OrdinalIgnoreCase))
            {
                claimsCount++;
            }
            else if (file.Path.StartsWith("evidence/", StringComparison.OrdinalIgnoreCase))
            {
                evidenceCount++;
            }
            else if (file.Path.StartsWith("creatorledger/", StringComparison.OrdinalIgnoreCase))
            {
                creatorLedgerCount++;
            }
            else if (file.Path.StartsWith("revocations/", StringComparison.OrdinalIgnoreCase))
            {
                revocationsCount++;
            }
        }

        // Compute manifest hash
        var manifestHash = SignPackHandler.ComputeCanonicalManifestHash(manifest);

        return new PublishReport
        {
            PublishedAt = publishedAt.ToString("O"),
            InputClaimPath = command.InputClaimPath,
            OutputPath = outputPath,
            OutputKind = outputKind,
            RootClaimCoreDigest = manifest.RootClaimCoreDigest,
            PackId = manifest.PackId,
            ManifestSha256Hex = manifestHash,
            Included = new PublishIncluded
            {
                Citations = command.IncludeCitations && claimsCount > 1,
                Attestations = attestationsCount > 0,
                Timestamps = timestampCount > 0,
                Evidence = evidenceCount > 0,
                CreatorLedger = creatorLedgerCount > 0,
                Revocations = revocationsCount > 0,
                TsaTrust = manifest.Include.TsaTrustDir != null
            },
            Counts = new PublishCounts
            {
                Claims = claimsCount,
                EvidenceFiles = evidenceCount,
                CreatorLedgerBundles = creatorLedgerCount,
                Revocations = revocationsCount,
                TimestampReceipts = timestampCount,
                Attestations = attestationsCount,
                ManifestSignatures = manifest.ManifestSignatures?.Count ?? 0
            },
            Signing = new PublishSigning
            {
                PublisherSigned = publisherSigned,
                AuthorSigned = authorSigned
            },
            VerificationGate = new PublishVerificationGate
            {
                Strict = command.Strict,
                ExitCode = gateExitCode,
                Result = gatePassed ? GateResult.Pass : GateResult.Fail,
                Notes = notes
            }
        };
    }

    private static async Task WriteReportAsync(string path, PublishReport report)
    {
        var parentDir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(parentDir))
        {
            Directory.CreateDirectory(parentDir);
        }

        var json = JsonSerializer.Serialize(report, JsonOptions);
        await File.WriteAllTextAsync(path, json);
    }

    private sealed class ValidationResult
    {
        public bool Success { get; init; }
        public string? Error { get; init; }
        public ClaimBundle? RootBundle { get; init; }
        public Ed25519PrivateKey? PublisherKey { get; init; }
        public SignerIdentityInfo? PublisherIdentity { get; init; }
        public Ed25519PrivateKey? AuthorKey { get; init; }
        public SignerIdentityInfo? AuthorIdentity { get; init; }
    }
}
