using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ClaimLedger.Application.Attestations;
using ClaimLedger.Application.Citations;
using ClaimLedger.Application.CreatorLedger;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Registry;
using ClaimLedger.Application.Revocations;
using ClaimLedger.Application.Timestamps;
using ClaimLedger.Domain.Packs;
using Shared.Crypto;

namespace ClaimLedger.Application.Packs;

/// <summary>
/// Command to verify a ClaimPack.
/// </summary>
public sealed record VerifyPackCommand(
    string PackDirectory,
    bool Strict = false,
    bool StrictCitations = false,
    bool StrictRevocations = false,
    bool StrictTsa = false,
    bool StrictManifestSignatures = false,
    bool VerifyCitations = true,
    bool VerifyAttestations = true,
    bool VerifyTsa = true,
    bool VerifyManifestSignatures = false,
    /// <summary>
    /// If true, verify CreatorLedger bundle evidence.
    /// </summary>
    bool VerifyCreatorLedger = false,
    /// <summary>
    /// If true, fail when any CreatorLedger bundle is missing or invalid.
    /// </summary>
    bool StrictCreatorLedger = false,
    /// <summary>
    /// Optional directory to resolve CreatorLedger bundles from (defaults to pack's creatorledger/).
    /// </summary>
    string? CreatorLedgerDirectory = null,
    /// <summary>
    /// Optional registry path for resolving citations and bundles.
    /// </summary>
    string? RegistryPath = null,
    /// <summary>
    /// If true, fail when registry resolution fails (stale, ambiguous, missing).
    /// </summary>
    bool StrictRegistry = false);

/// <summary>
/// Result of pack verification.
/// </summary>
public sealed class VerifyPackResult
{
    public required bool IsValid { get; init; }
    public required int ExitCode { get; init; }
    public string? Error { get; init; }
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();

    // Details
    public ClaimPackManifest? Manifest { get; init; }
    public ClaimBundle? RootBundle { get; init; }
    public string? RootClaimCoreDigest { get; init; }

    // Verification results
    public ManifestCheckResult? ManifestCheck { get; init; }
    public ManifestSignatureCheckResult? ManifestSignaturesResult { get; init; }
    public CitationVerificationResult? CitationsResult { get; init; }
    public AttestationVerificationResult? AttestationsResult { get; init; }
    public RevocationVerificationResult? RevocationsResult { get; init; }
    public VerifyTimestampsResult? TimestampsResult { get; init; }
    public CreatorLedgerVerificationSummary? CreatorLedgerResult { get; init; }
    public RegistryResolutionSummary? RegistryResult { get; init; }
}

/// <summary>
/// Summary of registry resolution during verification.
/// </summary>
public sealed record RegistryResolutionSummary(
    bool UsedRegistry,
    int CitationsResolvedViaRegistry,
    int BundlesResolvedViaRegistry,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Errors)
{
    public RegistryResolutionSummary() : this(false, 0, 0, Array.Empty<string>(), Array.Empty<string>()) { }
}

/// <summary>
/// Summary of CreatorLedger bundle verification.
/// </summary>
public sealed class CreatorLedgerVerificationSummary
{
    public required bool IsValid { get; init; }
    public required int TotalBundles { get; init; }
    public required int BundlesVerified { get; init; }
    public required int BundlesMissing { get; init; }
    public required int BundlesFailed { get; init; }
    public int BundlesResolvedViaRegistry { get; init; }
    public IReadOnlyList<CreatorLedgerBundleResult> Results { get; init; } = Array.Empty<CreatorLedgerBundleResult>();
    public IReadOnlyList<string> Errors { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Result of verifying a single CreatorLedger bundle.
/// </summary>
public sealed class CreatorLedgerBundleResult
{
    public required string EvidenceHash { get; init; }
    public required string Status { get; init; }
    public string? AssetId { get; init; }
    public string? ContentHash { get; init; }
    public string? TrustLevel { get; init; }
    public string? Error { get; init; }
}

/// <summary>
/// Result of manifest integrity check.
/// </summary>
public sealed class ManifestCheckResult
{
    public required bool IsValid { get; init; }
    public required bool RootDigestMatch { get; init; }
    public int FilesChecked { get; init; }
    public int FilesMissing { get; init; }
    public int FilesHashMismatch { get; init; }
    public int FilesSizeMismatch { get; init; }
    public int ExtraFiles { get; init; }
    public IReadOnlyList<string> Errors { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Result of manifest signature verification.
/// </summary>
public sealed class ManifestSignatureCheckResult
{
    public required bool IsValid { get; init; }
    public required int TotalSignatures { get; init; }
    public required int ValidSignatures { get; init; }
    public required int InvalidSignatures { get; init; }
    public required int RevokedSigners { get; init; }
    public IReadOnlyList<ManifestSignatureVerification> Results { get; init; } = Array.Empty<ManifestSignatureVerification>();
    public IReadOnlyList<string> Errors { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Result of verifying a single manifest signature.
/// </summary>
public sealed class ManifestSignatureVerification
{
    public required string SignerKind { get; init; }
    public required string SignerPublicKey { get; init; }
    public required string SignerResearcherId { get; init; }
    public string? SignerDisplayName { get; init; }
    public required bool SignatureValid { get; init; }
    public required bool ManifestHashMatch { get; init; }
    public required bool IsRevoked { get; init; }
    public string? Error { get; init; }
}

/// <summary>
/// Handles verification of ClaimPacks.
/// </summary>
public static class VerifyPackHandler
{
    /// <summary>
    /// Verifies a ClaimPack.
    /// </summary>
    public static async Task<VerifyPackResult> HandleAsync(VerifyPackCommand command)
    {
        var packDir = command.PackDirectory;
        var warnings = new List<string>();

        // Check pack directory exists
        if (!Directory.Exists(packDir))
        {
            return new VerifyPackResult
            {
                IsValid = false,
                ExitCode = 4,
                Error = $"Pack directory not found: {packDir}"
            };
        }

        // Load manifest
        var manifestPath = Path.Combine(packDir, "manifest.json");
        if (!File.Exists(manifestPath))
        {
            return new VerifyPackResult
            {
                IsValid = false,
                ExitCode = 4,
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
            return new VerifyPackResult
            {
                IsValid = false,
                ExitCode = 4,
                Error = $"Invalid manifest: {ex.Message}"
            };
        }

        // Validate manifest contract
        if (manifest.Contract != ClaimPackManifest.ContractVersion)
        {
            return new VerifyPackResult
            {
                IsValid = false,
                ExitCode = 4,
                Error = $"Unknown manifest contract: {manifest.Contract}"
            };
        }

        // Validate all paths in manifest
        foreach (var file in manifest.Files)
        {
            var pathValidation = PackPathValidator.ValidatePath(file.Path);
            if (!pathValidation.IsValid)
            {
                return new VerifyPackResult
                {
                    IsValid = false,
                    ExitCode = 4,
                    Error = $"Invalid path in manifest: {file.Path} - {pathValidation.Error}"
                };
            }
        }

        // Check for duplicate paths
        var paths = manifest.Files.Select(f => f.Path.ToLowerInvariant()).ToList();
        if (paths.Count != paths.Distinct().Count())
        {
            return new VerifyPackResult
            {
                IsValid = false,
                ExitCode = 4,
                Error = "Manifest contains duplicate paths"
            };
        }

        // Verify manifest file integrity
        var manifestCheck = await VerifyManifestIntegrityAsync(packDir, manifest, command.Strict);
        if (!manifestCheck.IsValid)
        {
            var exitCode = command.Strict ? 3 : 4;
            return new VerifyPackResult
            {
                IsValid = false,
                ExitCode = exitCode,
                Error = string.Join("; ", manifestCheck.Errors),
                ManifestCheck = manifestCheck
            };
        }

        // Add warnings for non-strict issues
        if (manifestCheck.ExtraFiles > 0 && !command.Strict)
        {
            warnings.Add($"{manifestCheck.ExtraFiles} extra file(s) not listed in manifest");
        }

        // Load root claim
        var rootClaimPath = Path.Combine(packDir, manifest.RootClaimPath);
        if (!File.Exists(rootClaimPath))
        {
            return new VerifyPackResult
            {
                IsValid = false,
                ExitCode = 4,
                Error = "Pack missing root claim (claim.json)"
            };
        }

        ClaimBundle rootBundle;
        try
        {
            var rootClaimJson = await File.ReadAllTextAsync(rootClaimPath);
            rootBundle = JsonSerializer.Deserialize<ClaimBundle>(rootClaimJson)
                ?? throw new JsonException("Root claim is null");
        }
        catch (Exception ex)
        {
            return new VerifyPackResult
            {
                IsValid = false,
                ExitCode = 4,
                Error = $"Invalid root claim: {ex.Message}"
            };
        }

        // Verify root claim digest matches manifest
        var computedDigest = ClaimCoreDigest.Compute(rootBundle);
        if (computedDigest.ToString() != manifest.RootClaimCoreDigest)
        {
            if (command.Strict)
            {
                return new VerifyPackResult
                {
                    IsValid = false,
                    ExitCode = 3,
                    Error = "Root claim digest mismatch with manifest"
                };
            }
            warnings.Add("Root claim digest does not match manifest");
        }

        // Build claim resolution map from pack
        Dictionary<string, ClaimBundle>? resolvedBundles = null;
        if (manifest.Include.ClaimsDir != null)
        {
            var claimsDir = Path.Combine(packDir, manifest.Include.ClaimsDir.TrimEnd('/'));
            if (Directory.Exists(claimsDir))
            {
                resolvedBundles = await LoadClaimBundlesFromDirectoryAsync(claimsDir);
            }
        }

        // Initialize registry resolver if provided
        RegistryResolver? registryResolver = null;
        var registrySummary = new RegistryResolutionSummary
        {
            UsedRegistry = false,
            CitationsResolvedViaRegistry = 0,
            BundlesResolvedViaRegistry = 0
        };
        var registryWarnings = new List<string>();
        var registryErrors = new List<string>();

        if (!string.IsNullOrEmpty(command.RegistryPath))
        {
            var strictReg = command.Strict || command.StrictRegistry;
            var resolverResult = await RegistryResolver.LoadAsync(command.RegistryPath, strictReg);

            if (!resolverResult.Success)
            {
                if (strictReg)
                {
                    return new VerifyPackResult
                    {
                        IsValid = false,
                        ExitCode = 4,
                        Error = $"Failed to load registry: {resolverResult.Error}"
                    };
                }
                warnings.Add($"Registry could not be loaded: {resolverResult.Error}");
            }
            else
            {
                registryResolver = resolverResult.Resolver;
                registrySummary = registrySummary with { UsedRegistry = true };
            }
        }

        // Resolve citations via registry if needed
        var citationsResolvedViaRegistry = 0;
        if (registryResolver != null && rootBundle.Citations != null && rootBundle.Citations.Count > 0)
        {
            var requiredDigests = rootBundle.Citations
                .Select(c => c.CitedClaimCoreDigest)
                .Where(d => resolvedBundles == null || !resolvedBundles.ContainsKey(d))
                .ToList();

            if (requiredDigests.Count > 0)
            {
                resolvedBundles ??= new Dictionary<string, ClaimBundle>();

                foreach (var digest in requiredDigests)
                {
                    var resolveResult = await registryResolver.ResolveClaimAsync(digest);
                    if (resolveResult.Status == ResolveStatus.Resolved && resolveResult.Bundle != null)
                    {
                        resolvedBundles[digest] = resolveResult.Bundle;
                        citationsResolvedViaRegistry++;
                    }
                }

                registryWarnings.AddRange(registryResolver.Warnings);
                registryErrors.AddRange(registryResolver.Errors);
            }
        }

        // Verify citations
        CitationVerificationResult? citationsResult = null;
        if (command.VerifyCitations && rootBundle.Citations != null && rootBundle.Citations.Count > 0)
        {
            var strictCitations = command.Strict || command.StrictCitations;
            citationsResult = VerifyCitationsHandler.Handle(
                new VerifyCitationsQuery(rootBundle, strictCitations, resolvedBundles));

            if (!citationsResult.AllValid)
            {
                return new VerifyPackResult
                {
                    IsValid = false,
                    ExitCode = 3,
                    Error = "Citation verification failed",
                    Manifest = manifest,
                    RootBundle = rootBundle,
                    RootClaimCoreDigest = computedDigest.ToString(),
                    ManifestCheck = manifestCheck,
                    CitationsResult = citationsResult
                };
            }
        }

        // Verify attestations
        AttestationVerificationResult? attestationsResult = null;
        if (command.VerifyAttestations && rootBundle.Attestations != null && rootBundle.Attestations.Count > 0)
        {
            attestationsResult = VerifyAttestationsHandler.Handle(
                new VerifyAttestationsQuery(rootBundle, DateTimeOffset.UtcNow));

            if (!attestationsResult.AllValid)
            {
                return new VerifyPackResult
                {
                    IsValid = false,
                    ExitCode = 3,
                    Error = "Attestation verification failed",
                    Manifest = manifest,
                    RootBundle = rootBundle,
                    RootClaimCoreDigest = computedDigest.ToString(),
                    ManifestCheck = manifestCheck,
                    CitationsResult = citationsResult,
                    AttestationsResult = attestationsResult
                };
            }
        }

        // Verify revocations
        RevocationVerificationResult? revocationsResult = null;
        if (manifest.Include.RevocationsDir != null)
        {
            var revocationsDir = Path.Combine(packDir, manifest.Include.RevocationsDir.TrimEnd('/'));
            if (Directory.Exists(revocationsDir))
            {
                var registry = await LoadRevocationsFromDirectoryAsync(revocationsDir);
                var strictRevocations = command.Strict || command.StrictRevocations;

                revocationsResult = VerifyAgainstRevocationsHandler.Handle(
                    new VerifyAgainstRevocationsQuery(rootBundle, registry, strictRevocations));

                if (!revocationsResult.IsValid)
                {
                    return new VerifyPackResult
                    {
                        IsValid = false,
                        ExitCode = 6, // REVOKED
                        Error = "Signer key is revoked",
                        Manifest = manifest,
                        RootBundle = rootBundle,
                        RootClaimCoreDigest = computedDigest.ToString(),
                        ManifestCheck = manifestCheck,
                        CitationsResult = citationsResult,
                        AttestationsResult = attestationsResult,
                        RevocationsResult = revocationsResult
                    };
                }
            }
        }

        // Verify TSA timestamps
        VerifyTimestampsResult? timestampsResult = null;
        if (command.VerifyTsa && rootBundle.TimestampReceipts != null && rootBundle.TimestampReceipts.Count > 0)
        {
            X509Certificate2Collection? trustAnchors = null;
            if (manifest.Include.TsaTrustDir != null)
            {
                var tsaTrustDir = Path.Combine(packDir, manifest.Include.TsaTrustDir.TrimEnd('/'));
                if (Directory.Exists(tsaTrustDir))
                {
                    trustAnchors = TsaTrustVerifier.LoadCertificatesFromDirectory(tsaTrustDir);
                }
            }

            var strictTsa = command.Strict || command.StrictTsa;
            timestampsResult = VerifyTimestampsHandler.Handle(
                new VerifyTimestampsQuery(rootBundle, trustAnchors, strictTsa));

            if (!timestampsResult.AllValid)
            {
                return new VerifyPackResult
                {
                    IsValid = false,
                    ExitCode = 3,
                    Error = "Timestamp verification failed",
                    Manifest = manifest,
                    RootBundle = rootBundle,
                    RootClaimCoreDigest = computedDigest.ToString(),
                    ManifestCheck = manifestCheck,
                    CitationsResult = citationsResult,
                    AttestationsResult = attestationsResult,
                    RevocationsResult = revocationsResult,
                    TimestampsResult = timestampsResult
                };
            }
        }

        // Verify evidence (if strict mode)
        if (command.Strict && manifest.Include.EvidenceDir != null)
        {
            var evidenceDir = Path.Combine(packDir, manifest.Include.EvidenceDir.TrimEnd('/'));
            if (Directory.Exists(evidenceDir))
            {
                var evidenceCheck = await VerifyEvidenceAsync(rootBundle, evidenceDir);
                if (!evidenceCheck.IsValid)
                {
                    return new VerifyPackResult
                    {
                        IsValid = false,
                        ExitCode = 3,
                        Error = evidenceCheck.Error,
                        Manifest = manifest,
                        RootBundle = rootBundle,
                        RootClaimCoreDigest = computedDigest.ToString(),
                        ManifestCheck = manifestCheck,
                        CitationsResult = citationsResult,
                        AttestationsResult = attestationsResult,
                        RevocationsResult = revocationsResult,
                        TimestampsResult = timestampsResult
                    };
                }
            }
        }

        // Verify manifest signatures (if requested)
        ManifestSignatureCheckResult? manifestSignaturesResult = null;
        if (command.VerifyManifestSignatures || command.StrictManifestSignatures)
        {
            var strictSigs = command.Strict || command.StrictManifestSignatures;

            // Load revocation registry if available for signer revocation checks
            RevocationRegistry? signerRevocationRegistry = null;
            if (manifest.Include.RevocationsDir != null)
            {
                var revocationsDir = Path.Combine(packDir, manifest.Include.RevocationsDir.TrimEnd('/'));
                if (Directory.Exists(revocationsDir))
                {
                    signerRevocationRegistry = await LoadRevocationsFromDirectoryAsync(revocationsDir);
                }
            }

            manifestSignaturesResult = VerifyManifestSignatures(manifest, signerRevocationRegistry, strictSigs);

            if (!manifestSignaturesResult.IsValid)
            {
                var exitCode = manifestSignaturesResult.RevokedSigners > 0 ? 6 : 3;
                return new VerifyPackResult
                {
                    IsValid = false,
                    ExitCode = exitCode,
                    Error = string.Join("; ", manifestSignaturesResult.Errors),
                    Warnings = manifestSignaturesResult.Warnings,
                    Manifest = manifest,
                    RootBundle = rootBundle,
                    RootClaimCoreDigest = computedDigest.ToString(),
                    ManifestCheck = manifestCheck,
                    ManifestSignaturesResult = manifestSignaturesResult,
                    CitationsResult = citationsResult,
                    AttestationsResult = attestationsResult,
                    RevocationsResult = revocationsResult,
                    TimestampsResult = timestampsResult
                };
            }

            // Add warnings for non-strict issues
            warnings.AddRange(manifestSignaturesResult.Warnings);
        }

        // Verify CreatorLedger bundles (if requested)
        CreatorLedgerVerificationSummary? creatorLedgerResult = null;
        var bundlesResolvedViaRegistry = 0;
        if (command.VerifyCreatorLedger || command.StrictCreatorLedger)
        {
            var strictCL = command.Strict || command.StrictCreatorLedger;

            // Determine CreatorLedger directory
            var creatorLedgerDir = command.CreatorLedgerDirectory;
            if (string.IsNullOrEmpty(creatorLedgerDir) && manifest.Include.CreatorLedgerDir != null)
            {
                creatorLedgerDir = Path.Combine(packDir, manifest.Include.CreatorLedgerDir.TrimEnd('/'));
            }

            // First try pack-local, then registry for missing bundles
            creatorLedgerResult = await VerifyCreatorLedgerBundlesWithRegistryAsync(
                rootBundle, creatorLedgerDir, registryResolver, strictCL);

            if (!creatorLedgerResult.IsValid)
            {
                return new VerifyPackResult
                {
                    IsValid = false,
                    ExitCode = 3,
                    Error = "CreatorLedger bundle verification failed",
                    Warnings = creatorLedgerResult.Warnings,
                    Manifest = manifest,
                    RootBundle = rootBundle,
                    RootClaimCoreDigest = computedDigest.ToString(),
                    ManifestCheck = manifestCheck,
                    ManifestSignaturesResult = manifestSignaturesResult,
                    CitationsResult = citationsResult,
                    AttestationsResult = attestationsResult,
                    RevocationsResult = revocationsResult,
                    TimestampsResult = timestampsResult,
                    CreatorLedgerResult = creatorLedgerResult
                };
            }

            warnings.AddRange(creatorLedgerResult.Warnings);
            bundlesResolvedViaRegistry = creatorLedgerResult.BundlesResolvedViaRegistry;
        }

        // Add registry warnings
        warnings.AddRange(registryWarnings);

        // Build final registry summary
        var finalRegistrySummary = registrySummary with
        {
            CitationsResolvedViaRegistry = citationsResolvedViaRegistry,
            BundlesResolvedViaRegistry = bundlesResolvedViaRegistry,
            Warnings = registryWarnings,
            Errors = registryErrors
        };

        // Check for registry errors in strict mode
        if ((command.Strict || command.StrictRegistry) && registryErrors.Count > 0)
        {
            return new VerifyPackResult
            {
                IsValid = false,
                ExitCode = 3,
                Error = $"Registry resolution failed: {string.Join("; ", registryErrors)}",
                Warnings = warnings,
                Manifest = manifest,
                RootBundle = rootBundle,
                RootClaimCoreDigest = computedDigest.ToString(),
                ManifestCheck = manifestCheck,
                ManifestSignaturesResult = manifestSignaturesResult,
                CitationsResult = citationsResult,
                AttestationsResult = attestationsResult,
                RevocationsResult = revocationsResult,
                TimestampsResult = timestampsResult,
                CreatorLedgerResult = creatorLedgerResult,
                RegistryResult = finalRegistrySummary
            };
        }

        return new VerifyPackResult
        {
            IsValid = true,
            ExitCode = 0,
            Warnings = warnings,
            Manifest = manifest,
            RootBundle = rootBundle,
            RootClaimCoreDigest = computedDigest.ToString(),
            ManifestCheck = manifestCheck,
            ManifestSignaturesResult = manifestSignaturesResult,
            CitationsResult = citationsResult,
            AttestationsResult = attestationsResult,
            RevocationsResult = revocationsResult,
            TimestampsResult = timestampsResult,
            CreatorLedgerResult = creatorLedgerResult,
            RegistryResult = finalRegistrySummary
        };
    }

    private static async Task<ManifestCheckResult> VerifyManifestIntegrityAsync(
        string packDir,
        ClaimPackManifest manifest,
        bool strict)
    {
        var errors = new List<string>();
        var filesChecked = 0;
        var filesMissing = 0;
        var filesHashMismatch = 0;
        var filesSizeMismatch = 0;
        var extraFiles = 0;

        var manifestPaths = manifest.Files.Select(f => f.Path.ToLowerInvariant()).ToHashSet();

        // Check each file in manifest
        foreach (var entry in manifest.Files)
        {
            var filePath = PackPathValidator.SafeCombine(packDir, entry.Path);
            if (filePath == null)
            {
                errors.Add($"Invalid path: {entry.Path}");
                continue;
            }

            if (!File.Exists(filePath))
            {
                filesMissing++;
                errors.Add($"Missing file: {entry.Path}");
                continue;
            }

            filesChecked++;

            // Check size
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Length != entry.SizeBytes)
            {
                filesSizeMismatch++;
                errors.Add($"Size mismatch: {entry.Path} (expected {entry.SizeBytes}, got {fileInfo.Length})");
                continue;
            }

            // Check hash
            using var stream = File.OpenRead(filePath);
            var hash = SHA256.HashData(stream);
            var hashHex = Convert.ToHexString(hash).ToLowerInvariant();

            if (!string.Equals(hashHex, entry.Sha256Hex, StringComparison.OrdinalIgnoreCase))
            {
                filesHashMismatch++;
                errors.Add($"Hash mismatch: {entry.Path}");
            }
        }

        // In strict mode, check for extra files
        if (strict)
        {
            var allFiles = Directory.GetFiles(packDir, "*", SearchOption.AllDirectories)
                .Select(f => PackPathValidator.GetRelativePath(packDir, f).ToLowerInvariant())
                .Where(f => f != "manifest.json") // Exclude manifest itself
                .ToHashSet();

            foreach (var file in allFiles)
            {
                if (!manifestPaths.Contains(file))
                {
                    extraFiles++;
                    errors.Add($"Extra file not in manifest: {file}");
                }
            }
        }
        else
        {
            // Non-strict: just count extra files for warning
            var allFiles = Directory.GetFiles(packDir, "*", SearchOption.AllDirectories)
                .Select(f => PackPathValidator.GetRelativePath(packDir, f).ToLowerInvariant())
                .Where(f => f != "manifest.json")
                .ToHashSet();

            extraFiles = allFiles.Count - manifestPaths.Count;
            if (extraFiles < 0) extraFiles = 0;
        }

        var isValid = filesMissing == 0 && filesHashMismatch == 0 && filesSizeMismatch == 0 &&
                      (!strict || extraFiles == 0);

        return new ManifestCheckResult
        {
            IsValid = isValid,
            RootDigestMatch = true, // Checked separately
            FilesChecked = filesChecked,
            FilesMissing = filesMissing,
            FilesHashMismatch = filesHashMismatch,
            FilesSizeMismatch = filesSizeMismatch,
            ExtraFiles = extraFiles,
            Errors = errors
        };
    }

    private static async Task<Dictionary<string, ClaimBundle>> LoadClaimBundlesFromDirectoryAsync(string dir)
    {
        var result = new Dictionary<string, ClaimBundle>();

        foreach (var file in Directory.GetFiles(dir, "*.json", SearchOption.AllDirectories))
        {
            try
            {
                var json = await File.ReadAllTextAsync(file);
                var bundle = JsonSerializer.Deserialize<ClaimBundle>(json);
                if (bundle?.Claim != null)
                {
                    var digest = ClaimCoreDigest.Compute(bundle);
                    result[digest.ToString()] = bundle;
                }
            }
            catch
            {
                // Skip invalid files
            }
        }

        return result;
    }

    private static async Task<RevocationRegistry> LoadRevocationsFromDirectoryAsync(string dir)
    {
        var registry = new RevocationRegistry();

        foreach (var file in Directory.GetFiles(dir, "*.json", SearchOption.AllDirectories))
        {
            try
            {
                var json = await File.ReadAllTextAsync(file);
                var bundle = JsonSerializer.Deserialize<RevocationBundle>(json);
                if (bundle?.Revocation != null)
                {
                    var revocation = RevocationRegistry.LoadFromBundle(bundle);
                    if (revocation != null)
                    {
                        registry.Add(revocation);
                    }
                }
            }
            catch
            {
                // Skip invalid files
            }
        }

        return registry;
    }

    private static async Task<(bool IsValid, string? Error)> VerifyEvidenceAsync(
        ClaimBundle bundle,
        string evidenceDir)
    {
        // Build hash -> file mapping from evidence directory
        var evidenceFiles = new Dictionary<string, string>();
        foreach (var file in Directory.GetFiles(evidenceDir, "*", SearchOption.AllDirectories))
        {
            try
            {
                using var stream = File.OpenRead(file);
                var hash = ContentHash.Compute(stream);
                evidenceFiles[hash.ToString()] = file;
            }
            catch
            {
                // Skip files we can't hash
            }
        }

        // Check each evidence reference
        foreach (var evidence in bundle.Claim.Evidence)
        {
            if (!evidenceFiles.ContainsKey(evidence.Hash))
            {
                return (false, $"Missing evidence file for hash: {evidence.Hash}");
            }
        }

        return (true, null);
    }

    private static ManifestSignatureCheckResult VerifyManifestSignatures(
        ClaimPackManifest manifest,
        RevocationRegistry? revocationRegistry,
        bool strict)
    {
        var errors = new List<string>();
        var sigWarnings = new List<string>();
        var results = new List<ManifestSignatureVerification>();

        var signatures = manifest.ManifestSignatures ?? Array.Empty<ManifestSignatureEntry>();

        // Strict mode requires at least one signature
        if (strict && signatures.Count == 0)
        {
            return new ManifestSignatureCheckResult
            {
                IsValid = false,
                TotalSignatures = 0,
                ValidSignatures = 0,
                InvalidSignatures = 0,
                RevokedSigners = 0,
                Errors = new[] { "Strict manifest signature verification requires at least one signature" }
            };
        }

        // No signatures is valid in non-strict mode (just warn)
        if (signatures.Count == 0)
        {
            return new ManifestSignatureCheckResult
            {
                IsValid = true,
                TotalSignatures = 0,
                ValidSignatures = 0,
                InvalidSignatures = 0,
                RevokedSigners = 0,
                Warnings = new[] { "Pack has no manifest signatures" }
            };
        }

        // Compute expected manifest hash
        var expectedHash = SignPackHandler.ComputeCanonicalManifestHash(manifest);

        var validCount = 0;
        var invalidCount = 0;
        var revokedCount = 0;

        foreach (var entry in signatures)
        {
            var verification = VerifySingleManifestSignature(entry, expectedHash, revocationRegistry);
            results.Add(verification);

            if (verification.SignatureValid && verification.ManifestHashMatch && !verification.IsRevoked)
            {
                validCount++;
            }
            else
            {
                if (verification.IsRevoked)
                {
                    revokedCount++;
                    if (strict)
                    {
                        errors.Add($"Manifest signer {verification.SignerResearcherId} is revoked");
                    }
                    else
                    {
                        sigWarnings.Add($"Manifest signer {verification.SignerResearcherId} is revoked");
                    }
                }
                else
                {
                    invalidCount++;
                    errors.Add(verification.Error ?? "Invalid manifest signature");
                }
            }
        }

        // Determine overall validity
        bool isValid;
        if (strict)
        {
            // Strict: all signatures must be valid and not revoked
            isValid = invalidCount == 0 && revokedCount == 0;
        }
        else
        {
            // Non-strict: at least one valid signature is sufficient
            isValid = validCount > 0 || invalidCount == 0;
        }

        return new ManifestSignatureCheckResult
        {
            IsValid = isValid,
            TotalSignatures = signatures.Count,
            ValidSignatures = validCount,
            InvalidSignatures = invalidCount,
            RevokedSigners = revokedCount,
            Results = results,
            Errors = errors,
            Warnings = sigWarnings
        };
    }

    private static ManifestSignatureVerification VerifySingleManifestSignature(
        ManifestSignatureEntry entry,
        string expectedManifestHash,
        RevocationRegistry? revocationRegistry)
    {
        var signerKind = entry.Signer.Kind;
        var signerPublicKeyStr = entry.Signature.PublicKey;
        var signerId = entry.Signer.Identity.ResearcherId;
        var signerDisplayName = entry.Signer.Identity.DisplayName;

        try
        {
            // Parse public key
            var signerPublicKey = Ed25519PublicKey.Parse(signerPublicKeyStr);

            // Parse signature
            var signature = Ed25519Signature.Parse(entry.Signature.Sig);

            // Verify manifest hash binding
            var signableHash = entry.Signable.ManifestSha256Hex;
            if (!string.Equals(signableHash, expectedManifestHash, StringComparison.OrdinalIgnoreCase))
            {
                return new ManifestSignatureVerification
                {
                    SignerKind = signerKind,
                    SignerPublicKey = signerPublicKeyStr,
                    SignerResearcherId = signerId,
                    SignerDisplayName = signerDisplayName,
                    SignatureValid = false,
                    ManifestHashMatch = false,
                    IsRevoked = false,
                    Error = "Manifest hash mismatch"
                };
            }

            // Verify cryptographic signature
            var signableBytes = CanonicalJson.SerializeToBytes(entry.Signable);
            var signatureValid = signerPublicKey.Verify(signableBytes, signature);

            if (!signatureValid)
            {
                return new ManifestSignatureVerification
                {
                    SignerKind = signerKind,
                    SignerPublicKey = signerPublicKeyStr,
                    SignerResearcherId = signerId,
                    SignerDisplayName = signerDisplayName,
                    SignatureValid = false,
                    ManifestHashMatch = true,
                    IsRevoked = false,
                    Error = "Invalid signature"
                };
            }

            // Check revocation status (at current time)
            var isRevoked = revocationRegistry?.IsRevoked(signerPublicKey, DateTimeOffset.UtcNow) ?? false;

            return new ManifestSignatureVerification
            {
                SignerKind = signerKind,
                SignerPublicKey = signerPublicKeyStr,
                SignerResearcherId = signerId,
                SignerDisplayName = signerDisplayName,
                SignatureValid = true,
                ManifestHashMatch = true,
                IsRevoked = isRevoked
            };
        }
        catch (Exception ex)
        {
            return new ManifestSignatureVerification
            {
                SignerKind = signerKind,
                SignerPublicKey = signerPublicKeyStr,
                SignerResearcherId = signerId,
                SignerDisplayName = signerDisplayName,
                SignatureValid = false,
                ManifestHashMatch = false,
                IsRevoked = false,
                Error = $"Failed to verify signature: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Verifies CreatorLedger bundles with registry fallback.
    /// </summary>
    private static async Task<CreatorLedgerVerificationSummary> VerifyCreatorLedgerBundlesWithRegistryAsync(
        ClaimBundle bundle,
        string? creatorLedgerDir,
        RegistryResolver? registryResolver,
        bool strict)
    {
        var results = new List<CreatorLedgerBundleResult>();
        var errors = new List<string>();
        var warnings = new List<string>();
        var bundlesResolvedViaRegistry = 0;

        // Find CREATORLEDGER_BUNDLE evidence
        var creatorLedgerEvidence = bundle.Claim.Evidence
            .Where(e => EvidenceKind.GetEffectiveKind(e.Kind) == EvidenceKind.CreatorLedgerBundle)
            .ToList();

        if (creatorLedgerEvidence.Count == 0)
        {
            return new CreatorLedgerVerificationSummary
            {
                IsValid = true,
                TotalBundles = 0,
                BundlesVerified = 0,
                BundlesMissing = 0,
                BundlesFailed = 0,
                Results = results
            };
        }

        // Build index of available bundles from local directory
        var availableBundles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrEmpty(creatorLedgerDir) && Directory.Exists(creatorLedgerDir))
        {
            foreach (var file in Directory.GetFiles(creatorLedgerDir, "*.json", SearchOption.AllDirectories))
            {
                try
                {
                    var bytes = File.ReadAllBytes(file);
                    var hash = SHA256.HashData(bytes);
                    var digest = Convert.ToHexString(hash).ToLowerInvariant();
                    availableBundles[digest] = file;
                }
                catch
                {
                    // Skip files we can't read
                }
            }
        }

        var verifier = new CreatorLedgerVerifier();
        var bundlesVerified = 0;
        var bundlesMissing = 0;
        var bundlesFailed = 0;

        foreach (var evidence in creatorLedgerEvidence)
        {
            var evidenceHash = evidence.Hash.ToLowerInvariant();
            byte[]? bundleBytes = null;
            string? bundlePath = null;
            var resolvedViaRegistry = false;

            // Try local first
            if (availableBundles.TryGetValue(evidenceHash, out bundlePath))
            {
                bundleBytes = File.ReadAllBytes(bundlePath);
            }
            // Try registry fallback
            else if (registryResolver != null)
            {
                var resolveResult = await registryResolver.ResolveCreatorLedgerBundleAsync(evidenceHash);
                if (resolveResult.Status == ResolveStatus.Resolved && resolveResult.BundleBytes != null)
                {
                    bundleBytes = resolveResult.BundleBytes;
                    bundlePath = resolveResult.SourcePath;
                    resolvedViaRegistry = true;
                }
            }

            if (bundleBytes == null)
            {
                bundlesMissing++;
                results.Add(new CreatorLedgerBundleResult
                {
                    EvidenceHash = evidenceHash,
                    Status = "MISSING",
                    Error = "Bundle file not found"
                });

                if (strict)
                {
                    errors.Add($"CreatorLedger bundle not found for digest: {evidenceHash}");
                }
                else
                {
                    warnings.Add($"CreatorLedger bundle not found for digest: {evidenceHash}");
                }
                continue;
            }

            // Verify the bundle
            try
            {
                // Verify digest matches
                var computedDigest = verifier.ComputeBundleDigest(bundleBytes);
                if (!string.Equals(computedDigest, evidenceHash, StringComparison.OrdinalIgnoreCase))
                {
                    bundlesFailed++;
                    results.Add(new CreatorLedgerBundleResult
                    {
                        EvidenceHash = evidenceHash,
                        Status = "DIGEST_MISMATCH",
                        Error = $"Computed digest {computedDigest} does not match evidence hash {evidenceHash}"
                    });
                    errors.Add($"CreatorLedger bundle digest mismatch: {evidenceHash}");
                    continue;
                }

                // Run CreatorLedger verification
                var verificationResult = verifier.Verify(bundleBytes);

                if (!verificationResult.IsValid)
                {
                    bundlesFailed++;
                    results.Add(new CreatorLedgerBundleResult
                    {
                        EvidenceHash = evidenceHash,
                        Status = verificationResult.Status,
                        AssetId = verificationResult.AssetId,
                        ContentHash = verificationResult.ContentHash,
                        Error = verificationResult.Error
                    });
                    errors.Add($"CreatorLedger bundle verification failed for {evidenceHash}: {verificationResult.Error}");
                    continue;
                }

                // Bundle verified successfully
                bundlesVerified++;
                if (resolvedViaRegistry)
                {
                    bundlesResolvedViaRegistry++;
                }
                results.Add(new CreatorLedgerBundleResult
                {
                    EvidenceHash = evidenceHash,
                    Status = verificationResult.Status,
                    AssetId = verificationResult.AssetId,
                    ContentHash = verificationResult.ContentHash,
                    TrustLevel = verificationResult.TrustLevel
                });
            }
            catch (Exception ex)
            {
                bundlesFailed++;
                results.Add(new CreatorLedgerBundleResult
                {
                    EvidenceHash = evidenceHash,
                    Status = "ERROR",
                    Error = $"Failed to verify bundle: {ex.Message}"
                });
                errors.Add($"CreatorLedger bundle error for {evidenceHash}: {ex.Message}");
            }
        }

        var isValid = strict
            ? bundlesMissing == 0 && bundlesFailed == 0
            : bundlesFailed == 0;

        return new CreatorLedgerVerificationSummary
        {
            IsValid = isValid,
            TotalBundles = creatorLedgerEvidence.Count,
            BundlesVerified = bundlesVerified,
            BundlesMissing = bundlesMissing,
            BundlesFailed = bundlesFailed,
            BundlesResolvedViaRegistry = bundlesResolvedViaRegistry,
            Results = results,
            Errors = errors,
            Warnings = warnings
        };
    }

    /// <summary>
    /// Verifies CreatorLedger bundles referenced as evidence.
    /// </summary>
    private static CreatorLedgerVerificationSummary VerifyCreatorLedgerBundles(
        ClaimBundle bundle,
        string? creatorLedgerDir,
        bool strict)
    {
        var results = new List<CreatorLedgerBundleResult>();
        var errors = new List<string>();
        var warnings = new List<string>();

        // Find CREATORLEDGER_BUNDLE evidence
        var creatorLedgerEvidence = bundle.Claim.Evidence
            .Where(e => EvidenceKind.GetEffectiveKind(e.Kind) == EvidenceKind.CreatorLedgerBundle)
            .ToList();

        if (creatorLedgerEvidence.Count == 0)
        {
            // No CreatorLedger evidence - always valid
            return new CreatorLedgerVerificationSummary
            {
                IsValid = true,
                TotalBundles = 0,
                BundlesVerified = 0,
                BundlesMissing = 0,
                BundlesFailed = 0,
                Results = results
            };
        }

        // Need a directory to resolve bundles
        if (string.IsNullOrEmpty(creatorLedgerDir) || !Directory.Exists(creatorLedgerDir))
        {
            if (strict)
            {
                return new CreatorLedgerVerificationSummary
                {
                    IsValid = false,
                    TotalBundles = creatorLedgerEvidence.Count,
                    BundlesVerified = 0,
                    BundlesMissing = creatorLedgerEvidence.Count,
                    BundlesFailed = 0,
                    Results = results,
                    Errors = new[] { "CreatorLedger directory not found or not specified" }
                };
            }

            // Non-strict: warn but pass
            return new CreatorLedgerVerificationSummary
            {
                IsValid = true,
                TotalBundles = creatorLedgerEvidence.Count,
                BundlesVerified = 0,
                BundlesMissing = creatorLedgerEvidence.Count,
                BundlesFailed = 0,
                Results = results,
                Warnings = new[] { $"{creatorLedgerEvidence.Count} CreatorLedger bundle(s) could not be verified (directory not found)" }
            };
        }

        // Build index of available bundles by digest
        var availableBundles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in Directory.GetFiles(creatorLedgerDir, "*.json", SearchOption.AllDirectories))
        {
            try
            {
                var bytes = File.ReadAllBytes(file);
                using var stream = new MemoryStream(bytes);
                var hash = SHA256.HashData(stream);
                var digest = Convert.ToHexString(hash).ToLowerInvariant();
                availableBundles[digest] = file;
            }
            catch
            {
                // Skip files we can't read
            }
        }

        var verifier = new CreatorLedgerVerifier();
        var bundlesVerified = 0;
        var bundlesMissing = 0;
        var bundlesFailed = 0;

        foreach (var evidence in creatorLedgerEvidence)
        {
            var evidenceHash = evidence.Hash.ToLowerInvariant();

            // Try to find the bundle file
            if (!availableBundles.TryGetValue(evidenceHash, out var bundlePath))
            {
                bundlesMissing++;
                var result = new CreatorLedgerBundleResult
                {
                    EvidenceHash = evidenceHash,
                    Status = "MISSING",
                    Error = "Bundle file not found"
                };
                results.Add(result);

                if (strict)
                {
                    errors.Add($"CreatorLedger bundle not found for digest: {evidenceHash}");
                }
                else
                {
                    warnings.Add($"CreatorLedger bundle not found for digest: {evidenceHash}");
                }
                continue;
            }

            // Verify the bundle
            try
            {
                var bundleBytes = File.ReadAllBytes(bundlePath);

                // Verify digest matches
                var computedDigest = verifier.ComputeBundleDigest(bundleBytes);
                if (!string.Equals(computedDigest, evidenceHash, StringComparison.OrdinalIgnoreCase))
                {
                    bundlesFailed++;
                    var result = new CreatorLedgerBundleResult
                    {
                        EvidenceHash = evidenceHash,
                        Status = "DIGEST_MISMATCH",
                        Error = $"Computed digest {computedDigest} does not match evidence hash {evidenceHash}"
                    };
                    results.Add(result);
                    errors.Add($"CreatorLedger bundle digest mismatch: {evidenceHash}");
                    continue;
                }

                // Run CreatorLedger verification
                var verificationResult = verifier.Verify(bundleBytes);

                if (!verificationResult.IsValid)
                {
                    bundlesFailed++;
                    var result = new CreatorLedgerBundleResult
                    {
                        EvidenceHash = evidenceHash,
                        Status = verificationResult.Status,
                        AssetId = verificationResult.AssetId,
                        ContentHash = verificationResult.ContentHash,
                        Error = verificationResult.Error
                    };
                    results.Add(result);
                    errors.Add($"CreatorLedger bundle verification failed for {evidenceHash}: {verificationResult.Error}");
                    continue;
                }

                // Bundle verified successfully
                bundlesVerified++;
                results.Add(new CreatorLedgerBundleResult
                {
                    EvidenceHash = evidenceHash,
                    Status = verificationResult.Status,
                    AssetId = verificationResult.AssetId,
                    ContentHash = verificationResult.ContentHash,
                    TrustLevel = verificationResult.TrustLevel
                });
            }
            catch (Exception ex)
            {
                bundlesFailed++;
                var result = new CreatorLedgerBundleResult
                {
                    EvidenceHash = evidenceHash,
                    Status = "ERROR",
                    Error = $"Failed to verify bundle: {ex.Message}"
                };
                results.Add(result);
                errors.Add($"CreatorLedger bundle error for {evidenceHash}: {ex.Message}");
            }
        }

        // Determine overall validity
        var isValid = strict
            ? bundlesMissing == 0 && bundlesFailed == 0
            : bundlesFailed == 0; // Non-strict allows missing bundles

        return new CreatorLedgerVerificationSummary
        {
            IsValid = isValid,
            TotalBundles = creatorLedgerEvidence.Count,
            BundlesVerified = bundlesVerified,
            BundlesMissing = bundlesMissing,
            BundlesFailed = bundlesFailed,
            Results = results,
            Errors = errors,
            Warnings = warnings
        };
    }
}
