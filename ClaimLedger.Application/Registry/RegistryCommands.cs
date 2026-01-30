using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Packs;
using ClaimLedger.Domain.Packs;
using ClaimLedger.Domain.Registry;
using Shared.Crypto;

namespace ClaimLedger.Application.Registry;

#region Init Command

/// <summary>
/// Command to initialize a new registry.
/// </summary>
public sealed record InitRegistryCommand(string RegistryPath);

/// <summary>
/// Result of registry initialization.
/// </summary>
public sealed class InitRegistryResult
{
    public required bool Success { get; init; }
    public string? Error { get; init; }
    public string? RegistryId { get; init; }
    public string? IndexPath { get; init; }
}

/// <summary>
/// Handles registry initialization.
/// </summary>
public static class InitRegistryHandler
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static async Task<InitRegistryResult> HandleAsync(InitRegistryCommand command)
    {
        try
        {
            var registryPath = command.RegistryPath;

            // Create registry directory
            Directory.CreateDirectory(registryPath);

            var indexPath = Path.Combine(registryPath, "index.json");

            // Check if index already exists
            if (File.Exists(indexPath))
            {
                return new InitRegistryResult
                {
                    Success = false,
                    Error = "Registry already exists at this location"
                };
            }

            // Create empty index
            var now = DateTimeOffset.UtcNow.ToString("O");
            var registryId = Guid.NewGuid().ToString();

            var index = new ClaimRegistryIndex
            {
                RegistryId = registryId,
                CreatedAt = now,
                UpdatedAt = now
            };

            var json = JsonSerializer.Serialize(index, JsonOptions);
            await File.WriteAllTextAsync(indexPath, json);

            // Create optional subdirectories
            Directory.CreateDirectory(Path.Combine(registryPath, "packs"));
            Directory.CreateDirectory(Path.Combine(registryPath, "cache"));

            return new InitRegistryResult
            {
                Success = true,
                RegistryId = registryId,
                IndexPath = indexPath
            };
        }
        catch (Exception ex)
        {
            return new InitRegistryResult
            {
                Success = false,
                Error = $"Failed to initialize registry: {ex.Message}"
            };
        }
    }
}

#endregion

#region Add Command

/// <summary>
/// Command to add a pack to the registry.
/// </summary>
public sealed record AddPackToRegistryCommand(
    string RegistryPath,
    string PackPath,
    bool CopyPack = false);

/// <summary>
/// Result of adding a pack to registry.
/// </summary>
public sealed class AddPackResult
{
    public required bool Success { get; init; }
    public string? Error { get; init; }
    public string? PackId { get; init; }
    public string? RootDigest { get; init; }
    public int ClaimsIndexed { get; init; }
    public int CreatorLedgerBundlesIndexed { get; init; }
}

/// <summary>
/// Handles adding packs to the registry.
/// </summary>
public static class AddPackToRegistryHandler
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static async Task<AddPackResult> HandleAsync(AddPackToRegistryCommand command)
    {
        try
        {
            var registryPath = command.RegistryPath;
            var packPath = command.PackPath;

            // Load registry index
            var indexPath = Path.Combine(registryPath, "index.json");
            if (!File.Exists(indexPath))
            {
                return new AddPackResult
                {
                    Success = false,
                    Error = "Registry not found. Run 'registry init' first."
                };
            }

            var indexJson = await File.ReadAllTextAsync(indexPath);
            var index = JsonSerializer.Deserialize<ClaimRegistryIndex>(indexJson)
                ?? throw new JsonException("Failed to deserialize registry index");

            // Validate pack path
            var pathValidation = ValidatePackPath(packPath);
            if (!pathValidation.IsValid)
            {
                return new AddPackResult
                {
                    Success = false,
                    Error = pathValidation.Error
                };
            }

            // Determine pack kind
            var kind = DeterminePackKind(packPath);
            if (kind == null)
            {
                return new AddPackResult
                {
                    Success = false,
                    Error = "Pack must be a directory or .zip file"
                };
            }

            // Index the pack
            var packInfo = await IndexPackAsync(packPath, kind.Value);
            if (!packInfo.Success)
            {
                return new AddPackResult
                {
                    Success = false,
                    Error = packInfo.Error
                };
            }

            // Check for duplicate
            var existingPack = index.Packs.FirstOrDefault(p => p.PackId == packInfo.PackId);
            if (existingPack != null)
            {
                return new AddPackResult
                {
                    Success = false,
                    Error = $"Pack {packInfo.PackId} is already in the registry"
                };
            }

            // Compute relative or absolute path for storage
            var storedPath = packPath;
            if (command.CopyPack)
            {
                var destPath = Path.Combine(registryPath, "packs", packInfo.PackId!);
                if (kind == PackKind.Directory)
                {
                    CopyDirectory(packPath, destPath);
                }
                else
                {
                    Directory.CreateDirectory(destPath);
                    File.Copy(packPath, Path.Combine(destPath, Path.GetFileName(packPath)));
                }
                storedPath = Path.Combine("packs", packInfo.PackId!);
            }
            else
            {
                // Store relative path if possible
                storedPath = GetRelativeOrAbsolutePath(registryPath, packPath);
            }

            // Create pack entry
            var packEntry = new PackEntry
            {
                PackId = packInfo.PackId!,
                Path = storedPath,
                Kind = kind.Value,
                RootClaimCoreDigest = packInfo.RootDigest!,
                ManifestSha256Hex = packInfo.ManifestHash!,
                ManifestSigned = packInfo.ManifestSigned,
                HasClaimsDir = packInfo.HasClaimsDir,
                HasCreatorLedgerDir = packInfo.HasCreatorLedgerDir,
                HasRevocationsDir = packInfo.HasRevocationsDir,
                HasTsaTrustDir = packInfo.HasTsaTrustDir,
                FileInventorySha256Hex = packInfo.FileInventoryHash,
                AddedAt = DateTimeOffset.UtcNow.ToString("O")
            };

            // Add to packs list
            index.Packs.Add(packEntry);

            // Index claims
            var claimsIndexed = 0;
            foreach (var (digest, path) in packInfo.ClaimDigests)
            {
                if (!index.Claims.TryGetValue(digest, out var locations))
                {
                    locations = new List<ClaimLocation>();
                    index.Claims[digest] = locations;
                }

                // Avoid duplicates
                if (!locations.Any(l => l.PackId == packInfo.PackId && l.RelativePath == path))
                {
                    locations.Add(new ClaimLocation
                    {
                        PackId = packInfo.PackId!,
                        RelativePath = path
                    });
                    claimsIndexed++;
                }
            }

            // Index CreatorLedger bundles
            var bundlesIndexed = 0;
            foreach (var (digest, path) in packInfo.CreatorLedgerDigests)
            {
                if (!index.CreatorLedgerBundles.TryGetValue(digest, out var locations))
                {
                    locations = new List<BundleLocation>();
                    index.CreatorLedgerBundles[digest] = locations;
                }

                // Avoid duplicates
                if (!locations.Any(l => l.PackId == packInfo.PackId && l.RelativePath == path))
                {
                    locations.Add(new BundleLocation
                    {
                        PackId = packInfo.PackId!,
                        RelativePath = path
                    });
                    bundlesIndexed++;
                }
            }

            // Update timestamp and save
            index.UpdatedAt = DateTimeOffset.UtcNow.ToString("O");

            // Sort for deterministic output
            SortIndex(index);

            var updatedJson = JsonSerializer.Serialize(index, JsonOptions);
            await File.WriteAllTextAsync(indexPath, updatedJson);

            return new AddPackResult
            {
                Success = true,
                PackId = packInfo.PackId,
                RootDigest = packInfo.RootDigest,
                ClaimsIndexed = claimsIndexed,
                CreatorLedgerBundlesIndexed = bundlesIndexed
            };
        }
        catch (Exception ex)
        {
            return new AddPackResult
            {
                Success = false,
                Error = $"Failed to add pack: {ex.Message}"
            };
        }
    }

    private static (bool IsValid, string? Error) ValidatePackPath(string path)
    {
        // Check for path traversal
        var normalized = Path.GetFullPath(path);

        // Basic existence check
        if (!Directory.Exists(path) && !File.Exists(path))
        {
            return (false, $"Pack path does not exist: {path}");
        }

        return (true, null);
    }

    private static PackKind? DeterminePackKind(string path)
    {
        if (Directory.Exists(path))
            return PackKind.Directory;

        if (File.Exists(path) && path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            return PackKind.Zip;

        return null;
    }

    private static async Task<PackIndexInfo> IndexPackAsync(string packPath, PackKind kind)
    {
        if (kind == PackKind.Zip)
        {
            return new PackIndexInfo
            {
                Success = false,
                Error = "Zip pack support not yet implemented"
            };
        }

        // Directory pack
        var manifestPath = Path.Combine(packPath, "manifest.json");
        if (!File.Exists(manifestPath))
        {
            return new PackIndexInfo
            {
                Success = false,
                Error = "Pack missing manifest.json"
            };
        }

        // Load and parse manifest
        var manifestJson = await File.ReadAllTextAsync(manifestPath);
        var manifest = JsonSerializer.Deserialize<ClaimPackManifest>(manifestJson);
        if (manifest == null)
        {
            return new PackIndexInfo
            {
                Success = false,
                Error = "Invalid manifest.json"
            };
        }

        // Compute manifest hash
        var manifestBytes = Encoding.UTF8.GetBytes(manifestJson);
        var manifestHash = Convert.ToHexString(SHA256.HashData(manifestBytes)).ToLowerInvariant();

        // Check manifest signature presence
        var manifestSigned = manifest.ManifestSignatures != null && manifest.ManifestSignatures.Count > 0;

        // Index claims
        var claimDigests = new List<(string Digest, string Path)>();

        // Add root claim
        claimDigests.Add((manifest.RootClaimCoreDigest, manifest.RootClaimPath));

        // Index claims directory
        if (manifest.Include.ClaimsDir != null)
        {
            var claimsDir = Path.Combine(packPath, manifest.Include.ClaimsDir.TrimEnd('/'));
            if (Directory.Exists(claimsDir))
            {
                foreach (var claimFile in Directory.GetFiles(claimsDir, "*.json", SearchOption.AllDirectories))
                {
                    try
                    {
                        var json = await File.ReadAllTextAsync(claimFile);
                        var bundle = JsonSerializer.Deserialize<ClaimBundle>(json);
                        if (bundle?.Claim != null)
                        {
                            var digest = ClaimCoreDigest.Compute(bundle);
                            var relativePath = GetPackRelativePath(packPath, claimFile);
                            claimDigests.Add((digest.ToString(), relativePath));
                        }
                    }
                    catch
                    {
                        // Skip invalid files
                    }
                }
            }
        }

        // Index CreatorLedger bundles
        var creatorLedgerDigests = new List<(string Digest, string Path)>();
        if (manifest.Include.CreatorLedgerDir != null)
        {
            var clDir = Path.Combine(packPath, manifest.Include.CreatorLedgerDir.TrimEnd('/'));
            if (Directory.Exists(clDir))
            {
                foreach (var bundleFile in Directory.GetFiles(clDir, "*.json", SearchOption.AllDirectories))
                {
                    try
                    {
                        var bytes = await File.ReadAllBytesAsync(bundleFile);
                        var hash = SHA256.HashData(bytes);
                        var digest = Convert.ToHexString(hash).ToLowerInvariant();
                        var relativePath = GetPackRelativePath(packPath, bundleFile);
                        creatorLedgerDigests.Add((digest, relativePath));
                    }
                    catch
                    {
                        // Skip invalid files
                    }
                }
            }
        }

        // Compute file inventory hash for staleness detection
        var fileInventory = manifest.Files
            .OrderBy(f => f.Path, StringComparer.OrdinalIgnoreCase)
            .Select(f => $"{f.Path}:{f.Sha256Hex}:{f.SizeBytes}")
            .ToList();
        var inventoryString = string.Join("\n", fileInventory);
        var inventoryHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(inventoryString))).ToLowerInvariant();

        return new PackIndexInfo
        {
            Success = true,
            PackId = manifest.PackId,
            RootDigest = manifest.RootClaimCoreDigest,
            ManifestHash = manifestHash,
            ManifestSigned = manifestSigned,
            HasClaimsDir = manifest.Include.ClaimsDir != null,
            HasCreatorLedgerDir = manifest.Include.CreatorLedgerDir != null,
            HasRevocationsDir = manifest.Include.RevocationsDir != null,
            HasTsaTrustDir = manifest.Include.TsaTrustDir != null,
            FileInventoryHash = inventoryHash,
            ClaimDigests = claimDigests,
            CreatorLedgerDigests = creatorLedgerDigests
        };
    }

    private static string GetPackRelativePath(string packPath, string filePath)
    {
        var relative = Path.GetRelativePath(packPath, filePath);
        return relative.Replace('\\', '/');
    }

    private static string GetRelativeOrAbsolutePath(string registryPath, string packPath)
    {
        try
        {
            var registryDir = Path.GetFullPath(registryPath);
            var packDir = Path.GetFullPath(packPath);

            // Try to compute relative path
            var relative = Path.GetRelativePath(registryDir, packDir);

            // If relative path doesn't escape too far, use it
            if (!relative.StartsWith("..\\..\\..\\..\\", StringComparison.Ordinal) &&
                !relative.StartsWith("../../../../", StringComparison.Ordinal))
            {
                return relative.Replace('\\', '/');
            }
        }
        catch
        {
            // Fall through to absolute
        }

        return Path.GetFullPath(packPath);
    }

    private static void CopyDirectory(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);

        foreach (var file in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            var relativePath = Path.GetRelativePath(sourceDir, file);
            var destPath = Path.Combine(destDir, relativePath);
            var destFileDir = Path.GetDirectoryName(destPath);
            if (!string.IsNullOrEmpty(destFileDir))
            {
                Directory.CreateDirectory(destFileDir);
            }
            File.Copy(file, destPath, overwrite: true);
        }
    }

    private static void SortIndex(ClaimRegistryIndex index)
    {
        // Sort packs by PackId
        index.Packs.Sort((a, b) => string.Compare(a.PackId, b.PackId, StringComparison.OrdinalIgnoreCase));

        // Sort claim locations within each digest
        foreach (var kvp in index.Claims)
        {
            kvp.Value.Sort((a, b) =>
            {
                var cmp = string.Compare(a.PackId, b.PackId, StringComparison.OrdinalIgnoreCase);
                return cmp != 0 ? cmp : string.Compare(a.RelativePath, b.RelativePath, StringComparison.OrdinalIgnoreCase);
            });
        }

        // Sort bundle locations within each digest
        foreach (var kvp in index.CreatorLedgerBundles)
        {
            kvp.Value.Sort((a, b) =>
            {
                var cmp = string.Compare(a.PackId, b.PackId, StringComparison.OrdinalIgnoreCase);
                return cmp != 0 ? cmp : string.Compare(a.RelativePath, b.RelativePath, StringComparison.OrdinalIgnoreCase);
            });
        }
    }

    private sealed class PackIndexInfo
    {
        public bool Success { get; init; }
        public string? Error { get; init; }
        public string? PackId { get; init; }
        public string? RootDigest { get; init; }
        public string? ManifestHash { get; init; }
        public bool ManifestSigned { get; init; }
        public bool HasClaimsDir { get; init; }
        public bool HasCreatorLedgerDir { get; init; }
        public bool HasRevocationsDir { get; init; }
        public bool HasTsaTrustDir { get; init; }
        public string? FileInventoryHash { get; init; }
        public List<(string Digest, string Path)> ClaimDigests { get; init; } = new();
        public List<(string Digest, string Path)> CreatorLedgerDigests { get; init; } = new();
    }
}

#endregion

#region Build Command

/// <summary>
/// Command to rebuild or refresh the registry index.
/// </summary>
public sealed record BuildRegistryCommand(
    string RegistryPath,
    string? ScanDirectory = null,
    bool Force = false);

/// <summary>
/// Result of registry build.
/// </summary>
public sealed class BuildRegistryResult
{
    public required bool Success { get; init; }
    public string? Error { get; init; }
    public int PacksScanned { get; init; }
    public int PacksAdded { get; init; }
    public int PacksRemoved { get; init; }
    public int PacksStale { get; init; }
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Handles registry rebuild/refresh.
/// </summary>
public static class BuildRegistryHandler
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static async Task<BuildRegistryResult> HandleAsync(BuildRegistryCommand command)
    {
        try
        {
            var registryPath = command.RegistryPath;
            var indexPath = Path.Combine(registryPath, "index.json");

            if (!File.Exists(indexPath))
            {
                return new BuildRegistryResult
                {
                    Success = false,
                    Error = "Registry not found. Run 'registry init' first."
                };
            }

            var indexJson = await File.ReadAllTextAsync(indexPath);
            var index = JsonSerializer.Deserialize<ClaimRegistryIndex>(indexJson)
                ?? throw new JsonException("Failed to deserialize registry index");

            var warnings = new List<string>();
            var packsRemoved = 0;
            var packsStale = 0;

            // Check existing packs for staleness
            var validPacks = new List<PackEntry>();
            foreach (var pack in index.Packs)
            {
                var packPath = ResolvePackPath(registryPath, pack.Path);
                if (!PackExists(packPath, pack.Kind))
                {
                    packsRemoved++;
                    warnings.Add($"Pack removed (not found): {pack.PackId}");
                    continue;
                }

                // Check for staleness
                if (!command.Force)
                {
                    var staleCheck = await CheckPackStalenessAsync(packPath, pack);
                    if (staleCheck.IsStale)
                    {
                        packsStale++;
                        warnings.Add($"Pack stale: {pack.PackId} - {staleCheck.Reason}");
                        // Keep the pack but mark it needs refresh
                    }
                }

                validPacks.Add(pack);
            }

            // If scanning a directory, add new packs
            var packsAdded = 0;
            var packsScanned = 0;

            if (!string.IsNullOrEmpty(command.ScanDirectory) && Directory.Exists(command.ScanDirectory))
            {
                var existingPackIds = validPacks.Select(p => p.PackId).ToHashSet();

                // Find all potential pack directories (have manifest.json)
                foreach (var dir in Directory.GetDirectories(command.ScanDirectory, "*", SearchOption.TopDirectoryOnly))
                {
                    packsScanned++;

                    if (File.Exists(Path.Combine(dir, "manifest.json")))
                    {
                        var addResult = await AddPackToRegistryHandler.HandleAsync(
                            new AddPackToRegistryCommand(registryPath, dir));

                        if (addResult.Success && !existingPackIds.Contains(addResult.PackId!))
                        {
                            packsAdded++;
                        }
                    }
                }

                // Find zip files
                foreach (var zipFile in Directory.GetFiles(command.ScanDirectory, "*.zip", SearchOption.TopDirectoryOnly))
                {
                    packsScanned++;
                    // Zip support would go here
                }
            }

            // If force, rebuild entire index
            if (command.Force)
            {
                // Clear and re-index all claims and bundles
                index.Claims.Clear();
                index.CreatorLedgerBundles.Clear();

                foreach (var pack in validPacks)
                {
                    var packPath = ResolvePackPath(registryPath, pack.Path);
                    await ReindexPackContentsAsync(packPath, pack, index);
                }
            }

            // Update and save
            index.Packs = validPacks;
            index.UpdatedAt = DateTimeOffset.UtcNow.ToString("O");
            AddPackToRegistryHandler_SortIndex(index);

            var updatedJson = JsonSerializer.Serialize(index, JsonOptions);
            await File.WriteAllTextAsync(indexPath, updatedJson);

            return new BuildRegistryResult
            {
                Success = true,
                PacksScanned = packsScanned,
                PacksAdded = packsAdded,
                PacksRemoved = packsRemoved,
                PacksStale = packsStale,
                Warnings = warnings
            };
        }
        catch (Exception ex)
        {
            return new BuildRegistryResult
            {
                Success = false,
                Error = $"Failed to build registry: {ex.Message}"
            };
        }
    }

    private static string ResolvePackPath(string registryPath, string storedPath)
    {
        if (Path.IsPathRooted(storedPath))
            return storedPath;

        return Path.Combine(registryPath, storedPath);
    }

    private static bool PackExists(string path, PackKind kind)
    {
        return kind switch
        {
            PackKind.Directory => Directory.Exists(path) && File.Exists(Path.Combine(path, "manifest.json")),
            PackKind.Zip => File.Exists(path),
            _ => false
        };
    }

    private static async Task<(bool IsStale, string? Reason)> CheckPackStalenessAsync(string packPath, PackEntry entry)
    {
        if (entry.Kind == PackKind.Zip)
        {
            // Zip staleness check not implemented yet
            return (false, null);
        }

        var manifestPath = Path.Combine(packPath, "manifest.json");
        if (!File.Exists(manifestPath))
        {
            return (true, "manifest.json missing");
        }

        // Check manifest hash
        var manifestBytes = await File.ReadAllBytesAsync(manifestPath);
        var currentHash = Convert.ToHexString(SHA256.HashData(manifestBytes)).ToLowerInvariant();

        if (!string.Equals(currentHash, entry.ManifestSha256Hex, StringComparison.OrdinalIgnoreCase))
        {
            return (true, "manifest hash changed");
        }

        return (false, null);
    }

    private static async Task ReindexPackContentsAsync(string packPath, PackEntry pack, ClaimRegistryIndex index)
    {
        if (pack.Kind == PackKind.Zip)
            return; // Not implemented

        // Re-add root claim
        if (!index.Claims.TryGetValue(pack.RootClaimCoreDigest, out var rootLocations))
        {
            rootLocations = new List<ClaimLocation>();
            index.Claims[pack.RootClaimCoreDigest] = rootLocations;
        }
        rootLocations.Add(new ClaimLocation
        {
            PackId = pack.PackId,
            RelativePath = "claim.json"
        });

        // Re-index claims directory
        if (pack.HasClaimsDir)
        {
            var claimsDir = Path.Combine(packPath, "claims");
            if (Directory.Exists(claimsDir))
            {
                foreach (var claimFile in Directory.GetFiles(claimsDir, "*.json", SearchOption.AllDirectories))
                {
                    try
                    {
                        var json = await File.ReadAllTextAsync(claimFile);
                        var bundle = JsonSerializer.Deserialize<ClaimBundle>(json);
                        if (bundle?.Claim != null)
                        {
                            var digest = ClaimCoreDigest.Compute(bundle).ToString();
                            var relativePath = Path.GetRelativePath(packPath, claimFile).Replace('\\', '/');

                            if (!index.Claims.TryGetValue(digest, out var locations))
                            {
                                locations = new List<ClaimLocation>();
                                index.Claims[digest] = locations;
                            }
                            locations.Add(new ClaimLocation
                            {
                                PackId = pack.PackId,
                                RelativePath = relativePath
                            });
                        }
                    }
                    catch
                    {
                        // Skip invalid files
                    }
                }
            }
        }

        // Re-index CreatorLedger bundles
        if (pack.HasCreatorLedgerDir)
        {
            var clDir = Path.Combine(packPath, "creatorledger");
            if (Directory.Exists(clDir))
            {
                foreach (var bundleFile in Directory.GetFiles(clDir, "*.json", SearchOption.AllDirectories))
                {
                    try
                    {
                        var bytes = await File.ReadAllBytesAsync(bundleFile);
                        var hash = SHA256.HashData(bytes);
                        var digest = Convert.ToHexString(hash).ToLowerInvariant();
                        var relativePath = Path.GetRelativePath(packPath, bundleFile).Replace('\\', '/');

                        if (!index.CreatorLedgerBundles.TryGetValue(digest, out var locations))
                        {
                            locations = new List<BundleLocation>();
                            index.CreatorLedgerBundles[digest] = locations;
                        }
                        locations.Add(new BundleLocation
                        {
                            PackId = pack.PackId,
                            RelativePath = relativePath
                        });
                    }
                    catch
                    {
                        // Skip invalid files
                    }
                }
            }
        }
    }

    // Helper to access the sort method from AddPackToRegistryHandler
    private static void AddPackToRegistryHandler_SortIndex(ClaimRegistryIndex index)
    {
        // Duplicate the sorting logic
        index.Packs.Sort((a, b) => string.Compare(a.PackId, b.PackId, StringComparison.OrdinalIgnoreCase));

        foreach (var kvp in index.Claims)
        {
            kvp.Value.Sort((a, b) =>
            {
                var cmp = string.Compare(a.PackId, b.PackId, StringComparison.OrdinalIgnoreCase);
                return cmp != 0 ? cmp : string.Compare(a.RelativePath, b.RelativePath, StringComparison.OrdinalIgnoreCase);
            });
        }

        foreach (var kvp in index.CreatorLedgerBundles)
        {
            kvp.Value.Sort((a, b) =>
            {
                var cmp = string.Compare(a.PackId, b.PackId, StringComparison.OrdinalIgnoreCase);
                return cmp != 0 ? cmp : string.Compare(a.RelativePath, b.RelativePath, StringComparison.OrdinalIgnoreCase);
            });
        }
    }
}

#endregion

#region Query Command

/// <summary>
/// Command to query the registry.
/// </summary>
public sealed record QueryRegistryCommand(
    string RegistryPath,
    string? ClaimDigest = null,
    string? CreatorLedgerDigest = null,
    bool PickFirst = false);

/// <summary>
/// Result of registry query.
/// </summary>
public sealed class QueryRegistryResult
{
    public required bool Success { get; init; }
    public required int ExitCode { get; init; }
    public string? Error { get; init; }
    public IReadOnlyList<QueryMatch> Matches { get; init; } = Array.Empty<QueryMatch>();
    public bool IsAmbiguous { get; init; }
}

/// <summary>
/// A query match result.
/// </summary>
public sealed class QueryMatch
{
    public required string Digest { get; init; }
    public required string Kind { get; init; } // "CLAIM" or "CREATORLEDGER_BUNDLE"
    public required string PackId { get; init; }
    public required string PackPath { get; init; }
    public required string RelativePath { get; init; }
    public required string FullPath { get; init; }
}

/// <summary>
/// Handles registry queries.
/// </summary>
public static class QueryRegistryHandler
{
    public static async Task<QueryRegistryResult> HandleAsync(QueryRegistryCommand command)
    {
        try
        {
            var registryPath = command.RegistryPath;
            var indexPath = Path.Combine(registryPath, "index.json");

            if (!File.Exists(indexPath))
            {
                return new QueryRegistryResult
                {
                    Success = false,
                    ExitCode = 4,
                    Error = "Registry not found"
                };
            }

            var indexJson = await File.ReadAllTextAsync(indexPath);
            var index = JsonSerializer.Deserialize<ClaimRegistryIndex>(indexJson)
                ?? throw new JsonException("Failed to deserialize registry index");

            // Build pack lookup
            var packLookup = index.Packs.ToDictionary(p => p.PackId, p => p);

            var matches = new List<QueryMatch>();

            // Query claims
            if (!string.IsNullOrEmpty(command.ClaimDigest))
            {
                var digestLower = command.ClaimDigest.ToLowerInvariant();

                // Exact match first
                if (index.Claims.TryGetValue(digestLower, out var exactLocations))
                {
                    foreach (var loc in exactLocations)
                    {
                        if (packLookup.TryGetValue(loc.PackId, out var pack))
                        {
                            var packPath = ResolvePackPath(registryPath, pack.Path);
                            matches.Add(new QueryMatch
                            {
                                Digest = digestLower,
                                Kind = "CLAIM",
                                PackId = loc.PackId,
                                PackPath = pack.Path,
                                RelativePath = loc.RelativePath,
                                FullPath = Path.Combine(packPath, loc.RelativePath)
                            });
                        }
                    }
                }
                else
                {
                    // Try prefix match
                    var prefixMatches = index.Claims
                        .Where(kvp => kvp.Key.StartsWith(digestLower, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    foreach (var kvp in prefixMatches)
                    {
                        foreach (var loc in kvp.Value)
                        {
                            if (packLookup.TryGetValue(loc.PackId, out var pack))
                            {
                                var packPath = ResolvePackPath(registryPath, pack.Path);
                                matches.Add(new QueryMatch
                                {
                                    Digest = kvp.Key,
                                    Kind = "CLAIM",
                                    PackId = loc.PackId,
                                    PackPath = pack.Path,
                                    RelativePath = loc.RelativePath,
                                    FullPath = Path.Combine(packPath, loc.RelativePath)
                                });
                            }
                        }
                    }
                }
            }

            // Query CreatorLedger bundles
            if (!string.IsNullOrEmpty(command.CreatorLedgerDigest))
            {
                var digestLower = command.CreatorLedgerDigest.ToLowerInvariant();

                // Exact match first
                if (index.CreatorLedgerBundles.TryGetValue(digestLower, out var exactLocations))
                {
                    foreach (var loc in exactLocations)
                    {
                        if (packLookup.TryGetValue(loc.PackId, out var pack))
                        {
                            var packPath = ResolvePackPath(registryPath, pack.Path);
                            matches.Add(new QueryMatch
                            {
                                Digest = digestLower,
                                Kind = "CREATORLEDGER_BUNDLE",
                                PackId = loc.PackId,
                                PackPath = pack.Path,
                                RelativePath = loc.RelativePath,
                                FullPath = Path.Combine(packPath, loc.RelativePath)
                            });
                        }
                    }
                }
                else
                {
                    // Try prefix match
                    var prefixMatches = index.CreatorLedgerBundles
                        .Where(kvp => kvp.Key.StartsWith(digestLower, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    foreach (var kvp in prefixMatches)
                    {
                        foreach (var loc in kvp.Value)
                        {
                            if (packLookup.TryGetValue(loc.PackId, out var pack))
                            {
                                var packPath = ResolvePackPath(registryPath, pack.Path);
                                matches.Add(new QueryMatch
                                {
                                    Digest = kvp.Key,
                                    Kind = "CREATORLEDGER_BUNDLE",
                                    PackId = loc.PackId,
                                    PackPath = pack.Path,
                                    RelativePath = loc.RelativePath,
                                    FullPath = Path.Combine(packPath, loc.RelativePath)
                                });
                            }
                        }
                    }
                }
            }

            if (matches.Count == 0)
            {
                return new QueryRegistryResult
                {
                    Success = true,
                    ExitCode = 0,
                    Matches = matches
                };
            }

            // Check for ambiguity (multiple distinct digests)
            var distinctDigests = matches.Select(m => m.Digest).Distinct().ToList();
            if (distinctDigests.Count > 1)
            {
                if (command.PickFirst)
                {
                    // Return only matches for the first digest
                    var firstDigest = distinctDigests[0];
                    matches = matches.Where(m => m.Digest == firstDigest).ToList();
                }
                else
                {
                    return new QueryRegistryResult
                    {
                        Success = false,
                        ExitCode = 4,
                        Error = $"Ambiguous prefix: {distinctDigests.Count} distinct digests match. Use full digest or --pick-first.",
                        Matches = matches,
                        IsAmbiguous = true
                    };
                }
            }

            return new QueryRegistryResult
            {
                Success = true,
                ExitCode = 0,
                Matches = matches
            };
        }
        catch (Exception ex)
        {
            return new QueryRegistryResult
            {
                Success = false,
                ExitCode = 5,
                Error = $"Query failed: {ex.Message}"
            };
        }
    }

    private static string ResolvePackPath(string registryPath, string storedPath)
    {
        if (Path.IsPathRooted(storedPath))
            return storedPath;

        return Path.Combine(registryPath, storedPath);
    }
}

#endregion
