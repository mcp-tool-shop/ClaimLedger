using System.Security.Cryptography;
using System.Text.Json;
using ClaimLedger.Application.Export;
using ClaimLedger.Domain.Packs;
using ClaimLedger.Domain.Registry;

namespace ClaimLedger.Application.Registry;

/// <summary>
/// Resolves claims and bundles from a local registry.
/// </summary>
public sealed class RegistryResolver
{
    private readonly string _registryPath;
    private readonly ClaimRegistryIndex _index;
    private readonly Dictionary<string, PackEntry> _packLookup;
    private readonly bool _strict;
    private readonly List<string> _warnings = new();
    private readonly List<string> _errors = new();

    private RegistryResolver(
        string registryPath,
        ClaimRegistryIndex index,
        bool strict)
    {
        _registryPath = registryPath;
        _index = index;
        _packLookup = index.Packs.ToDictionary(p => p.PackId, p => p);
        _strict = strict;
    }

    /// <summary>
    /// Loads a registry and creates a resolver.
    /// </summary>
    public static async Task<RegistryResolverResult> LoadAsync(string registryPath, bool strict = false)
    {
        var indexPath = Path.Combine(registryPath, "index.json");

        if (!File.Exists(indexPath))
        {
            return new RegistryResolverResult
            {
                Success = false,
                Error = $"Registry not found: {registryPath}"
            };
        }

        try
        {
            var indexJson = await File.ReadAllTextAsync(indexPath);
            var index = JsonSerializer.Deserialize<ClaimRegistryIndex>(indexJson);

            if (index == null)
            {
                return new RegistryResolverResult
                {
                    Success = false,
                    Error = "Failed to parse registry index"
                };
            }

            if (index.Contract != ClaimRegistryIndex.ContractVersion)
            {
                return new RegistryResolverResult
                {
                    Success = false,
                    Error = $"Unsupported registry contract: {index.Contract}"
                };
            }

            var resolver = new RegistryResolver(registryPath, index, strict);

            return new RegistryResolverResult
            {
                Success = true,
                Resolver = resolver
            };
        }
        catch (Exception ex)
        {
            return new RegistryResolverResult
            {
                Success = false,
                Error = $"Failed to load registry: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Gets accumulated warnings.
    /// </summary>
    public IReadOnlyList<string> Warnings => _warnings;

    /// <summary>
    /// Gets accumulated errors.
    /// </summary>
    public IReadOnlyList<string> Errors => _errors;

    /// <summary>
    /// Attempts to resolve a claim bundle by its claim_core_digest.
    /// </summary>
    public async Task<ResolveClaimResult> ResolveClaimAsync(string claimCoreDigest)
    {
        var digestLower = claimCoreDigest.ToLowerInvariant();

        if (!_index.Claims.TryGetValue(digestLower, out var locations) || locations.Count == 0)
        {
            return new ResolveClaimResult
            {
                Status = ResolveStatus.NotFound
            };
        }

        // Check for ambiguity (multiple packs)
        if (locations.Count > 1)
        {
            var packIds = locations.Select(l => l.PackId).Distinct().ToList();
            if (packIds.Count > 1)
            {
                if (_strict)
                {
                    var msg = $"Ambiguous claim resolution for {digestLower}: found in {packIds.Count} packs [{string.Join(", ", packIds)}]";
                    _errors.Add(msg);
                    return new ResolveClaimResult
                    {
                        Status = ResolveStatus.Ambiguous,
                        Error = msg,
                        CandidatePackIds = packIds
                    };
                }

                _warnings.Add($"Ambiguous claim resolution for {digestLower}: found in {packIds.Count} packs");
                // Non-strict: treat as unresolved
                return new ResolveClaimResult
                {
                    Status = ResolveStatus.Ambiguous,
                    CandidatePackIds = packIds
                };
            }
        }

        // Single candidate - resolve it
        var location = locations[0];

        if (!_packLookup.TryGetValue(location.PackId, out var pack))
        {
            var msg = $"Pack {location.PackId} not found in registry";
            if (_strict) _errors.Add(msg);
            else _warnings.Add(msg);

            return new ResolveClaimResult
            {
                Status = ResolveStatus.PackNotFound,
                Error = msg
            };
        }

        // Validate pack exists
        var packPath = ResolvePackPath(pack.Path);
        var staleCheck = await CheckPackStalenessAsync(packPath, pack);

        if (staleCheck.IsStale)
        {
            var msg = $"Pack {pack.PackId} is stale: {staleCheck.Reason}";
            if (_strict)
            {
                _errors.Add(msg);
                return new ResolveClaimResult
                {
                    Status = ResolveStatus.Stale,
                    Error = msg
                };
            }

            _warnings.Add(msg);
        }

        // Load the claim bundle
        var claimPath = Path.Combine(packPath, location.RelativePath);
        if (!File.Exists(claimPath))
        {
            var msg = $"Claim file not found: {claimPath}";
            if (_strict) _errors.Add(msg);
            else _warnings.Add(msg);

            return new ResolveClaimResult
            {
                Status = ResolveStatus.FileNotFound,
                Error = msg
            };
        }

        try
        {
            var json = await File.ReadAllTextAsync(claimPath);
            var bundle = JsonSerializer.Deserialize<ClaimBundle>(json);

            if (bundle == null)
            {
                return new ResolveClaimResult
                {
                    Status = ResolveStatus.InvalidContent,
                    Error = "Failed to parse claim bundle"
                };
            }

            return new ResolveClaimResult
            {
                Status = ResolveStatus.Resolved,
                Bundle = bundle,
                SourcePackId = pack.PackId,
                SourcePath = claimPath
            };
        }
        catch (Exception ex)
        {
            return new ResolveClaimResult
            {
                Status = ResolveStatus.InvalidContent,
                Error = $"Failed to load claim: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Attempts to resolve a CreatorLedger bundle by its digest.
    /// </summary>
    public async Task<ResolveBundleResult> ResolveCreatorLedgerBundleAsync(string bundleDigest)
    {
        var digestLower = bundleDigest.ToLowerInvariant();

        if (!_index.CreatorLedgerBundles.TryGetValue(digestLower, out var locations) || locations.Count == 0)
        {
            return new ResolveBundleResult
            {
                Status = ResolveStatus.NotFound
            };
        }

        // Check for ambiguity
        if (locations.Count > 1)
        {
            var packIds = locations.Select(l => l.PackId).Distinct().ToList();
            if (packIds.Count > 1)
            {
                if (_strict)
                {
                    var msg = $"Ambiguous bundle resolution for {digestLower}: found in {packIds.Count} packs [{string.Join(", ", packIds)}]";
                    _errors.Add(msg);
                    return new ResolveBundleResult
                    {
                        Status = ResolveStatus.Ambiguous,
                        Error = msg,
                        CandidatePackIds = packIds
                    };
                }

                _warnings.Add($"Ambiguous bundle resolution for {digestLower}: found in {packIds.Count} packs");
                return new ResolveBundleResult
                {
                    Status = ResolveStatus.Ambiguous,
                    CandidatePackIds = packIds
                };
            }
        }

        // Single candidate
        var location = locations[0];

        if (!_packLookup.TryGetValue(location.PackId, out var pack))
        {
            var msg = $"Pack {location.PackId} not found in registry";
            if (_strict) _errors.Add(msg);
            else _warnings.Add(msg);

            return new ResolveBundleResult
            {
                Status = ResolveStatus.PackNotFound,
                Error = msg
            };
        }

        // Validate pack exists
        var packPath = ResolvePackPath(pack.Path);
        var staleCheck = await CheckPackStalenessAsync(packPath, pack);

        if (staleCheck.IsStale)
        {
            var msg = $"Pack {pack.PackId} is stale: {staleCheck.Reason}";
            if (_strict)
            {
                _errors.Add(msg);
                return new ResolveBundleResult
                {
                    Status = ResolveStatus.Stale,
                    Error = msg
                };
            }

            _warnings.Add(msg);
        }

        // Load the bundle
        var bundlePath = Path.Combine(packPath, location.RelativePath);
        if (!File.Exists(bundlePath))
        {
            var msg = $"Bundle file not found: {bundlePath}";
            if (_strict) _errors.Add(msg);
            else _warnings.Add(msg);

            return new ResolveBundleResult
            {
                Status = ResolveStatus.FileNotFound,
                Error = msg
            };
        }

        try
        {
            var bytes = await File.ReadAllBytesAsync(bundlePath);

            return new ResolveBundleResult
            {
                Status = ResolveStatus.Resolved,
                BundleBytes = bytes,
                SourcePackId = pack.PackId,
                SourcePath = bundlePath
            };
        }
        catch (Exception ex)
        {
            return new ResolveBundleResult
            {
                Status = ResolveStatus.InvalidContent,
                Error = $"Failed to load bundle: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Builds a dictionary of resolved claim bundles for citation verification.
    /// </summary>
    public async Task<Dictionary<string, ClaimBundle>> ResolveClaimsForCitationsAsync(
        IEnumerable<string> requiredDigests,
        Dictionary<string, ClaimBundle>? existingResolved = null)
    {
        var result = new Dictionary<string, ClaimBundle>(StringComparer.OrdinalIgnoreCase);

        // Copy existing
        if (existingResolved != null)
        {
            foreach (var (digest, bundle) in existingResolved)
            {
                result[digest] = bundle;
            }
        }

        // Resolve missing
        foreach (var digest in requiredDigests)
        {
            if (result.ContainsKey(digest))
                continue;

            var resolved = await ResolveClaimAsync(digest);
            if (resolved.Status == ResolveStatus.Resolved && resolved.Bundle != null)
            {
                result[digest] = resolved.Bundle;
            }
        }

        return result;
    }

    private string ResolvePackPath(string storedPath)
    {
        if (Path.IsPathRooted(storedPath))
            return storedPath;

        return Path.Combine(_registryPath, storedPath);
    }

    private static async Task<(bool IsStale, string? Reason)> CheckPackStalenessAsync(string packPath, PackEntry entry)
    {
        if (entry.Kind == PackKind.Zip)
        {
            if (!File.Exists(packPath))
            {
                return (true, "zip file missing");
            }
            return (false, null);
        }

        if (!Directory.Exists(packPath))
        {
            return (true, "directory missing");
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
}

/// <summary>
/// Result of loading a registry resolver.
/// </summary>
public sealed class RegistryResolverResult
{
    public required bool Success { get; init; }
    public string? Error { get; init; }
    public RegistryResolver? Resolver { get; init; }
}

/// <summary>
/// Status of a resolution attempt.
/// </summary>
public enum ResolveStatus
{
    Resolved,
    NotFound,
    Ambiguous,
    PackNotFound,
    Stale,
    FileNotFound,
    InvalidContent
}

/// <summary>
/// Result of resolving a claim.
/// </summary>
public sealed class ResolveClaimResult
{
    public required ResolveStatus Status { get; init; }
    public string? Error { get; init; }
    public ClaimBundle? Bundle { get; init; }
    public string? SourcePackId { get; init; }
    public string? SourcePath { get; init; }
    public IReadOnlyList<string>? CandidatePackIds { get; init; }
}

/// <summary>
/// Result of resolving a CreatorLedger bundle.
/// </summary>
public sealed class ResolveBundleResult
{
    public required ResolveStatus Status { get; init; }
    public string? Error { get; init; }
    public byte[]? BundleBytes { get; init; }
    public string? SourcePackId { get; init; }
    public string? SourcePath { get; init; }
    public IReadOnlyList<string>? CandidatePackIds { get; init; }
}
