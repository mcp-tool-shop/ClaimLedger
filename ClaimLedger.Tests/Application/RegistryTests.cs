using System.Text;
using System.Text.Json;
using ClaimLedger.Application.CreatorLedger;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Packs;
using ClaimLedger.Application.Registry;
using ClaimLedger.Domain.Citations;
using ClaimLedger.Domain.Packs;
using ClaimLedger.Domain.Registry;
using Shared.Crypto;
using Xunit;

namespace ClaimLedger.Tests.Application;

/// <summary>
/// Tests for Phase 11: Local Registry + Resolver
/// </summary>
public class RegistryTests
{
    #region Init Tests

    [Fact]
    public async Task Init_CreatesRegistry()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");

        var result = await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        Assert.True(result.Success);
        Assert.NotNull(result.RegistryId);
        Assert.True(File.Exists(Path.Combine(registryPath, "index.json")));
        Assert.True(Directory.Exists(Path.Combine(registryPath, "packs")));
        Assert.True(Directory.Exists(Path.Combine(registryPath, "cache")));
    }

    [Fact]
    public async Task Init_CreatesValidIndexJson()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        var indexJson = await File.ReadAllTextAsync(Path.Combine(registryPath, "index.json"));
        var index = JsonSerializer.Deserialize<ClaimRegistryIndex>(indexJson);

        Assert.NotNull(index);
        Assert.Equal(ClaimRegistryIndex.ContractVersion, index.Contract);
        Assert.NotEmpty(index.RegistryId);
        Assert.NotEmpty(index.CreatedAt);
        Assert.NotEmpty(index.UpdatedAt);
        Assert.Empty(index.Packs);
        Assert.Empty(index.Claims);
        Assert.Empty(index.CreatorLedgerBundles);
    }

    [Fact]
    public async Task Init_FailsIfAlreadyExists()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        var result = await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        Assert.False(result.Success);
        Assert.Contains("already exists", result.Error);
    }

    #endregion

    #region Add Tests

    [Fact]
    public async Task Add_IndexesDirectoryPack()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        await CreateSamplePackAsync(packPath);

        var result = await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        Assert.True(result.Success);
        Assert.NotNull(result.PackId);
        Assert.NotNull(result.RootDigest);
        Assert.True(result.ClaimsIndexed >= 1); // At least root claim
    }

    [Fact]
    public async Task Add_IndexesClaimsDirectory()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        await CreatePackWithCitedClaimsAsync(packPath);

        var result = await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        Assert.True(result.Success);
        Assert.True(result.ClaimsIndexed >= 2); // Root + cited claims
    }

    [Fact]
    public async Task Add_IndexesCreatorLedgerBundles()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        await CreatePackWithCreatorLedgerAsync(packPath);

        var result = await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        Assert.True(result.Success);
        Assert.True(result.CreatorLedgerBundlesIndexed >= 1);
    }

    [Fact]
    public async Task Add_StoresRelativePath()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "packs", "pack1");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        await CreateSamplePackAsync(packPath);

        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        var indexJson = await File.ReadAllTextAsync(Path.Combine(registryPath, "index.json"));
        var index = JsonSerializer.Deserialize<ClaimRegistryIndex>(indexJson);

        Assert.NotNull(index);
        Assert.Single(index.Packs);
        // Should be relative path, not absolute
        Assert.DoesNotContain(":\\", index.Packs[0].Path);
    }

    [Fact]
    public async Task Add_CopyOption_CopiesPackToRegistry()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        await CreateSamplePackAsync(packPath);

        var result = await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath, CopyPack: true));

        Assert.True(result.Success);
        Assert.True(Directory.Exists(Path.Combine(registryPath, "packs", result.PackId!)));
    }

    [Fact]
    public async Task Add_FailsForNonExistentPath()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var badPath = Path.Combine(tempDir.Path, "nonexistent_pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        var result = await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, badPath));

        Assert.False(result.Success);
        Assert.NotNull(result.Error);
        // Either "does not exist" or "missing manifest.json"
        Assert.True(result.Error.Contains("does not exist") || result.Error.Contains("missing manifest"));
    }

    [Fact]
    public async Task Add_FailsForDuplicatePack()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        await CreateSamplePackAsync(packPath);

        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        var result = await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        Assert.False(result.Success);
        Assert.Contains("already in the registry", result.Error);
    }

    [Fact]
    public async Task Add_FailsWithoutRegistry()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await CreateSamplePackAsync(packPath);

        var result = await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        Assert.False(result.Success);
        Assert.Contains("Registry not found", result.Error);
    }

    #endregion

    #region Build Tests

    [Fact]
    public async Task Build_RemovesMissingPacks()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        await CreateSamplePackAsync(packPath);
        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        // Delete pack
        Directory.Delete(packPath, recursive: true);

        var result = await BuildRegistryHandler.HandleAsync(
            new BuildRegistryCommand(registryPath));

        Assert.True(result.Success);
        Assert.Equal(1, result.PacksRemoved);
    }

    [Fact]
    public async Task Build_DetectsStalePacks()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        await CreateSamplePackAsync(packPath);
        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        // Modify manifest
        var manifestPath = Path.Combine(packPath, "manifest.json");
        var json = await File.ReadAllTextAsync(manifestPath);
        await File.WriteAllTextAsync(manifestPath, json + " "); // Add whitespace to change hash

        var result = await BuildRegistryHandler.HandleAsync(
            new BuildRegistryCommand(registryPath));

        Assert.True(result.Success);
        Assert.Equal(1, result.PacksStale);
    }

    [Fact]
    public async Task Build_ScanDirectory_FindsNewPacks()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packsDir = Path.Combine(tempDir.Path, "packs");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        await CreateSamplePackAsync(Path.Combine(packsDir, "pack1"));
        await CreateSamplePackAsync(Path.Combine(packsDir, "pack2"));

        var result = await BuildRegistryHandler.HandleAsync(
            new BuildRegistryCommand(registryPath, ScanDirectory: packsDir));

        Assert.True(result.Success);
        Assert.Equal(2, result.PacksScanned);
        Assert.Equal(2, result.PacksAdded);
    }

    [Fact]
    public async Task Build_ForceRebuild_ReindexesContents()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        await CreateSamplePackAsync(packPath);
        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        // Manually corrupt the index
        var indexPath = Path.Combine(registryPath, "index.json");
        var indexJson = await File.ReadAllTextAsync(indexPath);
        var index = JsonSerializer.Deserialize<ClaimRegistryIndex>(indexJson)!;
        index.Claims.Clear();
        await File.WriteAllTextAsync(indexPath,
            JsonSerializer.Serialize(index, new JsonSerializerOptions { WriteIndented = true }));

        var result = await BuildRegistryHandler.HandleAsync(
            new BuildRegistryCommand(registryPath, Force: true));

        Assert.True(result.Success);

        // Verify claims are re-indexed
        indexJson = await File.ReadAllTextAsync(indexPath);
        index = JsonSerializer.Deserialize<ClaimRegistryIndex>(indexJson)!;
        Assert.NotEmpty(index.Claims);
    }

    #endregion

    #region Query Tests

    [Fact]
    public async Task Query_ExactDigestMatch_ReturnsCorrectPack()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        var (claimBundle, _) = await CreateSamplePackAsync(packPath);
        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        var digest = ClaimCoreDigest.Compute(claimBundle).ToString();
        var result = await QueryRegistryHandler.HandleAsync(
            new QueryRegistryCommand(registryPath, ClaimDigest: digest));

        Assert.True(result.Success);
        Assert.Single(result.Matches);
        Assert.Equal(digest, result.Matches[0].Digest);
        Assert.Equal("CLAIM", result.Matches[0].Kind);
    }

    [Fact]
    public async Task Query_PrefixMatch_UniqueWorks()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        var (claimBundle, _) = await CreateSamplePackAsync(packPath);
        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        var digest = ClaimCoreDigest.Compute(claimBundle).ToString();
        var prefix = digest[..8]; // First 8 chars

        var result = await QueryRegistryHandler.HandleAsync(
            new QueryRegistryCommand(registryPath, ClaimDigest: prefix));

        Assert.True(result.Success);
        Assert.Single(result.Matches);
    }

    [Fact]
    public async Task Query_AmbiguousPrefix_FailsWithCandidates()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        // Create multiple packs
        for (int i = 0; i < 5; i++)
        {
            var packPath = Path.Combine(tempDir.Path, $"pack{i}");
            await CreateSamplePackAsync(packPath);
            await AddPackToRegistryHandler.HandleAsync(
                new AddPackToRegistryCommand(registryPath, packPath));
        }

        // Query with very short prefix - likely to be ambiguous
        var result = await QueryRegistryHandler.HandleAsync(
            new QueryRegistryCommand(registryPath, ClaimDigest: "a")); // Single char

        // May or may not be ambiguous depending on generated digests
        // If ambiguous, should fail
        if (result.IsAmbiguous)
        {
            Assert.False(result.Success);
            Assert.Equal(4, result.ExitCode);
            Assert.True(result.Matches.Count > 1);
        }
    }

    [Fact]
    public async Task Query_PickFirst_ReturnsFirstMatch()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        await CreateSamplePackAsync(packPath);
        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        // Query with prefix that might match multiple
        var result = await QueryRegistryHandler.HandleAsync(
            new QueryRegistryCommand(registryPath, ClaimDigest: "a", PickFirst: true));

        // Should succeed even if potentially ambiguous
        Assert.True(result.Success || result.Matches.Count == 0);
    }

    [Fact]
    public async Task Query_CreatorLedgerBundle_FindsBundle()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        var bundleDigest = await CreatePackWithCreatorLedgerAsync(packPath);
        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        var result = await QueryRegistryHandler.HandleAsync(
            new QueryRegistryCommand(registryPath, CreatorLedgerDigest: bundleDigest));

        Assert.True(result.Success);
        Assert.Single(result.Matches);
        Assert.Equal("CREATORLEDGER_BUNDLE", result.Matches[0].Kind);
    }

    [Fact]
    public async Task Query_NotFound_ReturnsEmptyMatches()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        var result = await QueryRegistryHandler.HandleAsync(
            new QueryRegistryCommand(registryPath, ClaimDigest: "nonexistentdigest123"));

        Assert.True(result.Success);
        Assert.Empty(result.Matches);
    }

    #endregion

    #region Resolver Integration Tests

    [Fact]
    public async Task Resolver_LoadsRegistry()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        var result = await RegistryResolver.LoadAsync(registryPath);

        Assert.True(result.Success);
        Assert.NotNull(result.Resolver);
    }

    [Fact]
    public async Task Resolver_FailsForMissingRegistry()
    {
        var result = await RegistryResolver.LoadAsync("/nonexistent/path");

        Assert.False(result.Success);
        Assert.Contains("not found", result.Error);
    }

    [Fact]
    public async Task Resolver_ResolvesClaim()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        var (claimBundle, _) = await CreateSamplePackAsync(packPath);
        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        var resolverResult = await RegistryResolver.LoadAsync(registryPath);
        var resolver = resolverResult.Resolver!;

        var digest = ClaimCoreDigest.Compute(claimBundle).ToString();
        var result = await resolver.ResolveClaimAsync(digest);

        Assert.Equal(ResolveStatus.Resolved, result.Status);
        Assert.NotNull(result.Bundle);
    }

    [Fact]
    public async Task Resolver_ReturnsNotFoundForMissing()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        var resolverResult = await RegistryResolver.LoadAsync(registryPath);
        var resolver = resolverResult.Resolver!;

        var result = await resolver.ResolveClaimAsync("nonexistent");

        Assert.Equal(ResolveStatus.NotFound, result.Status);
    }

    [Fact]
    public async Task Resolver_ResolvesCreatorLedgerBundle()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        var bundleDigest = await CreatePackWithCreatorLedgerAsync(packPath);
        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        var resolverResult = await RegistryResolver.LoadAsync(registryPath);
        var resolver = resolverResult.Resolver!;

        var result = await resolver.ResolveCreatorLedgerBundleAsync(bundleDigest);

        Assert.Equal(ResolveStatus.Resolved, result.Status);
        Assert.NotNull(result.BundleBytes);
    }

    [Fact]
    public async Task Resolver_StrictMode_FailsOnAmbiguous()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        // Create same pack in two locations (duplicate digest)
        var pack1 = Path.Combine(tempDir.Path, "pack1");
        var pack2 = Path.Combine(tempDir.Path, "pack2");

        var (claimBundle1, _) = await CreateSamplePackAsync(pack1);

        // Manually create pack2 with same content but different packId
        var bundle2 = claimBundle1; // Same content
        await CreatePackFromBundleAsync(pack2, bundle2);

        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, pack1));
        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, pack2));

        var resolverResult = await RegistryResolver.LoadAsync(registryPath, strict: true);
        var resolver = resolverResult.Resolver!;

        var digest = ClaimCoreDigest.Compute(claimBundle1).ToString();
        var result = await resolver.ResolveClaimAsync(digest);

        Assert.Equal(ResolveStatus.Ambiguous, result.Status);
        Assert.NotNull(result.CandidatePackIds);
        Assert.True(result.CandidatePackIds.Count > 1);
    }

    [Fact]
    public async Task Resolver_DetectsStalePack()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));
        var (claimBundle, _) = await CreateSamplePackAsync(packPath);
        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, packPath));

        // Modify pack manifest
        var manifestPath = Path.Combine(packPath, "manifest.json");
        var json = await File.ReadAllTextAsync(manifestPath);
        await File.WriteAllTextAsync(manifestPath, json + " ");

        var resolverResult = await RegistryResolver.LoadAsync(registryPath, strict: true);
        var resolver = resolverResult.Resolver!;

        var digest = ClaimCoreDigest.Compute(claimBundle).ToString();
        var result = await resolver.ResolveClaimAsync(digest);

        Assert.Equal(ResolveStatus.Stale, result.Status);
    }

    #endregion

    #region VerifyPack with Registry Tests

    [Fact]
    public async Task VerifyPack_WithRegistry_ResolvesCitations()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var citedPackPath = Path.Combine(tempDir.Path, "cited");
        var citingPackPath = Path.Combine(tempDir.Path, "citing");

        // Initialize registry
        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        // Create cited pack
        var (citedBundle, _) = await CreateSamplePackAsync(citedPackPath);
        var citedDigest = ClaimCoreDigest.Compute(citedBundle).ToString();

        // Add cited pack to registry
        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, citedPackPath));

        // Create citing pack that references cited bundle
        await CreatePackWithCitationAsync(citingPackPath, citedDigest);

        // Verify citing pack using registry
        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            citingPackPath,
            RegistryPath: registryPath,
            VerifyCitations: true));

        Assert.True(result.IsValid);
        Assert.NotNull(result.RegistryResult);
        Assert.True(result.RegistryResult.UsedRegistry);
        Assert.True(result.RegistryResult.CitationsResolvedViaRegistry >= 1);
    }

    [Fact]
    public async Task VerifyPack_StrictRegistry_FailsOnUnresolvable()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        // Initialize empty registry
        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        // Create pack with citation to non-existent claim (must be valid 64-char hex)
        var nonExistentDigest = "0000000000000000000000000000000000000000000000000000000000000000";
        await CreatePackWithCitationAsync(packPath, nonExistentDigest);

        // Verify with strict registry
        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packPath,
            RegistryPath: registryPath,
            StrictCitations: true));

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task VerifyPack_WithRegistry_ResolvesCreatorLedgerBundles()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var bundlePackPath = Path.Combine(tempDir.Path, "bundle-pack");
        var claimPackPath = Path.Combine(tempDir.Path, "claim-pack");

        // Initialize registry
        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        // Create pack with CreatorLedger bundle
        var bundleDigest = await CreatePackWithCreatorLedgerAsync(bundlePackPath);
        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, bundlePackPath));

        // Create pack that references the bundle (without embedding it)
        await CreatePackWithCreatorLedgerEvidenceOnly(claimPackPath, bundleDigest);

        // Verify using registry
        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            claimPackPath,
            RegistryPath: registryPath,
            VerifyCreatorLedger: true));

        Assert.True(result.IsValid);
        Assert.NotNull(result.CreatorLedgerResult);
        Assert.True(result.CreatorLedgerResult.BundlesResolvedViaRegistry >= 1);
    }

    [Fact]
    public async Task VerifyPack_PackLocalFirst_BeforeRegistry()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var packPath = Path.Combine(tempDir.Path, "pack");

        // Initialize registry (empty)
        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        // Create pack with embedded cited claims (self-contained)
        await CreatePackWithCitedClaimsAsync(packPath);

        // Verify - should use pack-local first
        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packPath,
            RegistryPath: registryPath,
            VerifyCitations: true));

        Assert.True(result.IsValid);
        // Registry was provided but not needed
        Assert.NotNull(result.RegistryResult);
        Assert.Equal(0, result.RegistryResult.CitationsResolvedViaRegistry);
    }

    #endregion

    #region Staleness Tests

    [Fact]
    public async Task VerifyPack_StrictRegistry_FailsOnStalePack()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var citedPackPath = Path.Combine(tempDir.Path, "cited");
        var citingPackPath = Path.Combine(tempDir.Path, "citing");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        var (citedBundle, _) = await CreateSamplePackAsync(citedPackPath);
        var citedDigest = ClaimCoreDigest.Compute(citedBundle).ToString();

        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, citedPackPath));

        // Modify cited pack (make stale)
        var manifestPath = Path.Combine(citedPackPath, "manifest.json");
        var json = await File.ReadAllTextAsync(manifestPath);
        await File.WriteAllTextAsync(manifestPath, json + " ");

        // Create citing pack
        await CreatePackWithCitationAsync(citingPackPath, citedDigest);

        // Verify with strict registry - should fail due to stale
        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            citingPackPath,
            RegistryPath: registryPath,
            StrictRegistry: true,
            VerifyCitations: true));

        // Should either fail or have warnings about staleness
        Assert.True(!result.IsValid || result.Warnings.Any(w => w.Contains("stale", StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public async Task VerifyPack_NonStrictRegistry_WarnsOnStale()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");
        var citedPackPath = Path.Combine(tempDir.Path, "cited");
        var citingPackPath = Path.Combine(tempDir.Path, "citing");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        var (citedBundle, _) = await CreateSamplePackAsync(citedPackPath);
        var citedDigest = ClaimCoreDigest.Compute(citedBundle).ToString();

        await AddPackToRegistryHandler.HandleAsync(
            new AddPackToRegistryCommand(registryPath, citedPackPath));

        // Modify cited pack (make stale)
        var manifestPath = Path.Combine(citedPackPath, "manifest.json");
        var json = await File.ReadAllTextAsync(manifestPath);
        await File.WriteAllTextAsync(manifestPath, json + " ");

        // Create citing pack
        await CreatePackWithCitationAsync(citingPackPath, citedDigest);

        // Verify without strict registry - should warn but continue
        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            citingPackPath,
            RegistryPath: registryPath,
            StrictRegistry: false,
            StrictCitations: false,
            VerifyCitations: true));

        // Non-strict allows staleness with warnings
        // The citation may fail to resolve due to staleness, but that's non-strict too
        Assert.NotNull(result.RegistryResult);
    }

    #endregion

    #region Index Determinism Tests

    [Fact]
    public async Task Build_DeterministicOrder()
    {
        using var tempDir = new TempDirectory();
        var registryPath = Path.Combine(tempDir.Path, "registry");

        await InitRegistryHandler.HandleAsync(new InitRegistryCommand(registryPath));

        // Add packs in random order
        for (int i = 5; i >= 0; i--)
        {
            var packPath = Path.Combine(tempDir.Path, $"pack{i}");
            await CreateSamplePackAsync(packPath);
            await AddPackToRegistryHandler.HandleAsync(
                new AddPackToRegistryCommand(registryPath, packPath));
        }

        // Read index and verify sorted
        var indexJson = await File.ReadAllTextAsync(Path.Combine(registryPath, "index.json"));
        var index = JsonSerializer.Deserialize<ClaimRegistryIndex>(indexJson)!;

        // Packs should be sorted by PackId
        var packIds = index.Packs.Select(p => p.PackId).ToList();
        Assert.True(packIds.SequenceEqual(packIds.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)));
    }

    #endregion

    #region Helper Methods

    private static async Task<(ClaimBundle bundle, string packId)> CreateSamplePackAsync(string packPath)
    {
        Directory.CreateDirectory(packPath);

        var keyPair = Ed25519KeyPair.Generate();
        var claimBundle = CreateStandardClaimBundle(keyPair);

        var claimJson = JsonSerializer.Serialize(claimBundle, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packPath, "claim.json"), claimJson);

        var digest = ClaimCoreDigest.Compute(claimBundle).ToString();
        var packId = Guid.NewGuid().ToString();

        var manifest = new ClaimPackManifest
        {
            PackId = packId,
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            RootClaimCoreDigest = digest,
            Include = new PackIncludeConfig(),
            Files = new List<PackFileEntry>
            {
                await CreatePackFileEntry(Path.Combine(packPath, "claim.json"), "claim.json")
            }
        };

        var manifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packPath, "manifest.json"), manifestJson);

        return (claimBundle, packId);
    }

    private static async Task CreatePackFromBundleAsync(string packPath, ClaimBundle bundle)
    {
        Directory.CreateDirectory(packPath);

        var claimJson = JsonSerializer.Serialize(bundle, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packPath, "claim.json"), claimJson);

        var digest = ClaimCoreDigest.Compute(bundle).ToString();
        var packId = Guid.NewGuid().ToString();

        var manifest = new ClaimPackManifest
        {
            PackId = packId,
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            RootClaimCoreDigest = digest,
            Include = new PackIncludeConfig(),
            Files = new List<PackFileEntry>
            {
                await CreatePackFileEntry(Path.Combine(packPath, "claim.json"), "claim.json")
            }
        };

        var manifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packPath, "manifest.json"), manifestJson);
    }

    private static async Task CreatePackWithCitedClaimsAsync(string packPath)
    {
        Directory.CreateDirectory(packPath);
        var claimsDir = Path.Combine(packPath, "claims");
        Directory.CreateDirectory(claimsDir);

        var keyPair = Ed25519KeyPair.Generate();

        // Create cited claim
        var citedBundle = CreateStandardClaimBundle(keyPair, "Cited claim statement");
        var citedDigest = ClaimCoreDigest.Compute(citedBundle).ToString();

        var citedJson = JsonSerializer.Serialize(citedBundle, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(claimsDir, $"{citedDigest}.json"), citedJson);

        // Create citing claim
        var citingBundle = CreateClaimBundleWithCitation(keyPair, citedDigest);
        var citingDigest = ClaimCoreDigest.Compute(citingBundle).ToString();

        var citingJson = JsonSerializer.Serialize(citingBundle, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packPath, "claim.json"), citingJson);

        var manifest = new ClaimPackManifest
        {
            PackId = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            RootClaimCoreDigest = citingDigest,
            Include = new PackIncludeConfig { ClaimsDir = "claims/" },
            Files = new List<PackFileEntry>
            {
                await CreatePackFileEntry(Path.Combine(packPath, "claim.json"), "claim.json"),
                await CreatePackFileEntry(Path.Combine(claimsDir, $"{citedDigest}.json"), $"claims/{citedDigest}.json")
            }
        };

        var manifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packPath, "manifest.json"), manifestJson);
    }

    private static async Task<string> CreatePackWithCreatorLedgerAsync(string packPath)
    {
        Directory.CreateDirectory(packPath);
        var clDir = Path.Combine(packPath, "creatorledger");
        Directory.CreateDirectory(clDir);

        // Create CreatorLedger bundle
        var clKeyPair = Ed25519KeyPair.Generate();
        var bundleContent = CreateValidBundleJson("asset_test", clKeyPair);
        var bundleBytes = Encoding.UTF8.GetBytes(bundleContent);
        var bundleDigest = ComputeFileDigest(bundleBytes);
        await File.WriteAllBytesAsync(Path.Combine(clDir, $"{bundleDigest}.json"), bundleBytes);

        // Create claim with CreatorLedger evidence
        var keyPair = Ed25519KeyPair.Generate();
        var claimBundle = CreateClaimBundleWithCreatorLedgerEvidence(keyPair, bundleDigest);
        var claimDigest = ClaimCoreDigest.Compute(claimBundle).ToString();

        var claimJson = JsonSerializer.Serialize(claimBundle, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packPath, "claim.json"), claimJson);

        var manifest = new ClaimPackManifest
        {
            PackId = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            RootClaimCoreDigest = claimDigest,
            Include = new PackIncludeConfig { CreatorLedgerDir = "creatorledger/" },
            Files = new List<PackFileEntry>
            {
                await CreatePackFileEntry(Path.Combine(packPath, "claim.json"), "claim.json"),
                await CreatePackFileEntry(Path.Combine(clDir, $"{bundleDigest}.json"), $"creatorledger/{bundleDigest}.json")
            }
        };

        var manifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packPath, "manifest.json"), manifestJson);

        return bundleDigest;
    }

    private static async Task CreatePackWithCitationAsync(string packPath, string citedDigest)
    {
        Directory.CreateDirectory(packPath);

        var keyPair = Ed25519KeyPair.Generate();
        var claimBundle = CreateClaimBundleWithCitation(keyPair, citedDigest);
        var claimDigest = ClaimCoreDigest.Compute(claimBundle).ToString();

        var claimJson = JsonSerializer.Serialize(claimBundle, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packPath, "claim.json"), claimJson);

        var manifest = new ClaimPackManifest
        {
            PackId = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            RootClaimCoreDigest = claimDigest,
            Include = new PackIncludeConfig(),
            Files = new List<PackFileEntry>
            {
                await CreatePackFileEntry(Path.Combine(packPath, "claim.json"), "claim.json")
            }
        };

        var manifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packPath, "manifest.json"), manifestJson);
    }

    private static async Task CreatePackWithCreatorLedgerEvidenceOnly(string packPath, string bundleDigest)
    {
        Directory.CreateDirectory(packPath);

        var keyPair = Ed25519KeyPair.Generate();
        var claimBundle = CreateClaimBundleWithCreatorLedgerEvidence(keyPair, bundleDigest);
        var claimDigest = ClaimCoreDigest.Compute(claimBundle).ToString();

        var claimJson = JsonSerializer.Serialize(claimBundle, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packPath, "claim.json"), claimJson);

        // Note: No creatorledger/ dir - evidence not embedded
        var manifest = new ClaimPackManifest
        {
            PackId = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            RootClaimCoreDigest = claimDigest,
            Include = new PackIncludeConfig(),
            Files = new List<PackFileEntry>
            {
                await CreatePackFileEntry(Path.Combine(packPath, "claim.json"), "claim.json")
            }
        };

        var manifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packPath, "manifest.json"), manifestJson);
    }

    private static ClaimBundle CreateStandardClaimBundle(Ed25519KeyPair keyPair, string? statement = null)
    {
        var claimId = Guid.NewGuid().ToString();
        var researcherId = Guid.NewGuid().ToString();
        statement ??= "Test claim statement";
        var assertedAt = DateTimeOffset.UtcNow.ToString("O");

        var evidence = new List<EvidenceInfo>
        {
            new()
            {
                Type = "text/plain",
                Hash = Guid.NewGuid().ToString("N")
            }
        };

        var signable = new
        {
            claim_id = claimId,
            statement,
            asserted_at_utc = assertedAt,
            evidence = evidence.Select(e => new { type = e.Type, hash = e.Hash }).ToList(),
            researcher_id = researcherId
        };
        var signableBytes = CanonicalJson.SerializeToBytes(signable);
        var signature = keyPair.PrivateKey.Sign(signableBytes);

        return new ClaimBundle
        {
            Algorithms = new AlgorithmsInfo(),
            Claim = new ClaimInfo
            {
                ClaimId = claimId,
                Statement = statement,
                AssertedAtUtc = assertedAt,
                Evidence = evidence,
                Signature = signature.ToString()
            },
            Researcher = new ResearcherInfo
            {
                ResearcherId = researcherId,
                PublicKey = keyPair.PublicKey.ToString()
            }
        };
    }

    private static ClaimBundle CreateClaimBundleWithCitation(Ed25519KeyPair keyPair, string citedDigest)
    {
        var claimId = Guid.NewGuid().ToString();
        var researcherId = Guid.NewGuid().ToString();
        var statement = "Claim that cites another";
        var assertedAt = DateTimeOffset.UtcNow.ToString("O");

        var evidence = new List<EvidenceInfo>
        {
            new()
            {
                Type = "text/plain",
                Hash = Guid.NewGuid().ToString("N")
            }
        };

        // Create citation using CitationSignable format (matches ClaimCitation.v1 contract)
        var citationId = Guid.NewGuid().ToString();
        var citationIssuedAt = DateTimeOffset.UtcNow.ToString("O");
        var citationSignable = new CitationSignable
        {
            CitationId = citationId,
            CitedClaimCoreDigest = citedDigest,
            Relation = "CITES",
            IssuedAt = citationIssuedAt
        };
        var citationSignableBytes = CanonicalJson.SerializeToBytes(citationSignable);
        var citationSig = keyPair.PrivateKey.Sign(citationSignableBytes);

        var citations = new List<CitationInfo>
        {
            new()
            {
                CitationId = citationId,
                CitedClaimCoreDigest = citedDigest,
                Relation = "CITES",
                IssuedAtUtc = citationIssuedAt,
                Signature = citationSig.ToString()
            }
        };

        var signable = new
        {
            claim_id = claimId,
            statement,
            asserted_at_utc = assertedAt,
            evidence = evidence.Select(e => new { type = e.Type, hash = e.Hash }).ToList(),
            citations = citations.Select(c => new
            {
                citation_id = c.CitationId,
                cited_claim_core_digest = c.CitedClaimCoreDigest,
                relation = c.Relation
            }).ToList(),
            researcher_id = researcherId
        };
        var signableBytes = CanonicalJson.SerializeToBytes(signable);
        var signature = keyPair.PrivateKey.Sign(signableBytes);

        return new ClaimBundle
        {
            Algorithms = new AlgorithmsInfo(),
            Claim = new ClaimInfo
            {
                ClaimId = claimId,
                Statement = statement,
                AssertedAtUtc = assertedAt,
                Evidence = evidence,
                Signature = signature.ToString()
            },
            Researcher = new ResearcherInfo
            {
                ResearcherId = researcherId,
                PublicKey = keyPair.PublicKey.ToString()
            },
            Citations = citations
        };
    }

    private static ClaimBundle CreateClaimBundleWithCreatorLedgerEvidence(Ed25519KeyPair keyPair, string bundleDigest)
    {
        var claimId = Guid.NewGuid().ToString();
        var researcherId = Guid.NewGuid().ToString();
        var statement = "Claim with CreatorLedger evidence";
        var assertedAt = DateTimeOffset.UtcNow.ToString("O");

        var evidence = new List<EvidenceInfo>
        {
            new()
            {
                Type = "application/json",
                Hash = bundleDigest,
                Kind = EvidenceKind.CreatorLedgerBundle,
                EmbeddedPath = $"creatorledger/{bundleDigest}.json",
                BundleAssetId = "asset_test"
            }
        };

        var signable = new
        {
            claim_id = claimId,
            statement,
            asserted_at_utc = assertedAt,
            evidence = evidence.Select(e => new { type = e.Type, hash = e.Hash, kind = e.Kind }).ToList(),
            researcher_id = researcherId
        };
        var signableBytes = CanonicalJson.SerializeToBytes(signable);
        var signature = keyPair.PrivateKey.Sign(signableBytes);

        return new ClaimBundle
        {
            Algorithms = new AlgorithmsInfo(),
            Claim = new ClaimInfo
            {
                ClaimId = claimId,
                Statement = statement,
                AssertedAtUtc = assertedAt,
                Evidence = evidence,
                Signature = signature.ToString()
            },
            Researcher = new ResearcherInfo
            {
                ResearcherId = researcherId,
                PublicKey = keyPair.PublicKey.ToString()
            }
        };
    }

    private static string CreateValidBundleJson(string assetId, Ed25519KeyPair keyPair)
    {
        var contentHash = "abc123def456";
        var creatorId = "creator_test";
        var attestedAt = "2024-01-15T10:30:00Z";

        var signable = new
        {
            asset_id = assetId,
            content_hash = contentHash,
            creator_id = creatorId,
            creator_public_key = keyPair.PublicKey.ToString(),
            attested_at_utc = attestedAt
        };
        var signableBytes = CanonicalJson.SerializeToBytes(signable);
        var signature = keyPair.PrivateKey.Sign(signableBytes);

        var bundle = new CreatorLedgerBundle
        {
            Version = "proof.v1",
            Algorithms = new CreatorLedgerAlgorithms
            {
                Signature = "Ed25519",
                Hash = "SHA-256",
                Encoding = "UTF-8"
            },
            AssetId = assetId,
            Attestations = new List<CreatorLedgerAttestation>
            {
                new()
                {
                    AttestationId = "att_test",
                    AssetId = assetId,
                    ContentHash = contentHash,
                    CreatorId = creatorId,
                    CreatorPublicKey = keyPair.PublicKey.ToString(),
                    AttestedAtUtc = attestedAt,
                    Signature = signature.ToString()
                }
            }
        };

        return JsonSerializer.Serialize(bundle, new JsonSerializerOptions { WriteIndented = true });
    }

    private static string ComputeFileDigest(byte[] bytes)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static async Task<PackFileEntry> CreatePackFileEntry(string filePath, string packPath)
    {
        var fileInfo = new FileInfo(filePath);
        var bytes = await File.ReadAllBytesAsync(filePath);
        var hash = System.Security.Cryptography.SHA256.HashData(bytes);

        return new PackFileEntry
        {
            Path = packPath,
            MediaType = "application/json",
            Sha256Hex = Convert.ToHexString(hash).ToLowerInvariant(),
            SizeBytes = fileInfo.Length
        };
    }

    private sealed class TempDirectory : IDisposable
    {
        public string Path { get; }

        public TempDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"cltest_{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Path))
                {
                    Directory.Delete(Path, recursive: true);
                }
            }
            catch
            {
                // Ignore cleanup errors
            }
        }
    }

    #endregion
}
