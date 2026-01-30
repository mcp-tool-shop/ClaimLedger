using System.Security.Cryptography;
using System.Text.Json;
using ClaimLedger.Application.Attestations;
using ClaimLedger.Application.Citations;
using ClaimLedger.Application.Claims;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Identity;
using ClaimLedger.Application.Packs;
using ClaimLedger.Application.Revocations;
using ClaimLedger.Application.Timestamps;
using ClaimLedger.Domain.Attestations;
using ClaimLedger.Domain.Citations;
using ClaimLedger.Domain.Packs;
using ClaimLedger.Domain.Primitives;
using ClaimLedger.Domain.Revocations;
using ClaimLedger.Domain.Timestamps;
using ClaimLedger.Tests.Fakes;
using Shared.Crypto;

namespace ClaimLedger.Tests.Application;

/// <summary>
/// Phase 7 tests for ClaimPack creation and verification.
/// Target: 30-50 "brutal tests" covering path safety, inventory integrity,
/// root binding, citations, evidence, revocations, and TSA.
/// </summary>
public class PackTests : IDisposable
{
    private readonly InMemoryKeyVault _keyVault = new();
    private readonly InMemoryResearcherIdentityRepository _identityRepo = new();
    private readonly InMemoryClaimRepository _claimRepo = new();
    private readonly FakeClock _clock = new();
    private readonly List<string> _tempDirs = new();

    public void Dispose()
    {
        foreach (var dir in _tempDirs)
        {
            try { Directory.Delete(dir, recursive: true); }
            catch { /* ignore cleanup failures */ }
        }
        GC.SuppressFinalize(this);
    }

    private string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "claimpack_test_" + Guid.NewGuid().ToString()[..8]);
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        return dir;
    }

    #region Path Safety Tests

    [Theory]
    [InlineData("..")]
    [InlineData("../secret.txt")]
    [InlineData("claims/../../../etc/passwd")]
    [InlineData("foo/../../bar")]
    public void PathValidator_RejectsTraversal(string path)
    {
        var result = PackPathValidator.ValidatePath(path);
        Assert.False(result.IsValid);
        Assert.Contains("..", result.Error);
    }

    [Theory]
    [InlineData("/absolute/path")]
    [InlineData("/etc/passwd")]
    public void PathValidator_RejectsAbsolutePaths(string path)
    {
        var result = PackPathValidator.ValidatePath(path);
        Assert.False(result.IsValid);
        Assert.Contains("Absolute", result.Error);
    }

    [Theory]
    [InlineData("C:\\Windows\\System32")]
    [InlineData("D:\\secret.txt")]
    [InlineData("c:/test.json")]
    public void PathValidator_RejectsDriveLetters(string path)
    {
        var result = PackPathValidator.ValidatePath(path);
        Assert.False(result.IsValid);
        // Could be "Drive letters" or "Absolute paths"
        Assert.True(result.Error!.Contains("Drive") || result.Error.Contains("Absolute"));
    }

    [Theory]
    [InlineData("\\\\server\\share")]
    [InlineData("//network/path")]
    public void PathValidator_RejectsUncPaths(string path)
    {
        var result = PackPathValidator.ValidatePath(path);
        Assert.False(result.IsValid);
        // Could be "UNC paths" or "Absolute paths" depending on order
        Assert.True(result.Error!.Contains("UNC") || result.Error.Contains("Absolute"));
    }

    [Theory]
    [InlineData("CON")]
    [InlineData("PRN")]
    [InlineData("AUX")]
    [InlineData("NUL")]
    [InlineData("COM1")]
    [InlineData("LPT1")]
    [InlineData("con.txt")]
    [InlineData("nul.json")]
    public void PathValidator_RejectsWindowsReservedNames(string path)
    {
        var result = PackPathValidator.ValidatePath(path);
        Assert.False(result.IsValid);
        Assert.Contains("Reserved", result.Error);
    }

    [Theory]
    [InlineData("claim.json")]
    [InlineData("claims/abc123.json")]
    [InlineData("evidence/data/file.csv")]
    [InlineData("tsa-trust/cert.pem")]
    public void PathValidator_AcceptsValidPaths(string path)
    {
        var result = PackPathValidator.ValidatePath(path);
        Assert.True(result.IsValid);
        Assert.Null(result.Error);
    }

    [Fact]
    public void PathValidator_RejectsNullByte()
    {
        var result = PackPathValidator.ValidatePath("claim\0.json");
        Assert.False(result.IsValid);
        Assert.Contains("null", result.Error);
    }

    [Fact]
    public void PathValidator_RejectsCurrentDirectory()
    {
        var result = PackPathValidator.ValidatePath("./claim.json");
        Assert.False(result.IsValid);
        Assert.Contains(".", result.Error);
    }

    [Fact]
    public void SafeCombine_RejectsEscapeAttempt()
    {
        var baseDir = CreateTempDir();

        // Should return null for paths that escape
        var result = PackPathValidator.SafeCombine(baseDir, "../../../etc/passwd");
        Assert.Null(result);
    }

    [Fact]
    public void SafeCombine_AcceptsValidPath()
    {
        var baseDir = CreateTempDir();

        var result = PackPathValidator.SafeCombine(baseDir, "claims/test.json");
        Assert.NotNull(result);
        Assert.StartsWith(baseDir, result);
    }

    [Fact]
    public void NormalizePath_ConvertsBackslashesToForward()
    {
        var result = PackPathValidator.NormalizePath("claims\\subdir\\test.json");
        Assert.Equal("claims/subdir/test.json", result);
    }

    #endregion

    #region Pack Creation Tests

    [Fact]
    public async Task CreatePack_MinimalBundle_CreatesValidPack()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = CreateTempDir();

        var result = await CreatePackHandler.HandleAsync(new CreatePackCommand(
            bundle, packDir));

        Assert.True(result.Success);
        Assert.NotNull(result.Manifest);
        Assert.True(File.Exists(Path.Combine(packDir, "manifest.json")));
        Assert.True(File.Exists(Path.Combine(packDir, "claim.json")));
    }

    [Fact]
    public async Task CreatePack_ManifestHasCorrectContract()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = CreateTempDir();

        var result = await CreatePackHandler.HandleAsync(new CreatePackCommand(
            bundle, packDir));

        Assert.Equal(ClaimPackManifest.ContractVersion, result.Manifest!.Contract);
        Assert.Equal("ClaimPackManifest.v1", result.Manifest.Contract);
    }

    [Fact]
    public async Task CreatePack_RootClaimPath_IsCorrect()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = CreateTempDir();

        var result = await CreatePackHandler.HandleAsync(new CreatePackCommand(
            bundle, packDir));

        Assert.Equal("claim.json", result.Manifest!.RootClaimPath);
    }

    [Fact]
    public async Task CreatePack_RootDigest_MatchesBundle()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = CreateTempDir();
        var expectedDigest = ClaimCoreDigest.Compute(bundle);

        var result = await CreatePackHandler.HandleAsync(new CreatePackCommand(
            bundle, packDir));

        Assert.Equal(expectedDigest.ToString(), result.Manifest!.RootClaimCoreDigest);
    }

    [Fact]
    public async Task CreatePack_FileHashes_AreCorrect()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = CreateTempDir();

        var result = await CreatePackHandler.HandleAsync(new CreatePackCommand(
            bundle, packDir));

        var claimEntry = result.Manifest!.Files.Single(f => f.Path == "claim.json");

        // Verify hash
        var actualBytes = await File.ReadAllBytesAsync(Path.Combine(packDir, "claim.json"));
        var actualHash = Convert.ToHexString(SHA256.HashData(actualBytes)).ToLowerInvariant();

        Assert.Equal(actualHash, claimEntry.Sha256Hex.ToLowerInvariant());
    }

    [Fact]
    public async Task CreatePack_WithCitations_IncludesClaimsDir()
    {
        var citingBundle = await CreateClaimBundle("Citing claim");
        var citedBundle = await CreateClaimBundle("Cited claim");
        var citedDigest = ClaimCoreDigest.Compute(citedBundle);

        // Add citation
        var citationHandler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await citationHandler.HandleAsync(new CreateCitationCommand(
            citingBundle, citedDigest, CitationRelation.Cites, null, null));

        citingBundle = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation, citedBundle));

        var packDir = CreateTempDir();
        var result = await CreatePackHandler.HandleAsync(new CreatePackCommand(
            citingBundle, packDir, IncludeCitations: true));

        Assert.True(result.Success);
        Assert.Equal("claims/", result.Manifest!.Include.ClaimsDir);
        Assert.True(Directory.Exists(Path.Combine(packDir, "claims")));
    }

    [Fact]
    public async Task CreatePack_WithEvidence_CopiesEvidenceDir()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = CreateTempDir();
        var evidenceDir = CreateTempDir();

        // Create evidence file
        var evidenceFile = Path.Combine(evidenceDir, "data.csv");
        await File.WriteAllTextAsync(evidenceFile, "col1,col2\n1,2\n");

        var result = await CreatePackHandler.HandleAsync(new CreatePackCommand(
            bundle, packDir, EvidenceDirectory: evidenceDir));

        Assert.True(result.Success);
        Assert.Equal("evidence/", result.Manifest!.Include.EvidenceDir);
        Assert.True(File.Exists(Path.Combine(packDir, "evidence", "data.csv")));
    }

    #endregion

    #region Pack Verification - Basic Tests

    [Fact]
    public async Task VerifyPack_ValidPack_ReturnsValid()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.True(result.IsValid);
        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public async Task VerifyPack_MissingDirectory_ReturnsExitCode4()
    {
        var result = await VerifyPackHandler.HandleAsync(
            new VerifyPackCommand("/nonexistent/path"));

        Assert.False(result.IsValid);
        Assert.Equal(4, result.ExitCode);
        // Could be "not found" or "missing manifest"
        Assert.NotNull(result.Error);
    }

    [Fact]
    public async Task VerifyPack_MissingManifest_ReturnsExitCode4()
    {
        var packDir = CreateTempDir();
        await File.WriteAllTextAsync(Path.Combine(packDir, "claim.json"), "{}");

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.False(result.IsValid);
        Assert.Equal(4, result.ExitCode);
        Assert.Contains("manifest.json", result.Error);
    }

    [Fact]
    public async Task VerifyPack_InvalidManifestJson_ReturnsExitCode4()
    {
        var packDir = CreateTempDir();
        await File.WriteAllTextAsync(Path.Combine(packDir, "manifest.json"), "not json");

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.False(result.IsValid);
        Assert.Equal(4, result.ExitCode);
        Assert.Contains("Invalid manifest", result.Error);
    }

    [Fact]
    public async Task VerifyPack_WrongManifestContract_ReturnsExitCode4()
    {
        var packDir = CreateTempDir();
        // Create a minimal valid manifest with wrong contract version
        var manifest = new ClaimPackManifest
        {
            PackId = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            RootClaimCoreDigest = new string('0', 64),
            Include = new PackIncludeConfig(),
            Files = new[] { new PackFileEntry { Path = "claim.json", MediaType = "application/json", Sha256Hex = new string('0', 64), SizeBytes = 100 } }
        };

        // Serialize, modify contract, write back
        var json = JsonSerializer.Serialize(manifest);
        var tamperedJson = json.Replace("ClaimPackManifest.v1", "ClaimPackManifest.v99");
        await File.WriteAllTextAsync(Path.Combine(packDir, "manifest.json"), tamperedJson);

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.False(result.IsValid);
        Assert.Equal(4, result.ExitCode);
        Assert.Contains("manifest", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    #endregion

    #region Inventory Integrity Tests

    [Fact]
    public async Task VerifyPack_MissingFile_ReturnsError()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        // Delete the claim file
        File.Delete(Path.Combine(packDir, "claim.json"));

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.False(result.IsValid);
        Assert.Contains("Missing", result.Error);
    }

    [Fact]
    public async Task VerifyPack_HashMismatch_ReturnsExitCode3InStrict()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        // Tamper with the claim file
        var claimPath = Path.Combine(packDir, "claim.json");
        var content = await File.ReadAllTextAsync(claimPath);
        await File.WriteAllTextAsync(claimPath, content + " ");  // Add space

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir, Strict: true));

        Assert.False(result.IsValid);
        // Could be ExitCode 3 (broken) or 4 (invalid) depending on order
        Assert.True(result.ExitCode == 3 || result.ExitCode == 4);
        Assert.Contains("mismatch", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyPack_SizeMismatch_ReturnsError()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        // Truncate the claim file
        var claimPath = Path.Combine(packDir, "claim.json");
        var content = await File.ReadAllTextAsync(claimPath);
        await File.WriteAllTextAsync(claimPath, content[..10]);

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.False(result.IsValid);
        Assert.Contains("mismatch", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyPack_ExtraFile_StrictMode_Fails()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        // Add extra file
        await File.WriteAllTextAsync(Path.Combine(packDir, "rogue.txt"), "evil");

        var result = await VerifyPackHandler.HandleAsync(
            new VerifyPackCommand(packDir, Strict: true));

        Assert.False(result.IsValid);
        Assert.Contains("Extra file", result.Error);
    }

    [Fact]
    public async Task VerifyPack_ExtraFile_NonStrict_Warns()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        // Add extra file
        await File.WriteAllTextAsync(Path.Combine(packDir, "rogue.txt"), "evil");

        var result = await VerifyPackHandler.HandleAsync(
            new VerifyPackCommand(packDir, Strict: false));

        // Should still be valid but with warning
        Assert.True(result.IsValid);
        Assert.Contains("extra", result.Warnings.FirstOrDefault() ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyPack_DuplicatePaths_ReturnsExitCode4()
    {
        var packDir = CreateTempDir();
        var manifest = new ClaimPackManifest
        {
            PackId = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            RootClaimCoreDigest = new string('0', 64),
            Include = new PackIncludeConfig(),
            Files = new[]
            {
                new PackFileEntry { Path = "claim.json", MediaType = "application/json", Sha256Hex = new string('0', 64), SizeBytes = 100 },
                new PackFileEntry { Path = "claim.json", MediaType = "application/json", Sha256Hex = new string('0', 64), SizeBytes = 100 }  // DUPLICATE
            }
        };

        await File.WriteAllTextAsync(
            Path.Combine(packDir, "manifest.json"),
            JsonSerializer.Serialize(manifest));

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.False(result.IsValid);
        Assert.Equal(4, result.ExitCode);
        Assert.Contains("duplicate", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyPack_PathTraversalInManifest_ReturnsExitCode4()
    {
        var packDir = CreateTempDir();
        var manifest = new ClaimPackManifest
        {
            PackId = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            RootClaimCoreDigest = new string('0', 64),
            Include = new PackIncludeConfig(),
            Files = new[]
            {
                new PackFileEntry { Path = "../../../etc/passwd", MediaType = "text/plain", Sha256Hex = new string('0', 64), SizeBytes = 100 }
            }
        };

        await File.WriteAllTextAsync(
            Path.Combine(packDir, "manifest.json"),
            JsonSerializer.Serialize(manifest));

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.False(result.IsValid);
        Assert.Equal(4, result.ExitCode);
        Assert.Contains("Invalid path", result.Error);
    }

    #endregion

    #region Root Binding Tests

    [Fact]
    public async Task VerifyPack_RootDigestMismatch_StrictMode_Fails()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        // Modify manifest to have wrong root digest
        var manifestPath = Path.Combine(packDir, "manifest.json");
        var manifestJson = await File.ReadAllTextAsync(manifestPath);
        var manifest = JsonSerializer.Deserialize<ClaimPackManifest>(manifestJson)!;

        var tamperedManifest = new
        {
            manifest.Contract,
            manifest.PackId,
            manifest.CreatedAt,
            manifest.RootClaimPath,
            RootClaimCoreDigest = new string('a', 64),  // WRONG
            manifest.Include,
            manifest.Files
        };

        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(tamperedManifest));

        var result = await VerifyPackHandler.HandleAsync(
            new VerifyPackCommand(packDir, Strict: true));

        Assert.False(result.IsValid);
        Assert.Equal(3, result.ExitCode);
        Assert.Contains("digest mismatch", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyPack_RootDigestMismatch_NonStrict_Warns()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        // Modify manifest to have wrong root digest
        var manifestPath = Path.Combine(packDir, "manifest.json");
        var manifestJson = await File.ReadAllTextAsync(manifestPath);
        var manifest = JsonSerializer.Deserialize<ClaimPackManifest>(manifestJson)!;

        var tamperedManifest = new
        {
            manifest.Contract,
            manifest.PackId,
            manifest.CreatedAt,
            manifest.RootClaimPath,
            RootClaimCoreDigest = new string('a', 64),  // WRONG
            manifest.Include,
            manifest.Files
        };

        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(tamperedManifest));

        var result = await VerifyPackHandler.HandleAsync(
            new VerifyPackCommand(packDir, Strict: false));

        // Warns but doesn't fail
        Assert.True(result.IsValid);
        Assert.Contains("digest", result.Warnings.FirstOrDefault() ?? "", StringComparison.OrdinalIgnoreCase);
    }

    #endregion

    #region Citation Verification in Pack

    [Fact]
    public async Task VerifyPack_WithValidCitations_Succeeds()
    {
        var citingBundle = await CreateClaimBundle("Citing claim");
        var citedBundle = await CreateClaimBundle("Cited claim");
        var citedDigest = ClaimCoreDigest.Compute(citedBundle);

        var citationHandler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await citationHandler.HandleAsync(new CreateCitationCommand(
            citingBundle, citedDigest, CitationRelation.Cites, null, null));

        citingBundle = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation, citedBundle));

        var packDir = await CreateValidPack(citingBundle, includeCitations: true);

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.True(result.IsValid);
        Assert.NotNull(result.CitationsResult);
        Assert.True(result.CitationsResult.AllValid);
    }

    [Fact]
    public async Task VerifyPack_WithTamperedCitation_Fails()
    {
        var citingBundle = await CreateClaimBundle("Citing claim");
        var citedBundle = await CreateClaimBundle("Cited claim");
        var citedDigest = ClaimCoreDigest.Compute(citedBundle);

        var citationHandler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await citationHandler.HandleAsync(new CreateCitationCommand(
            citingBundle, citedDigest, CitationRelation.Cites, null, "Original notes"));

        citingBundle = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation, citedBundle));

        var packDir = await CreateValidPack(citingBundle, includeCitations: true);

        // Tamper with citation in claim.json
        var claimPath = Path.Combine(packDir, "claim.json");
        var claimJson = await File.ReadAllTextAsync(claimPath);
        var tamperedJson = claimJson.Replace("Original notes", "TAMPERED");
        await File.WriteAllTextAsync(claimPath, tamperedJson);

        // Update manifest hash (so it passes inventory check)
        await UpdateManifestHash(packDir, "claim.json", tamperedJson);

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.False(result.IsValid);
        Assert.Equal(3, result.ExitCode);
        Assert.Contains("Citation", result.Error);
    }

    [Fact]
    public async Task VerifyPack_CitationsFromClaimsDir_Resolved()
    {
        var citingBundle = await CreateClaimBundle("Citing claim");
        var citedBundle = await CreateClaimBundle("Cited claim");
        var citedDigest = ClaimCoreDigest.Compute(citedBundle);

        var citationHandler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await citationHandler.HandleAsync(new CreateCitationCommand(
            citingBundle, citedDigest, CitationRelation.Cites, null, null));

        // Add citation WITHOUT embedding
        citingBundle = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation));

        var packDir = await CreateValidPack(citingBundle, includeCitations: true,
            resolvedCitations: new Dictionary<string, ClaimBundle>
            {
                [citedDigest.ToString()] = citedBundle
            });

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.True(result.IsValid);
        Assert.NotNull(result.CitationsResult);
        Assert.True(result.CitationsResult.AllValid);
    }

    #endregion

    #region Attestation Verification in Pack

    [Fact]
    public async Task VerifyPack_WithValidAttestations_Succeeds()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var attestor = await CreateResearcher("Dr. Reviewer");

        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, attestor.Id, AttestationType.Reviewed, "Reviewed"));

        bundle = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation));

        var packDir = await CreateValidPack(bundle);

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.True(result.IsValid);
        Assert.NotNull(result.AttestationsResult);
        Assert.True(result.AttestationsResult.AllValid);
    }

    [Fact]
    public async Task VerifyPack_WithTamperedAttestation_Fails()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var attestor = await CreateResearcher("Dr. Reviewer");

        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, attestor.Id, AttestationType.Reviewed, "Original statement"));

        bundle = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation));

        var packDir = await CreateValidPack(bundle);

        // Tamper with attestation
        var claimPath = Path.Combine(packDir, "claim.json");
        var claimJson = await File.ReadAllTextAsync(claimPath);
        var tamperedJson = claimJson.Replace("Original statement", "TAMPERED");
        await File.WriteAllTextAsync(claimPath, tamperedJson);

        // Update manifest hash
        await UpdateManifestHash(packDir, "claim.json", tamperedJson);

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.False(result.IsValid);
        Assert.Equal(3, result.ExitCode);
    }

    #endregion

    #region Revocation Verification in Pack

    [Fact]
    public async Task VerifyPack_WithRevocations_ChecksSignerKey()
    {
        // Create researcher with known keys
        var (researcher, keyPair) = await CreateResearcherWithKeys("Dr. Author");

        // Create claim
        var claimHandler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);
        var claim = await claimHandler.HandleAsync(new AssertClaimCommand(
            "Test claim",
            researcher.Id,
            Array.Empty<EvidenceInput>()));

        var exportHandler = new ExportClaimBundleHandler(_claimRepo, _identityRepo);
        var bundle = await exportHandler.HandleAsync(new ExportClaimBundleCommand(claim.Id));

        var packDir = await CreateValidPack(bundle);

        // Create revocation for the signer key
        var revocationsDir = Path.Combine(packDir, "revocations");
        Directory.CreateDirectory(revocationsDir);

        var revocation = Revocation.CreateSelfSigned(
            researcher.Id,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            _clock.UtcNow.AddDays(-1),  // Revoked BEFORE the claim was made
            RevocationReason.Compromised);

        var revocationBundle = ExportRevocationBundleHandler.Handle(revocation, researcher.DisplayName);

        await File.WriteAllTextAsync(
            Path.Combine(revocationsDir, "revocation.json"),
            JsonSerializer.Serialize(revocationBundle));

        // Update manifest to include revocations dir
        await UpdateManifestInclude(packDir, revocationsDir: "revocations/");

        var result = await VerifyPackHandler.HandleAsync(
            new VerifyPackCommand(packDir, StrictRevocations: true));

        Assert.False(result.IsValid);
        Assert.Equal(6, result.ExitCode);  // REVOKED
        Assert.Contains("revoked", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    #endregion

    #region TSA Verification in Pack

    [Fact]
    public async Task VerifyPack_WithTimestampReceipts_Verifies()
    {
        var bundle = await CreateClaimBundle("Test claim");

        // Add a timestamp receipt
        var coreDigest = ClaimCoreDigest.Compute(bundle);
        var messageImprint = Digest256.Compute(coreDigest.AsBytes()).AsBytes().ToArray();

        var receipt = TimestampReceipt.FromStored(
            TimestampReceiptId.New(),
            coreDigest,
            messageImprint,
            new byte[] { 0x00 },  // Dummy token - will fail real verification
            new TstInfo
            {
                HashAlgorithmOid = TstInfo.Sha256Oid,
                HashedMessage = messageImprint,
                GenTime = DateTimeOffset.UtcNow,
                PolicyOid = "1.2.3.4"
            },
            new TsaInfo { PolicyOid = "1.2.3.4" });

        bundle = AddTimestampToBundleHandler.Handle(
            new AddTimestampToBundleCommand(bundle, receipt));

        var packDir = await CreateValidPack(bundle);

        // Note: This will pass because the binding verification works
        // but CMS verification would fail (dummy token)
        var result = await VerifyPackHandler.HandleAsync(
            new VerifyPackCommand(packDir, VerifyTsa: false));

        Assert.True(result.IsValid);
    }

    #endregion

    #region Evidence Verification in Pack

    [Fact]
    public async Task VerifyPack_StrictMode_ChecksEvidence()
    {
        var evidenceContent = "col1,col2\n1,2\n";
        var evidenceHash = ContentHash.Compute(System.Text.Encoding.UTF8.GetBytes(evidenceContent));

        var researcher = await CreateResearcher("Dr. Author");
        var claimHandler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);
        var claim = await claimHandler.HandleAsync(new AssertClaimCommand(
            "Test claim with evidence",
            researcher.Id,
            new[] { new EvidenceInput("Dataset", evidenceHash, "data.csv") }));

        var exportHandler = new ExportClaimBundleHandler(_claimRepo, _identityRepo);
        var bundle = await exportHandler.HandleAsync(new ExportClaimBundleCommand(claim.Id));

        var packDir = CreateTempDir();
        var evidenceDir = CreateTempDir();

        // Create evidence file
        await File.WriteAllTextAsync(Path.Combine(evidenceDir, "data.csv"), evidenceContent);

        await CreatePackHandler.HandleAsync(new CreatePackCommand(
            bundle, packDir, EvidenceDirectory: evidenceDir));

        var result = await VerifyPackHandler.HandleAsync(
            new VerifyPackCommand(packDir, Strict: true));

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task VerifyPack_StrictMode_MissingEvidence_Fails()
    {
        var evidenceHash = ContentHash.Compute("some data"u8);

        var researcher = await CreateResearcher("Dr. Author");
        var claimHandler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);
        var claim = await claimHandler.HandleAsync(new AssertClaimCommand(
            "Test claim with evidence",
            researcher.Id,
            new[] { new EvidenceInput("Dataset", evidenceHash, "data.csv") }));

        var exportHandler = new ExportClaimBundleHandler(_claimRepo, _identityRepo);
        var bundle = await exportHandler.HandleAsync(new ExportClaimBundleCommand(claim.Id));

        var packDir = CreateTempDir();
        var evidenceDir = CreateTempDir();

        // Create WRONG evidence file
        await File.WriteAllTextAsync(Path.Combine(evidenceDir, "data.csv"), "wrong content");

        await CreatePackHandler.HandleAsync(new CreatePackCommand(
            bundle, packDir, EvidenceDirectory: evidenceDir));

        var result = await VerifyPackHandler.HandleAsync(
            new VerifyPackCommand(packDir, Strict: true));

        Assert.False(result.IsValid);
        Assert.Equal(3, result.ExitCode);
        Assert.Contains("evidence", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    #endregion

    #region Full Integration Tests

    [Fact]
    public async Task CreateAndVerify_CompleteWorkflow_Success()
    {
        // Create a complex bundle with citations and attestations
        var citingBundle = await CreateClaimBundle("Main research claim");
        var citedBundle = await CreateClaimBundle("Prior work");
        var citedDigest = ClaimCoreDigest.Compute(citedBundle);

        // Add citation
        var citationHandler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await citationHandler.HandleAsync(new CreateCitationCommand(
            citingBundle, citedDigest, CitationRelation.DependsOn, null, "Important prior work"));
        citingBundle = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation, citedBundle));

        // Add attestation
        var attestor = await CreateResearcher("Dr. Peer Reviewer");
        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            citingBundle, attestor.Id, AttestationType.Reviewed, "Methodology verified"));
        citingBundle = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(citingBundle, attestation));

        // Create pack
        var packDir = CreateTempDir();
        var createResult = await CreatePackHandler.HandleAsync(new CreatePackCommand(
            citingBundle, packDir, IncludeCitations: true));

        Assert.True(createResult.Success);

        // Verify pack
        var verifyResult = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.True(verifyResult.IsValid);
        Assert.Equal(0, verifyResult.ExitCode);
        Assert.NotNull(verifyResult.CitationsResult);
        Assert.NotNull(verifyResult.AttestationsResult);
        Assert.True(verifyResult.CitationsResult.AllValid);
        Assert.True(verifyResult.AttestationsResult.AllValid);
    }

    [Fact]
    public async Task VerifyPack_RoundTrip_PreservesAllData()
    {
        var bundle = await CreateClaimBundle("Test claim for roundtrip");
        var originalDigest = ClaimCoreDigest.Compute(bundle);

        var packDir = await CreateValidPack(bundle);

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.True(result.IsValid);
        Assert.Equal(originalDigest.ToString(), result.RootClaimCoreDigest);
        Assert.Equal(bundle.Claim.ClaimId, result.RootBundle!.Claim.ClaimId);
        Assert.Equal(bundle.Claim.Statement, result.RootBundle.Claim.Statement);
    }

    #endregion

    #region Helper Methods

    private async Task<ClaimBundle> CreateClaimBundle(string statement)
    {
        var researcher = await CreateResearcher("Dr. Author " + Guid.NewGuid().ToString()[..8]);
        var claimHandler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);
        var claim = await claimHandler.HandleAsync(new AssertClaimCommand(
            statement,
            researcher.Id,
            Array.Empty<EvidenceInput>()));

        var exportHandler = new ExportClaimBundleHandler(_claimRepo, _identityRepo);
        return await exportHandler.HandleAsync(new ExportClaimBundleCommand(claim.Id));
    }

    private async Task<ClaimLedger.Domain.Identity.ResearcherIdentity> CreateResearcher(string name)
    {
        var handler = new CreateResearcherIdentityHandler(_keyVault, _identityRepo, _clock);
        return await handler.HandleAsync(new CreateResearcherIdentityCommand(name));
    }

    private async Task<string> CreateValidPack(
        ClaimBundle bundle,
        bool includeCitations = false,
        Dictionary<string, ClaimBundle>? resolvedCitations = null)
    {
        var packDir = CreateTempDir();
        await CreatePackHandler.HandleAsync(new CreatePackCommand(
            bundle,
            packDir,
            IncludeCitations: includeCitations,
            ResolvedCitations: resolvedCitations));
        return packDir;
    }

    private static async Task UpdateManifestHash(string packDir, string filePath, string newContent)
    {
        var manifestPath = Path.Combine(packDir, "manifest.json");
        var manifestJson = await File.ReadAllTextAsync(manifestPath);
        var manifest = JsonSerializer.Deserialize<ClaimPackManifest>(manifestJson)!;

        var newHash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(newContent))).ToLowerInvariant();
        var newSize = System.Text.Encoding.UTF8.GetByteCount(newContent);

        var updatedFiles = manifest.Files.Select(f =>
            f.Path == filePath
                ? new PackFileEntry { Path = f.Path, MediaType = f.MediaType, Sha256Hex = newHash, SizeBytes = newSize }
                : f
        ).ToList();

        // Recompute root digest since claim changed
        var claimJson = await File.ReadAllTextAsync(Path.Combine(packDir, "claim.json"));
        var updatedBundle = JsonSerializer.Deserialize<ClaimBundle>(claimJson);
        var newDigest = ClaimCoreDigest.Compute(updatedBundle!);

        var updatedManifest = new ClaimPackManifest
        {
            PackId = manifest.PackId,
            CreatedAt = manifest.CreatedAt,
            RootClaimCoreDigest = newDigest.ToString(),
            Include = manifest.Include,
            Files = updatedFiles
        };

        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(updatedManifest));
    }

    private static async Task UpdateManifestInclude(string packDir, string? revocationsDir = null)
    {
        var manifestPath = Path.Combine(packDir, "manifest.json");
        var manifestJson = await File.ReadAllTextAsync(manifestPath);
        var manifest = JsonSerializer.Deserialize<ClaimPackManifest>(manifestJson)!;

        var updatedInclude = manifest.Include with
        {
            RevocationsDir = revocationsDir ?? manifest.Include.RevocationsDir
        };

        var updatedManifest = new ClaimPackManifest
        {
            PackId = manifest.PackId,
            CreatedAt = manifest.CreatedAt,
            RootClaimCoreDigest = manifest.RootClaimCoreDigest,
            Include = updatedInclude,
            Files = manifest.Files
        };

        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(updatedManifest));
    }

    private async Task<(ClaimLedger.Domain.Identity.ResearcherIdentity researcher, Ed25519KeyPair keyPair)> CreateResearcherWithKeys(string name)
    {
        var keyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();
        var researcher = new ClaimLedger.Domain.Identity.ResearcherIdentity(
            researcherId, keyPair.PublicKey, name, _clock.UtcNow);

        await _identityRepo.SaveAsync(researcher);
        await _keyVault.StoreAsync(researcherId, keyPair.PrivateKey);

        return (researcher, keyPair);
    }

    #endregion
}
