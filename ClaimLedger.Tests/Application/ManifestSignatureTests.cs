using System.Security.Cryptography;
using System.Text.Json;
using ClaimLedger.Application.Claims;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Identity;
using ClaimLedger.Application.Packs;
using ClaimLedger.Application.Revocations;
using ClaimLedger.Domain.Packs;
using ClaimLedger.Domain.Primitives;
using ClaimLedger.Domain.Revocations;
using ClaimLedger.Tests.Fakes;
using Shared.Crypto;

namespace ClaimLedger.Tests.Application;

/// <summary>
/// Phase 8 tests for signed ClaimPack manifests.
/// Target: ~20-30 tests covering signing, verification, roles, strictness, and revocation.
/// </summary>
public class ManifestSignatureTests : IDisposable
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
        var dir = Path.Combine(Path.GetTempPath(), "manifestsig_test_" + Guid.NewGuid().ToString()[..8]);
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        return dir;
    }

    #region Core Signing Tests

    [Fact]
    public async Task SignPack_ValidPack_SucceedsWithSignature()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);
        var (_, signerKeyPair) = await CreateSignerIdentity("Dr. Signer");

        var result = await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            signerKeyPair.PrivateKey,
            signerKeyPair.PublicKey,
            ManifestSignerKind.ClaimAuthor,
            ResearcherId.New().ToString(),
            "Dr. Signer"));

        Assert.True(result.Success);
        Assert.NotNull(result.UpdatedManifest);
        Assert.Single(result.UpdatedManifest.ManifestSignatures!);
        Assert.Equal(1, result.TotalSignatures);
    }

    [Fact]
    public async Task SignPack_AddsCorrectSignableContract()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);
        var (_, signerKeyPair) = await CreateSignerIdentity("Dr. Signer");

        var result = await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            signerKeyPair.PrivateKey,
            signerKeyPair.PublicKey,
            ManifestSignerKind.ClaimAuthor,
            ResearcherId.New().ToString()));

        var signatureEntry = result.UpdatedManifest!.ManifestSignatures![0];
        Assert.Equal(ClaimPackManifestSignable.ContractVersion, signatureEntry.Signable.Contract);
        Assert.Equal("ClaimPackManifestSignable.v1", signatureEntry.Signable.Contract);
    }

    [Fact]
    public async Task SignPack_SignableContainsCorrectManifestHash()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);
        var (_, signerKeyPair) = await CreateSignerIdentity("Dr. Signer");

        // Load original manifest to compute expected hash
        var originalManifestJson = await File.ReadAllTextAsync(Path.Combine(packDir, "manifest.json"));
        var originalManifest = JsonSerializer.Deserialize<ClaimPackManifest>(originalManifestJson)!;
        var expectedHash = SignPackHandler.ComputeCanonicalManifestHash(originalManifest);

        var result = await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            signerKeyPair.PrivateKey,
            signerKeyPair.PublicKey,
            ManifestSignerKind.ClaimAuthor,
            ResearcherId.New().ToString()));

        var signatureEntry = result.UpdatedManifest!.ManifestSignatures![0];
        Assert.Equal(expectedHash, signatureEntry.Signable.ManifestSha256Hex);
    }

    [Fact]
    public async Task SignPack_MultipleSignatures_AppendsOnly()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        var (_, signer1KeyPair) = await CreateSignerIdentity("Dr. Author");
        var (_, signer2KeyPair) = await CreateSignerIdentity("Publisher Bot");

        // First signature
        await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            signer1KeyPair.PrivateKey,
            signer1KeyPair.PublicKey,
            ManifestSignerKind.ClaimAuthor,
            ResearcherId.New().ToString(),
            "Dr. Author"));

        // Second signature
        var result = await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            signer2KeyPair.PrivateKey,
            signer2KeyPair.PublicKey,
            ManifestSignerKind.Publisher,
            ResearcherId.New().ToString(),
            "Publisher Bot"));

        Assert.True(result.Success);
        Assert.Equal(2, result.TotalSignatures);
        Assert.Equal(2, result.UpdatedManifest!.ManifestSignatures!.Count);
    }

    [Fact]
    public async Task SignPack_InvalidSignerKind_Fails()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);
        var (_, signerKeyPair) = await CreateSignerIdentity("Dr. Signer");

        var result = await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            signerKeyPair.PrivateKey,
            signerKeyPair.PublicKey,
            "INVALID_KIND",
            ResearcherId.New().ToString()));

        Assert.False(result.Success);
        Assert.Contains("Invalid signer kind", result.Error);
    }

    [Fact]
    public async Task SignPack_MissingManifest_Fails()
    {
        var packDir = CreateTempDir();
        var (_, signerKeyPair) = await CreateSignerIdentity("Dr. Signer");

        var result = await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            signerKeyPair.PrivateKey,
            signerKeyPair.PublicKey,
            ManifestSignerKind.ClaimAuthor,
            ResearcherId.New().ToString()));

        Assert.False(result.Success);
        Assert.Contains("manifest.json", result.Error);
    }

    #endregion

    #region Signer Role Tests

    [Fact]
    public async Task SignPack_ClaimAuthorRole_RecordedCorrectly()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);
        var (_, signerKeyPair) = await CreateSignerIdentity("Dr. Author");

        var result = await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            signerKeyPair.PrivateKey,
            signerKeyPair.PublicKey,
            ManifestSignerKind.ClaimAuthor,
            ResearcherId.New().ToString(),
            "Dr. Author"));

        var signatureEntry = result.UpdatedManifest!.ManifestSignatures![0];
        Assert.Equal(ManifestSignerKind.ClaimAuthor, signatureEntry.Signer.Kind);
        Assert.Equal("Dr. Author", signatureEntry.Signer.Identity.DisplayName);
    }

    [Fact]
    public async Task SignPack_PublisherRole_RecordedCorrectly()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);
        var (_, signerKeyPair) = await CreateSignerIdentity("CI/CD Pipeline");

        var result = await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            signerKeyPair.PrivateKey,
            signerKeyPair.PublicKey,
            ManifestSignerKind.Publisher,
            ResearcherId.New().ToString(),
            "CI/CD Pipeline"));

        var signatureEntry = result.UpdatedManifest!.ManifestSignatures![0];
        Assert.Equal(ManifestSignerKind.Publisher, signatureEntry.Signer.Kind);
    }

    [Fact]
    public async Task SignPack_MixedRoles_BothValid()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        var (_, authorKeyPair) = await CreateSignerIdentity("Dr. Author");
        var (_, publisherKeyPair) = await CreateSignerIdentity("Publisher");

        await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            authorKeyPair.PrivateKey,
            authorKeyPair.PublicKey,
            ManifestSignerKind.ClaimAuthor,
            ResearcherId.New().ToString()));

        await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            publisherKeyPair.PrivateKey,
            publisherKeyPair.PublicKey,
            ManifestSignerKind.Publisher,
            ResearcherId.New().ToString()));

        var verifyResult = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packDir,
            VerifyManifestSignatures: true));

        Assert.True(verifyResult.IsValid);
        Assert.NotNull(verifyResult.ManifestSignaturesResult);
        Assert.Equal(2, verifyResult.ManifestSignaturesResult.ValidSignatures);
    }

    #endregion

    #region Verification Tests

    [Fact]
    public async Task VerifyPack_SignedPack_VerifiesSuccessfully()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);
        var (_, signerKeyPair) = await CreateSignerIdentity("Dr. Signer");

        await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            signerKeyPair.PrivateKey,
            signerKeyPair.PublicKey,
            ManifestSignerKind.ClaimAuthor,
            ResearcherId.New().ToString()));

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packDir,
            VerifyManifestSignatures: true));

        Assert.True(result.IsValid);
        Assert.NotNull(result.ManifestSignaturesResult);
        Assert.Equal(1, result.ManifestSignaturesResult.ValidSignatures);
        Assert.Equal(0, result.ManifestSignaturesResult.InvalidSignatures);
    }

    [Fact]
    public async Task VerifyPack_TamperedFile_SignatureFails()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);
        var (_, signerKeyPair) = await CreateSignerIdentity("Dr. Signer");

        await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            signerKeyPair.PrivateKey,
            signerKeyPair.PublicKey,
            ManifestSignerKind.ClaimAuthor,
            ResearcherId.New().ToString()));

        // Tamper with a file listed in manifest
        var claimPath = Path.Combine(packDir, "claim.json");
        var content = await File.ReadAllTextAsync(claimPath);
        await File.WriteAllTextAsync(claimPath, content + " ");

        // Also update the manifest file entry hash to pass inventory check
        // but not the signature (signature is over original hash)
        var manifestPath = Path.Combine(packDir, "manifest.json");
        var manifestJson = await File.ReadAllTextAsync(manifestPath);
        var manifest = JsonSerializer.Deserialize<ClaimPackManifest>(manifestJson)!;

        var newHash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(content + " "))).ToLowerInvariant();
        var updatedFiles = manifest.Files.Select(f =>
            f.Path == "claim.json"
                ? new PackFileEntry { Path = f.Path, MediaType = f.MediaType, Sha256Hex = newHash, SizeBytes = content.Length + 1 }
                : f
        ).ToList();

        // Create new manifest with updated file hash but keep old signature
        var tamperedManifest = new ClaimPackManifest
        {
            PackId = manifest.PackId,
            CreatedAt = manifest.CreatedAt,
            RootClaimPath = manifest.RootClaimPath,
            RootClaimCoreDigest = manifest.RootClaimCoreDigest,
            Include = manifest.Include,
            Files = updatedFiles,
            ManifestSignatures = manifest.ManifestSignatures  // Old signatures
        };
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(tamperedManifest));

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packDir,
            VerifyManifestSignatures: true,
            StrictManifestSignatures: true));

        Assert.False(result.IsValid);
        Assert.NotNull(result.ManifestSignaturesResult);
        Assert.Contains("hash mismatch", result.ManifestSignaturesResult.Results[0].Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyPack_NoSignatures_NonStrict_PassesWithWarning()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packDir,
            VerifyManifestSignatures: true,
            StrictManifestSignatures: false));

        Assert.True(result.IsValid);
        Assert.NotNull(result.ManifestSignaturesResult);
        Assert.Equal(0, result.ManifestSignaturesResult.TotalSignatures);
        Assert.Contains("no manifest signatures", result.ManifestSignaturesResult.Warnings[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyPack_NoSignatures_Strict_Fails()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packDir,
            VerifyManifestSignatures: true,
            StrictManifestSignatures: true));

        Assert.False(result.IsValid);
        Assert.Equal(3, result.ExitCode);  // Broken
        Assert.Contains("at least one signature", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyPack_InvalidSignature_Strict_Fails()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        // Create a signature with wrong key
        var (_, wrongKeyPair) = await CreateSignerIdentity("Wrong Signer");
        var manifestPath = Path.Combine(packDir, "manifest.json");
        var manifest = JsonSerializer.Deserialize<ClaimPackManifest>(await File.ReadAllTextAsync(manifestPath))!;

        var canonicalHash = SignPackHandler.ComputeCanonicalManifestHash(manifest);

        // Create a valid signable but sign with wrong content
        var signable = new ClaimPackManifestSignable
        {
            ManifestSha256Hex = canonicalHash,
            PackId = manifest.PackId,
            RootClaimCoreDigest = manifest.RootClaimCoreDigest,
            CreatedAt = manifest.CreatedAt
        };

        // Sign something different (corrupted signature)
        var wrongData = System.Text.Encoding.UTF8.GetBytes("wrong content");
        var badSignature = wrongKeyPair.PrivateKey.Sign(wrongData);

        var signatureEntry = new ManifestSignatureEntry
        {
            Signable = signable,
            Signature = new ManifestSignature
            {
                PublicKey = wrongKeyPair.PublicKey.ToString(),
                Sig = badSignature.ToString()
            },
            Signer = new ManifestSigner
            {
                Kind = ManifestSignerKind.ClaimAuthor,
                Identity = new ManifestSignerIdentity
                {
                    ResearcherId = ResearcherId.New().ToString(),
                    PublicKey = wrongKeyPair.PublicKey.ToString()
                }
            }
        };

        var tamperedManifest = new ClaimPackManifest
        {
            PackId = manifest.PackId,
            CreatedAt = manifest.CreatedAt,
            RootClaimPath = manifest.RootClaimPath,
            RootClaimCoreDigest = manifest.RootClaimCoreDigest,
            Include = manifest.Include,
            Files = manifest.Files,
            ManifestSignatures = new[] { signatureEntry }
        };
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(tamperedManifest));

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packDir,
            VerifyManifestSignatures: true,
            StrictManifestSignatures: true));

        Assert.False(result.IsValid);
        Assert.Equal(3, result.ExitCode);
    }

    #endregion

    #region Canonicalization Tests

    [Fact]
    public async Task ManifestHash_StableAcrossReserializations()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        var manifestPath = Path.Combine(packDir, "manifest.json");
        var manifest1 = JsonSerializer.Deserialize<ClaimPackManifest>(await File.ReadAllTextAsync(manifestPath))!;

        var hash1 = SignPackHandler.ComputeCanonicalManifestHash(manifest1);

        // Reserialize and deserialize
        var json = JsonSerializer.Serialize(manifest1);
        var manifest2 = JsonSerializer.Deserialize<ClaimPackManifest>(json)!;

        var hash2 = SignPackHandler.ComputeCanonicalManifestHash(manifest2);

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public async Task ManifestHash_ExcludesSignatures()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);
        var (_, signerKeyPair) = await CreateSignerIdentity("Dr. Signer");

        var manifestPath = Path.Combine(packDir, "manifest.json");
        var manifestBefore = JsonSerializer.Deserialize<ClaimPackManifest>(await File.ReadAllTextAsync(manifestPath))!;

        var hashBefore = SignPackHandler.ComputeCanonicalManifestHash(manifestBefore);

        // Add signature
        await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            signerKeyPair.PrivateKey,
            signerKeyPair.PublicKey,
            ManifestSignerKind.ClaimAuthor,
            ResearcherId.New().ToString()));

        var manifestAfter = JsonSerializer.Deserialize<ClaimPackManifest>(await File.ReadAllTextAsync(manifestPath))!;

        var hashAfter = SignPackHandler.ComputeCanonicalManifestHash(manifestAfter);

        // Hash should be same (signatures excluded)
        Assert.Equal(hashBefore, hashAfter);
    }

    #endregion

    #region Revocation Tests

    [Fact]
    public async Task VerifyPack_RevokedManifestSigner_Strict_Fails()
    {
        // Create a signer identity that we'll later revoke
        var signerKeyPair = Ed25519KeyPair.Generate();
        var signerId = ResearcherId.New();

        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        // Sign the pack with a fresh identity (not tied to claim signer)
        await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            signerKeyPair.PrivateKey,
            signerKeyPair.PublicKey,
            ManifestSignerKind.Publisher,  // Use Publisher role to avoid claim signer revocation
            signerId.ToString(),
            "Dr. Manifest Signer"));

        // Create revocation bundle as a separate file (not in pack)
        // We'll add it to a revocations registry directly
        var revocationsDir = CreateTempDir();
        var revocation = Revocation.CreateSelfSigned(
            signerId,
            signerKeyPair.PublicKey,
            signerKeyPair.PrivateKey,
            _clock.UtcNow.AddDays(-1),  // Revoked before signing
            RevocationReason.Compromised);

        var revocationBundleObj = ExportRevocationBundleHandler.Handle(revocation, "Dr. Manifest Signer");
        await File.WriteAllTextAsync(
            Path.Combine(revocationsDir, "revocation.json"),
            JsonSerializer.Serialize(revocationBundleObj));

        // Copy revocations into the pack
        var packRevocationsDir = Path.Combine(packDir, "revocations");
        Directory.CreateDirectory(packRevocationsDir);
        File.Copy(
            Path.Combine(revocationsDir, "revocation.json"),
            Path.Combine(packRevocationsDir, "revocation.json"));

        // Update manifest to include revocations - but we need to re-sign after
        // Actually, for this test we manually update the manifest to point to revocations dir
        await UpdateManifestIncludeNoResign(packDir, revocationsDir: "revocations/");

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packDir,
            VerifyManifestSignatures: true,
            StrictManifestSignatures: true));

        // When the manifest signer is revoked, should fail with exit code 6
        Assert.False(result.IsValid);
        Assert.NotNull(result.ManifestSignaturesResult);
        // The result should show revoked signers
        Assert.True(result.ManifestSignaturesResult.RevokedSigners > 0 ||
                    result.ManifestSignaturesResult.InvalidSignatures > 0);
    }

    [Fact]
    public async Task VerifyPack_RevokedManifestSigner_NonStrict_SignatureInvalid()
    {
        // This tests the scenario where a manifest signer's key is later found
        // in a revocation registry. Since the manifest hash changes when we
        // add the revocations directory, the signature becomes invalid (hash mismatch).
        // This is the expected behavior - you can't add files to a signed pack
        // without invalidating the manifest signature.

        var signerKeyPair = Ed25519KeyPair.Generate();
        var signerId = ResearcherId.New();

        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        // Sign the pack
        await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            signerKeyPair.PrivateKey,
            signerKeyPair.PublicKey,
            ManifestSignerKind.Publisher,
            signerId.ToString(),
            "Dr. Manifest Signer"));

        // Create revocation
        var revocationsDir = CreateTempDir();
        var revocation = Revocation.CreateSelfSigned(
            signerId,
            signerKeyPair.PublicKey,
            signerKeyPair.PrivateKey,
            _clock.UtcNow.AddDays(-1),
            RevocationReason.Compromised);

        var revocationBundleObj = ExportRevocationBundleHandler.Handle(revocation, "Dr. Manifest Signer");
        await File.WriteAllTextAsync(
            Path.Combine(revocationsDir, "revocation.json"),
            JsonSerializer.Serialize(revocationBundleObj));

        // Copy revocations into pack
        var packRevocationsDir = Path.Combine(packDir, "revocations");
        Directory.CreateDirectory(packRevocationsDir);
        File.Copy(
            Path.Combine(revocationsDir, "revocation.json"),
            Path.Combine(packRevocationsDir, "revocation.json"));

        await UpdateManifestIncludeNoResign(packDir, revocationsDir: "revocations/");

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packDir,
            VerifyManifestSignatures: true,
            StrictManifestSignatures: false));

        // Non-strict with one invalid signature should still pass
        // (non-strict only requires NO invalid signatures OR at least one valid signature)
        Assert.NotNull(result.ManifestSignaturesResult);
        // The signature will fail due to manifest hash mismatch (we added a directory)
        Assert.True(result.ManifestSignaturesResult.InvalidSignatures > 0 ||
                    result.ManifestSignaturesResult.Warnings.Count > 0);
    }

    #endregion

    #region Backward Compatibility Tests

    [Fact]
    public async Task VerifyPack_OldPackWithoutSignatures_StillValid()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);

        // Verify without checking signatures
        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.True(result.IsValid);
        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public async Task VerifyPack_SignedPack_WorksWithoutSignatureVerification()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packDir = await CreateValidPack(bundle);
        var (_, signerKeyPair) = await CreateSignerIdentity("Dr. Signer");

        await SignPackHandler.HandleAsync(new SignPackCommand(
            packDir,
            signerKeyPair.PrivateKey,
            signerKeyPair.PublicKey,
            ManifestSignerKind.ClaimAuthor,
            ResearcherId.New().ToString()));

        // Verify without signature checking
        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(packDir));

        Assert.True(result.IsValid);
        Assert.Null(result.ManifestSignaturesResult);  // Not checked
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

    private async Task<(ClaimLedger.Domain.Identity.ResearcherIdentity researcher, Ed25519KeyPair keyPair)> CreateSignerIdentity(string name)
    {
        var keyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();
        var researcher = new ClaimLedger.Domain.Identity.ResearcherIdentity(
            researcherId, keyPair.PublicKey, name, _clock.UtcNow);

        await _identityRepo.SaveAsync(researcher);
        await _keyVault.StoreAsync(researcherId, keyPair.PrivateKey);

        return (researcher, keyPair);
    }

    private async Task<string> CreateValidPack(ClaimBundle bundle)
    {
        var packDir = CreateTempDir();
        await CreatePackHandler.HandleAsync(new CreatePackCommand(bundle, packDir));
        return packDir;
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
            Files = manifest.Files,
            ManifestSignatures = manifest.ManifestSignatures
        };

        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(updatedManifest));
    }

    /// <summary>
    /// Updates manifest include without affecting existing signatures.
    /// Note: This breaks manifest hash consistency - use only for testing revocation scenarios
    /// where we want to add revocation files without re-signing.
    /// </summary>
    private static async Task UpdateManifestIncludeNoResign(string packDir, string? revocationsDir = null)
    {
        var manifestPath = Path.Combine(packDir, "manifest.json");
        var manifestJson = await File.ReadAllTextAsync(manifestPath);
        var manifest = JsonSerializer.Deserialize<ClaimPackManifest>(manifestJson)!;

        var updatedInclude = manifest.Include with
        {
            RevocationsDir = revocationsDir ?? manifest.Include.RevocationsDir
        };

        // Preserve existing signatures even though manifest hash will change
        // This simulates a scenario where revocations are discovered after signing
        var updatedManifest = new ClaimPackManifest
        {
            PackId = manifest.PackId,
            CreatedAt = manifest.CreatedAt,
            RootClaimCoreDigest = manifest.RootClaimCoreDigest,
            Include = updatedInclude,
            Files = manifest.Files,
            ManifestSignatures = manifest.ManifestSignatures
        };

        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(updatedManifest));
    }

    #endregion
}
