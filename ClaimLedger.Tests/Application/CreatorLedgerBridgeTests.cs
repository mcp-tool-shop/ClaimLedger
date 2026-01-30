using System.Text;
using System.Text.Json;
using ClaimLedger.Application.CreatorLedger;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Packs;
using ClaimLedger.Domain.Packs;
using Shared.Crypto;
using Xunit;

namespace ClaimLedger.Tests.Application;

/// <summary>
/// Tests for Phase 10: CreatorLedger Bridge
/// </summary>
public class CreatorLedgerBridgeTests
{
    private readonly CreatorLedgerVerifier _verifier = new();

    #region EvidenceKind Tests

    [Fact]
    public void EvidenceKind_GetEffectiveKind_ReturnsFileForNull()
    {
        Assert.Equal(EvidenceKind.File, EvidenceKind.GetEffectiveKind(null));
    }

    [Fact]
    public void EvidenceKind_GetEffectiveKind_ReturnsFileForFile()
    {
        Assert.Equal(EvidenceKind.File, EvidenceKind.GetEffectiveKind(EvidenceKind.File));
    }

    [Fact]
    public void EvidenceKind_GetEffectiveKind_ReturnsCreatorLedgerBundle()
    {
        Assert.Equal(EvidenceKind.CreatorLedgerBundle,
            EvidenceKind.GetEffectiveKind(EvidenceKind.CreatorLedgerBundle));
    }

    [Fact]
    public void EvidenceKind_IsValid_ReturnsTrueForFile()
    {
        Assert.True(EvidenceKind.IsValid(EvidenceKind.File));
    }

    [Fact]
    public void EvidenceKind_IsValid_ReturnsTrueForCreatorLedgerBundle()
    {
        Assert.True(EvidenceKind.IsValid(EvidenceKind.CreatorLedgerBundle));
    }

    [Fact]
    public void EvidenceKind_IsValid_ReturnsFalseForUnknown()
    {
        Assert.False(EvidenceKind.IsValid("UNKNOWN"));
    }

    #endregion

    #region CreatorLedgerVerifier Parsing Tests

    [Fact]
    public void Verify_InvalidJson_ReturnsInvalidInput()
    {
        var bytes = Encoding.UTF8.GetBytes("not valid json");
        var result = _verifier.Verify(bytes);

        Assert.False(result.IsValid);
        Assert.Equal(CreatorLedgerStatus.InvalidInput, result.Status);
        Assert.Contains("Invalid JSON", result.Error);
    }

    [Fact]
    public void Verify_NullBundle_ReturnsInvalidInput()
    {
        var bytes = Encoding.UTF8.GetBytes("null");
        var result = _verifier.Verify(bytes);

        Assert.False(result.IsValid);
        Assert.Equal(CreatorLedgerStatus.InvalidInput, result.Status);
    }

    [Fact]
    public void Verify_UnsupportedVersion_ReturnsInvalidInput()
    {
        var bundle = new CreatorLedgerBundle
        {
            Version = "proof.v99"
        };
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(bundle));
        var result = _verifier.Verify(bytes);

        Assert.False(result.IsValid);
        Assert.Equal(CreatorLedgerStatus.InvalidInput, result.Status);
        Assert.Contains("Unsupported bundle version", result.Error);
    }

    [Fact]
    public void Verify_UnsupportedAlgorithms_ReturnsInvalidInput()
    {
        var bundle = new CreatorLedgerBundle
        {
            Version = "proof.v1",
            Algorithms = new CreatorLedgerAlgorithms
            {
                Signature = "RSA",
                Hash = "SHA-256",
                Encoding = "UTF-8"
            }
        };
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(bundle));
        var result = _verifier.Verify(bytes);

        Assert.False(result.IsValid);
        Assert.Equal(CreatorLedgerStatus.InvalidInput, result.Status);
        Assert.Contains("Unsupported cryptographic algorithms", result.Error);
    }

    [Fact]
    public void Verify_NoAttestations_ReturnsBroken()
    {
        var bundle = new CreatorLedgerBundle
        {
            Version = "proof.v1",
            Algorithms = new CreatorLedgerAlgorithms
            {
                Signature = "Ed25519",
                Hash = "SHA-256",
                Encoding = "UTF-8"
            },
            Attestations = new List<CreatorLedgerAttestation>()
        };
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(bundle));
        var result = _verifier.Verify(bytes);

        Assert.False(result.IsValid);
        Assert.Equal(CreatorLedgerStatus.Broken, result.Status);
        Assert.Contains("No attestations found", result.Error);
    }

    [Fact]
    public void Verify_EmptyAttestations_ReturnsBroken()
    {
        var bundle = new CreatorLedgerBundle
        {
            Version = "proof.v1",
            Algorithms = new CreatorLedgerAlgorithms
            {
                Signature = "Ed25519",
                Hash = "SHA-256",
                Encoding = "UTF-8"
            },
            Attestations = null
        };
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(bundle));
        var result = _verifier.Verify(bytes);

        Assert.False(result.IsValid);
        Assert.Equal(CreatorLedgerStatus.Broken, result.Status);
    }

    #endregion

    #region CreatorLedgerVerifier Signature Tests

    [Fact]
    public void Verify_ValidBundle_ReturnsVerified()
    {
        // Create a valid bundle with proper Ed25519 signature
        var keyPair = Ed25519KeyPair.Generate();
        var assetId = "asset_test123";
        var contentHash = "abc123def456";
        var creatorId = "creator_test";
        var attestedAt = "2024-01-15T10:30:00Z";

        // Create signable
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

        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(bundle));
        var result = _verifier.Verify(bytes);

        Assert.True(result.IsValid);
        Assert.Equal(CreatorLedgerStatus.Verified, result.Status);
        Assert.Equal(assetId, result.AssetId);
        Assert.Equal(contentHash, result.ContentHash);
        Assert.Equal(1, result.AttestationsVerified);
        Assert.Equal(1, result.SignaturesValid);
        Assert.Equal(0, result.SignaturesFailed);
    }

    [Fact]
    public void Verify_InvalidSignature_ReturnsBroken()
    {
        var bundle = new CreatorLedgerBundle
        {
            Version = "proof.v1",
            Algorithms = new CreatorLedgerAlgorithms
            {
                Signature = "Ed25519",
                Hash = "SHA-256",
                Encoding = "UTF-8"
            },
            AssetId = "asset_test",
            Attestations = new List<CreatorLedgerAttestation>
            {
                new()
                {
                    AttestationId = "att_test",
                    AssetId = "asset_test",
                    ContentHash = "abc123",
                    CreatorId = "creator_test",
                    CreatorPublicKey = Ed25519KeyPair.Generate().PublicKey.ToString(),
                    AttestedAtUtc = "2024-01-15T10:30:00Z",
                    Signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                }
            }
        };

        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(bundle));
        var result = _verifier.Verify(bytes);

        Assert.False(result.IsValid);
        Assert.Equal(CreatorLedgerStatus.Broken, result.Status);
        Assert.Contains("Signature verification failed", result.Error);
    }

    [Fact]
    public void Verify_MissingPublicKey_FailsSignatureVerification()
    {
        var bundle = new CreatorLedgerBundle
        {
            Version = "proof.v1",
            Algorithms = new CreatorLedgerAlgorithms
            {
                Signature = "Ed25519",
                Hash = "SHA-256",
                Encoding = "UTF-8"
            },
            AssetId = "asset_test",
            Attestations = new List<CreatorLedgerAttestation>
            {
                new()
                {
                    AttestationId = "att_test",
                    AssetId = "asset_test",
                    ContentHash = "abc123",
                    CreatorId = "creator_test",
                    CreatorPublicKey = null, // Missing public key
                    AttestedAtUtc = "2024-01-15T10:30:00Z",
                    Signature = "AAAA"
                }
            }
        };

        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(bundle));
        var result = _verifier.Verify(bytes);

        Assert.False(result.IsValid);
        Assert.Equal(CreatorLedgerStatus.Broken, result.Status);
    }

    [Fact]
    public void Verify_MismatchedAssetId_ReturnsBroken()
    {
        // Bundle asset ID doesn't match any attestation
        var keyPair = Ed25519KeyPair.Generate();
        var bundle = new CreatorLedgerBundle
        {
            Version = "proof.v1",
            Algorithms = new CreatorLedgerAlgorithms
            {
                Signature = "Ed25519",
                Hash = "SHA-256",
                Encoding = "UTF-8"
            },
            AssetId = "different_asset",
            Attestations = new List<CreatorLedgerAttestation>
            {
                CreateValidAttestation(keyPair, "other_asset")
            }
        };

        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(bundle));
        var result = _verifier.Verify(bytes);

        Assert.False(result.IsValid);
        Assert.Equal(CreatorLedgerStatus.Broken, result.Status);
        Assert.Contains("No attestation found for asset", result.Error);
    }

    #endregion

    #region Bundle Digest Tests

    [Fact]
    public void ComputeBundleDigest_ReturnsSha256Hex()
    {
        var content = "test content";
        var bytes = Encoding.UTF8.GetBytes(content);

        var digest = _verifier.ComputeBundleDigest(bytes);

        Assert.NotNull(digest);
        Assert.Equal(64, digest.Length); // SHA-256 = 64 hex chars
        Assert.True(digest.All(c => "0123456789abcdef".Contains(c)));
    }

    [Fact]
    public void ComputeBundleDigest_IsDeterministic()
    {
        var content = "{\"test\": \"data\"}";
        var bytes = Encoding.UTF8.GetBytes(content);

        var digest1 = _verifier.ComputeBundleDigest(bytes);
        var digest2 = _verifier.ComputeBundleDigest(bytes);

        Assert.Equal(digest1, digest2);
    }

    [Fact]
    public void ComputeBundleDigest_DifferentForDifferentContent()
    {
        var bytes1 = Encoding.UTF8.GetBytes("content1");
        var bytes2 = Encoding.UTF8.GetBytes("content2");

        var digest1 = _verifier.ComputeBundleDigest(bytes1);
        var digest2 = _verifier.ComputeBundleDigest(bytes2);

        Assert.NotEqual(digest1, digest2);
    }

    #endregion

    #region Trust Level Tests

    [Fact]
    public void Verify_DerivedAttestation_ReturnsDeriveTrustLevel()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var assetId = "asset_derived";
        var attestation = CreateValidAttestation(keyPair, assetId, derivedFrom: "original_asset");

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
            Attestations = new List<CreatorLedgerAttestation> { attestation }
        };

        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(bundle));
        var result = _verifier.Verify(bytes);

        Assert.True(result.IsValid);
        Assert.Equal("Derived", result.TrustLevel);
    }

    [Fact]
    public void Verify_AnchoredAttestation_ReturnsVerifiedOriginal()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var assetId = "asset_anchored";
        var attestation = CreateValidAttestation(keyPair, assetId);

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
            Attestations = new List<CreatorLedgerAttestation> { attestation },
            Anchor = new CreatorLedgerAnchor
            {
                ChainName = "Bitcoin",
                TransactionId = "tx_abc123"
            }
        };

        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(bundle));
        var result = _verifier.Verify(bytes);

        Assert.True(result.IsValid);
        Assert.Equal("Verified Original", result.TrustLevel);
    }

    [Fact]
    public void Verify_UnanchoredAttestation_ReturnsSignedTrustLevel()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var assetId = "asset_unanchored";
        var attestation = CreateValidAttestation(keyPair, assetId);

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
            Attestations = new List<CreatorLedgerAttestation> { attestation },
            Anchor = null
        };

        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(bundle));
        var result = _verifier.Verify(bytes);

        Assert.True(result.IsValid);
        Assert.Equal("Signed", result.TrustLevel);
    }

    #endregion

    #region CreatePack with CreatorLedger Tests

    [Fact]
    public async Task CreatePack_WithCreatorLedgerDir_IncludesBundles()
    {
        using var tempDir = new TempDirectory();
        var outputDir = Path.Combine(tempDir.Path, "pack");
        var clDir = Path.Combine(tempDir.Path, "creatorledger");
        Directory.CreateDirectory(clDir);

        // Create a CreatorLedger bundle file
        var bundleContent = CreateValidBundleJson("asset_test");
        var bundleBytes = Encoding.UTF8.GetBytes(bundleContent);
        var bundleDigest = ComputeFileDigest(bundleBytes);
        await File.WriteAllBytesAsync(Path.Combine(clDir, "bundle.json"), bundleBytes);

        // Create claim bundle with CREATORLEDGER_BUNDLE evidence
        var keyPair = Ed25519KeyPair.Generate();
        var claimBundle = CreateClaimBundleWithCreatorLedgerEvidence(keyPair, bundleDigest);

        var result = await CreatePackHandler.HandleAsync(new CreatePackCommand(
            claimBundle,
            outputDir,
            CreatorLedgerDirectory: clDir));

        Assert.True(result.Success);
        Assert.NotNull(result.Manifest);
        Assert.NotNull(result.Manifest.Include.CreatorLedgerDir);
        Assert.Equal("creatorledger/", result.Manifest.Include.CreatorLedgerDir);

        // Verify bundle was copied
        var copiedPath = Path.Combine(outputDir, "creatorledger", $"{bundleDigest}.json");
        Assert.True(File.Exists(copiedPath));
    }

    [Fact]
    public async Task CreatePack_StrictCreatorLedger_FailsOnMissingBundle()
    {
        using var tempDir = new TempDirectory();
        var outputDir = Path.Combine(tempDir.Path, "pack");
        var clDir = Path.Combine(tempDir.Path, "creatorledger");
        Directory.CreateDirectory(clDir);
        // No bundles in directory

        // Create claim bundle with CREATORLEDGER_BUNDLE evidence
        var keyPair = Ed25519KeyPair.Generate();
        var claimBundle = CreateClaimBundleWithCreatorLedgerEvidence(keyPair, "nonexistent_digest");

        var result = await CreatePackHandler.HandleAsync(new CreatePackCommand(
            claimBundle,
            outputDir,
            CreatorLedgerDirectory: clDir,
            StrictCreatorLedger: true));

        Assert.False(result.Success);
        Assert.Contains("not found", result.Error);
    }

    [Fact]
    public async Task CreatePack_NonStrictCreatorLedger_SucceedsWithMissingBundle()
    {
        using var tempDir = new TempDirectory();
        var outputDir = Path.Combine(tempDir.Path, "pack");
        var clDir = Path.Combine(tempDir.Path, "creatorledger");
        Directory.CreateDirectory(clDir);
        // No bundles in directory

        // Create claim bundle with CREATORLEDGER_BUNDLE evidence
        var keyPair = Ed25519KeyPair.Generate();
        var claimBundle = CreateClaimBundleWithCreatorLedgerEvidence(keyPair, "nonexistent_digest");

        var result = await CreatePackHandler.HandleAsync(new CreatePackCommand(
            claimBundle,
            outputDir,
            CreatorLedgerDirectory: clDir,
            StrictCreatorLedger: false));

        Assert.True(result.Success);
    }

    #endregion

    #region VerifyPack with CreatorLedger Tests

    [Fact]
    public async Task VerifyPack_WithCreatorLedger_VerifiesBundles()
    {
        using var tempDir = new TempDirectory();
        var packDir = Path.Combine(tempDir.Path, "pack");
        var clDir = Path.Combine(tempDir.Path, "creatorledger");

        // Create pack with valid CreatorLedger bundle
        await CreatePackWithCreatorLedger(packDir, clDir);

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packDir,
            VerifyCreatorLedger: true));

        Assert.True(result.IsValid);
        Assert.NotNull(result.CreatorLedgerResult);
        Assert.True(result.CreatorLedgerResult.IsValid);
        Assert.Equal(1, result.CreatorLedgerResult.BundlesVerified);
    }

    [Fact]
    public async Task VerifyPack_StrictCreatorLedger_FailsOnMissingBundle()
    {
        using var tempDir = new TempDirectory();
        var packDir = Path.Combine(tempDir.Path, "pack");
        Directory.CreateDirectory(packDir);

        // Create claim bundle with CREATORLEDGER_BUNDLE evidence
        var keyPair = Ed25519KeyPair.Generate();
        var claimBundle = CreateClaimBundleWithCreatorLedgerEvidence(keyPair, "nonexistent_digest");

        // Write claim.json
        var claimJson = JsonSerializer.Serialize(claimBundle, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packDir, "claim.json"), claimJson);

        // Write manifest
        var digest = ClaimCoreDigest.Compute(claimBundle);
        var manifest = new ClaimPackManifest
        {
            PackId = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            RootClaimCoreDigest = digest.ToString(),
            Include = new PackIncludeConfig(),
            Files = new List<PackFileEntry>
            {
                CreatePackFileEntry(Path.Combine(packDir, "claim.json"), "claim.json")
            }
        };
        var manifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packDir, "manifest.json"), manifestJson);

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packDir,
            StrictCreatorLedger: true));

        Assert.False(result.IsValid);
        Assert.NotNull(result.CreatorLedgerResult);
        Assert.False(result.CreatorLedgerResult.IsValid);
        Assert.Equal(1, result.CreatorLedgerResult.BundlesMissing);
    }

    [Fact]
    public async Task VerifyPack_NonStrictCreatorLedger_WarnsOnMissingBundle()
    {
        using var tempDir = new TempDirectory();
        var packDir = Path.Combine(tempDir.Path, "pack");
        Directory.CreateDirectory(packDir);

        // Create claim bundle with CREATORLEDGER_BUNDLE evidence
        var keyPair = Ed25519KeyPair.Generate();
        var claimBundle = CreateClaimBundleWithCreatorLedgerEvidence(keyPair, "nonexistent_digest");

        // Write claim.json
        var claimJson = JsonSerializer.Serialize(claimBundle, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packDir, "claim.json"), claimJson);

        // Write manifest
        var digest = ClaimCoreDigest.Compute(claimBundle);
        var manifest = new ClaimPackManifest
        {
            PackId = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            RootClaimCoreDigest = digest.ToString(),
            Include = new PackIncludeConfig(),
            Files = new List<PackFileEntry>
            {
                CreatePackFileEntry(Path.Combine(packDir, "claim.json"), "claim.json")
            }
        };
        var manifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packDir, "manifest.json"), manifestJson);

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packDir,
            VerifyCreatorLedger: true,
            StrictCreatorLedger: false));

        Assert.True(result.IsValid);
        Assert.NotNull(result.CreatorLedgerResult);
        Assert.True(result.CreatorLedgerResult.IsValid);
        Assert.Equal(1, result.CreatorLedgerResult.BundlesMissing);
        Assert.True(result.CreatorLedgerResult.Warnings.Count > 0);
    }

    [Fact]
    public async Task VerifyPack_CreatorLedger_FailsOnInvalidBundle()
    {
        using var tempDir = new TempDirectory();
        var packDir = Path.Combine(tempDir.Path, "pack");
        var clDir = Path.Combine(packDir, "creatorledger");
        Directory.CreateDirectory(clDir);

        // Create invalid bundle
        var invalidBundle = "{\"Version\": \"proof.v1\", \"Attestations\": []}";
        var bundleBytes = Encoding.UTF8.GetBytes(invalidBundle);
        var bundleDigest = ComputeFileDigest(bundleBytes);
        await File.WriteAllBytesAsync(Path.Combine(clDir, $"{bundleDigest}.json"), bundleBytes);

        // Create claim bundle with CREATORLEDGER_BUNDLE evidence
        var keyPair = Ed25519KeyPair.Generate();
        var claimBundle = CreateClaimBundleWithCreatorLedgerEvidence(keyPair, bundleDigest);

        // Write claim.json
        var claimJson = JsonSerializer.Serialize(claimBundle, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packDir, "claim.json"), claimJson);

        // Write manifest
        var digest = ClaimCoreDigest.Compute(claimBundle);
        var manifest = new ClaimPackManifest
        {
            PackId = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            RootClaimCoreDigest = digest.ToString(),
            Include = new PackIncludeConfig { CreatorLedgerDir = "creatorledger/" },
            Files = new List<PackFileEntry>
            {
                CreatePackFileEntry(Path.Combine(packDir, "claim.json"), "claim.json"),
                CreatePackFileEntry(Path.Combine(clDir, $"{bundleDigest}.json"), $"creatorledger/{bundleDigest}.json")
            }
        };
        var manifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packDir, "manifest.json"), manifestJson);

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packDir,
            VerifyCreatorLedger: true));

        Assert.False(result.IsValid);
        Assert.NotNull(result.CreatorLedgerResult);
        Assert.Equal(1, result.CreatorLedgerResult.BundlesFailed);
    }

    [Fact]
    public async Task VerifyPack_NoCreatorLedgerEvidence_SkipsVerification()
    {
        using var tempDir = new TempDirectory();
        var packDir = Path.Combine(tempDir.Path, "pack");
        Directory.CreateDirectory(packDir);

        // Create standard claim bundle without CreatorLedger evidence
        var keyPair = Ed25519KeyPair.Generate();
        var claimBundle = CreateStandardClaimBundle(keyPair);

        // Write claim.json
        var claimJson = JsonSerializer.Serialize(claimBundle, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packDir, "claim.json"), claimJson);

        // Write manifest
        var digest = ClaimCoreDigest.Compute(claimBundle);
        var manifest = new ClaimPackManifest
        {
            PackId = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            RootClaimCoreDigest = digest.ToString(),
            Include = new PackIncludeConfig(),
            Files = new List<PackFileEntry>
            {
                CreatePackFileEntry(Path.Combine(packDir, "claim.json"), "claim.json")
            }
        };
        var manifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packDir, "manifest.json"), manifestJson);

        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packDir,
            VerifyCreatorLedger: true,
            StrictCreatorLedger: true));

        Assert.True(result.IsValid);
        Assert.NotNull(result.CreatorLedgerResult);
        Assert.True(result.CreatorLedgerResult.IsValid);
        Assert.Equal(0, result.CreatorLedgerResult.TotalBundles);
    }

    [Fact]
    public async Task VerifyPack_OverrideCreatorLedgerDir()
    {
        using var tempDir = new TempDirectory();
        var packDir = Path.Combine(tempDir.Path, "pack");
        var externalClDir = Path.Combine(tempDir.Path, "external_cl");
        Directory.CreateDirectory(externalClDir);

        // Create valid bundle in external directory
        var keyPair = Ed25519KeyPair.Generate();
        var bundleContent = CreateValidBundleJson("asset_test", keyPair);
        var bundleBytes = Encoding.UTF8.GetBytes(bundleContent);
        var bundleDigest = ComputeFileDigest(bundleBytes);
        await File.WriteAllBytesAsync(Path.Combine(externalClDir, $"{bundleDigest}.json"), bundleBytes);

        // Create claim bundle with CREATORLEDGER_BUNDLE evidence
        var claimBundle = CreateClaimBundleWithCreatorLedgerEvidence(keyPair, bundleDigest);

        // Create pack without embedded CreatorLedger
        Directory.CreateDirectory(packDir);
        var claimJson = JsonSerializer.Serialize(claimBundle, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packDir, "claim.json"), claimJson);

        var digest = ClaimCoreDigest.Compute(claimBundle);
        var manifest = new ClaimPackManifest
        {
            PackId = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            RootClaimCoreDigest = digest.ToString(),
            Include = new PackIncludeConfig(), // No CreatorLedgerDir
            Files = new List<PackFileEntry>
            {
                CreatePackFileEntry(Path.Combine(packDir, "claim.json"), "claim.json")
            }
        };
        var manifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packDir, "manifest.json"), manifestJson);

        // Verify using external directory
        var result = await VerifyPackHandler.HandleAsync(new VerifyPackCommand(
            packDir,
            VerifyCreatorLedger: true,
            CreatorLedgerDirectory: externalClDir));

        Assert.True(result.IsValid);
        Assert.NotNull(result.CreatorLedgerResult);
        Assert.Equal(1, result.CreatorLedgerResult.BundlesVerified);
    }

    #endregion

    #region Helper Methods

    private static CreatorLedgerAttestation CreateValidAttestation(Ed25519KeyPair keyPair, string assetId, string? derivedFrom = null)
    {
        var contentHash = "abc123def456";
        var creatorId = "creator_test";
        var attestedAt = "2024-01-15T10:30:00Z";

        object signable;
        if (derivedFrom != null)
        {
            signable = new
            {
                asset_id = assetId,
                content_hash = contentHash,
                creator_id = creatorId,
                creator_public_key = keyPair.PublicKey.ToString(),
                attested_at_utc = attestedAt,
                derived_from_asset_id = derivedFrom
            };
        }
        else
        {
            signable = new
            {
                asset_id = assetId,
                content_hash = contentHash,
                creator_id = creatorId,
                creator_public_key = keyPair.PublicKey.ToString(),
                attested_at_utc = attestedAt
            };
        }

        var signableBytes = CanonicalJson.SerializeToBytes(signable);
        var signature = keyPair.PrivateKey.Sign(signableBytes);

        return new CreatorLedgerAttestation
        {
            AttestationId = "att_test",
            AssetId = assetId,
            ContentHash = contentHash,
            CreatorId = creatorId,
            CreatorPublicKey = keyPair.PublicKey.ToString(),
            AttestedAtUtc = attestedAt,
            Signature = signature.ToString(),
            DerivedFromAssetId = derivedFrom
        };
    }

    private static string CreateValidBundleJson(string assetId, Ed25519KeyPair? keyPair = null)
    {
        keyPair ??= Ed25519KeyPair.Generate();
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

    private static ClaimBundle CreateClaimBundleWithCreatorLedgerEvidence(Ed25519KeyPair keyPair, string bundleDigest)
    {
        var claimId = $"claim_{Guid.NewGuid():N}";
        var statement = "Test claim with CreatorLedger evidence";
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

        // Create signable
        var signable = new
        {
            claim_id = claimId,
            statement,
            asserted_at_utc = assertedAt,
            evidence = evidence.Select(e => new { type = e.Type, hash = e.Hash, kind = e.Kind }).ToList(),
            researcher_id = "test_researcher"
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
                ResearcherId = "test_researcher",
                PublicKey = keyPair.PublicKey.ToString()
            }
        };
    }

    private static ClaimBundle CreateStandardClaimBundle(Ed25519KeyPair keyPair)
    {
        var claimId = $"claim_{Guid.NewGuid():N}";
        var statement = "Test claim with standard file evidence";
        var assertedAt = DateTimeOffset.UtcNow.ToString("O");

        var evidence = new List<EvidenceInfo>
        {
            new()
            {
                Type = "text/plain",
                Hash = "abc123def456",
                Kind = EvidenceKind.File
            }
        };

        // Create signable
        var signable = new
        {
            claim_id = claimId,
            statement,
            asserted_at_utc = assertedAt,
            evidence = evidence.Select(e => new { type = e.Type, hash = e.Hash }).ToList(),
            researcher_id = "test_researcher"
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
                ResearcherId = "test_researcher",
                PublicKey = keyPair.PublicKey.ToString()
            }
        };
    }

    private static PackFileEntry CreatePackFileEntry(string filePath, string packPath)
    {
        var fileInfo = new FileInfo(filePath);
        using var stream = File.OpenRead(filePath);
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var hash = sha256.ComputeHash(stream);

        return new PackFileEntry
        {
            Path = packPath,
            MediaType = "application/json",
            Sha256Hex = Convert.ToHexString(hash).ToLowerInvariant(),
            SizeBytes = fileInfo.Length
        };
    }

    private static async Task CreatePackWithCreatorLedger(string packDir, string clDir)
    {
        Directory.CreateDirectory(packDir);
        Directory.CreateDirectory(clDir);
        var packClDir = Path.Combine(packDir, "creatorledger");
        Directory.CreateDirectory(packClDir);

        // Create valid CreatorLedger bundle
        var clKeyPair = Ed25519KeyPair.Generate();
        var bundleContent = CreateValidBundleJson("asset_test", clKeyPair);
        var bundleBytes = Encoding.UTF8.GetBytes(bundleContent);
        var bundleDigest = ComputeFileDigest(bundleBytes);
        var bundlePath = Path.Combine(packClDir, $"{bundleDigest}.json");
        await File.WriteAllBytesAsync(bundlePath, bundleBytes);

        // Create claim bundle
        var keyPair = Ed25519KeyPair.Generate();
        var claimBundle = CreateClaimBundleWithCreatorLedgerEvidence(keyPair, bundleDigest);

        // Write claim.json
        var claimJson = JsonSerializer.Serialize(claimBundle, new JsonSerializerOptions { WriteIndented = true });
        var claimPath = Path.Combine(packDir, "claim.json");
        await File.WriteAllTextAsync(claimPath, claimJson);

        // Create manifest
        var digest = ClaimCoreDigest.Compute(claimBundle);
        var manifest = new ClaimPackManifest
        {
            PackId = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            RootClaimCoreDigest = digest.ToString(),
            Include = new PackIncludeConfig
            {
                CreatorLedgerDir = "creatorledger/"
            },
            Files = new List<PackFileEntry>
            {
                CreatePackFileEntry(claimPath, "claim.json"),
                CreatePackFileEntry(bundlePath, $"creatorledger/{bundleDigest}.json")
            }
        };

        var manifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(packDir, "manifest.json"), manifestJson);
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
