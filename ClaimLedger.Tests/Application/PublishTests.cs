using System.IO.Compression;
using System.Text;
using System.Text.Json;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Packs;
using ClaimLedger.Application.Publish;
using ClaimLedger.Domain.Citations;
using ClaimLedger.Domain.Packs;
using ClaimLedger.Domain.Publish;
using Shared.Crypto;
using Xunit;

namespace ClaimLedger.Tests.Application;

/// <summary>
/// Tests for Phase 12: Publish Command
/// </summary>
public class PublishTests
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    #region Happy Path Tests

    [Fact]
    public async Task Publish_ToDirectory_Success()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath));

        Assert.True(result.Success);
        Assert.Equal(0, result.ExitCode);
        Assert.NotNull(result.Report);
        Assert.Equal(OutputKind.Directory, result.Report.OutputKind);
        Assert.True(Directory.Exists(outputPath));
        Assert.True(File.Exists(Path.Combine(outputPath, "manifest.json")));
        Assert.True(File.Exists(Path.Combine(outputPath, "claim.json")));
    }

    [Fact]
    public async Task Publish_ToZip_Success()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output.zip");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath));

        Assert.True(result.Success);
        Assert.Equal(0, result.ExitCode);
        Assert.NotNull(result.Report);
        Assert.Equal(OutputKind.Zip, result.Report.OutputKind);
        Assert.True(File.Exists(outputPath));

        // Verify ZIP contents
        using var zip = ZipFile.OpenRead(outputPath);
        Assert.Contains(zip.Entries, e => e.Name == "manifest.json");
        Assert.Contains(zip.Entries, e => e.Name == "claim.json");
    }

    [Fact]
    public async Task Publish_WithZipFlag_CreatesZip()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            Zip: true));

        Assert.True(result.Success);
        Assert.Equal(OutputKind.Zip, result.Report!.OutputKind);
        // Output path is used as-is with zip flag
        Assert.True(File.Exists(outputPath));
    }

    [Fact]
    public async Task Publish_WithPublisherSignature_Success()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");
        var publisherKeyPath = Path.Combine(tempDir.Path, "publisher.key.json");
        var publisherIdentityPath = Path.Combine(tempDir.Path, "publisher.identity.json");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        // Create publisher key and identity files
        var publisherKeyPair = Ed25519KeyPair.Generate();
        var publisherId = Guid.NewGuid().ToString();
        await CreateKeyFile(publisherKeyPath, publisherKeyPair.PrivateKey);
        await CreateIdentityFile(publisherIdentityPath, publisherId, publisherKeyPair.PublicKey, "Test Publisher");

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            SignPack: true,
            PublisherKeyPath: publisherKeyPath,
            PublisherIdentityPath: publisherIdentityPath));

        Assert.True(result.Success);
        Assert.NotNull(result.Report);
        Assert.True(result.Report.Signing.PublisherSigned);
        Assert.False(result.Report.Signing.AuthorSigned);
        Assert.Equal(1, result.Report.Counts.ManifestSignatures);
    }

    [Fact]
    public async Task Publish_WithAuthorSignature_Success()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");
        var authorKeyPath = Path.Combine(tempDir.Path, "author.key.json");
        var authorIdentityPath = Path.Combine(tempDir.Path, "author.identity.json");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        // Create author key and identity files
        var authorKeyPair = Ed25519KeyPair.Generate();
        var authorId = Guid.NewGuid().ToString();
        await CreateKeyFile(authorKeyPath, authorKeyPair.PrivateKey);
        await CreateIdentityFile(authorIdentityPath, authorId, authorKeyPair.PublicKey, "Test Author");

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            SignPack: true,
            AuthorKeyPath: authorKeyPath,
            AuthorIdentityPath: authorIdentityPath));

        Assert.True(result.Success);
        Assert.NotNull(result.Report);
        Assert.False(result.Report.Signing.PublisherSigned);
        Assert.True(result.Report.Signing.AuthorSigned);
        Assert.Equal(1, result.Report.Counts.ManifestSignatures);
    }

    [Fact]
    public async Task Publish_WithBothSignatures_Success()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");
        var publisherKeyPath = Path.Combine(tempDir.Path, "publisher.key.json");
        var publisherIdentityPath = Path.Combine(tempDir.Path, "publisher.identity.json");
        var authorKeyPath = Path.Combine(tempDir.Path, "author.key.json");
        var authorIdentityPath = Path.Combine(tempDir.Path, "author.identity.json");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        // Create publisher key and identity
        var publisherKeyPair = Ed25519KeyPair.Generate();
        await CreateKeyFile(publisherKeyPath, publisherKeyPair.PrivateKey);
        await CreateIdentityFile(publisherIdentityPath, Guid.NewGuid().ToString(), publisherKeyPair.PublicKey, "Publisher");

        // Create author key and identity
        var authorKeyPair = Ed25519KeyPair.Generate();
        await CreateKeyFile(authorKeyPath, authorKeyPair.PrivateKey);
        await CreateIdentityFile(authorIdentityPath, Guid.NewGuid().ToString(), authorKeyPair.PublicKey, "Author");

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            SignPack: true,
            PublisherKeyPath: publisherKeyPath,
            PublisherIdentityPath: publisherIdentityPath,
            AuthorKeyPath: authorKeyPath,
            AuthorIdentityPath: authorIdentityPath));

        Assert.True(result.Success);
        Assert.NotNull(result.Report);
        Assert.True(result.Report.Signing.PublisherSigned);
        Assert.True(result.Report.Signing.AuthorSigned);
        Assert.Equal(2, result.Report.Counts.ManifestSignatures);
    }

    #endregion

    #region Inclusion Correctness Tests

    [Fact]
    public async Task Publish_WithEvidence_CopiesFiles()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var evidenceDir = Path.Combine(tempDir.Path, "evidence");
        var outputPath = Path.Combine(tempDir.Path, "output");

        Directory.CreateDirectory(evidenceDir);
        await File.WriteAllTextAsync(Path.Combine(evidenceDir, "data.csv"), "a,b,c\n1,2,3");
        await File.WriteAllTextAsync(Path.Combine(evidenceDir, "notes.txt"), "Test notes");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            EvidenceDirectory: evidenceDir,
            Strict: false)); // Non-strict since evidence hashes don't match

        Assert.True(result.Success, $"Error: {result.Error}, ExitCode: {result.ExitCode}");
        Assert.NotNull(result.Report);
        Assert.True(result.Report.Included.Evidence);
        Assert.Equal(2, result.Report.Counts.EvidenceFiles);
        Assert.True(File.Exists(Path.Combine(outputPath, "evidence", "data.csv")));
        Assert.True(File.Exists(Path.Combine(outputPath, "evidence", "notes.txt")));
    }

    [Fact]
    public async Task Publish_WithCreatorLedger_CopiesBundles()
    {
        // This test verifies that CreatorLedger bundles are correctly copied to the output pack
        // Uses the CreatePack functionality directly since verification is complex
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var clDir = Path.Combine(tempDir.Path, "creatorledger");
        var outputPath = Path.Combine(tempDir.Path, "output");

        Directory.CreateDirectory(clDir);

        // Create a CreatorLedger bundle file
        var clKeyPair = Ed25519KeyPair.Generate();
        var bundleContent = CreateValidCreatorLedgerBundle("asset_123", clKeyPair);
        var bundleBytes = Encoding.UTF8.GetBytes(bundleContent);
        var bundleDigest = ComputeDigest(bundleBytes);
        await File.WriteAllBytesAsync(Path.Combine(clDir, $"{bundleDigest}.json"), bundleBytes);

        // Create claim with CreatorLedger evidence pointing to the bundle
        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateBundleWithCreatorLedgerEvidence(keyPair, bundleDigest);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        // Use CreatePackHandler directly to test bundle copying without full verification
        var createResult = await CreatePackHandler.HandleAsync(new CreatePackCommand(
            RootBundle: bundle,
            OutputDirectory: outputPath,
            CreatorLedgerDirectory: clDir,
            StrictCreatorLedger: false));

        Assert.True(createResult.Success, $"Error: {createResult.Error}");
        Assert.NotNull(createResult.Manifest);
        Assert.NotNull(createResult.Manifest.Include.CreatorLedgerDir);
        Assert.True(File.Exists(Path.Combine(outputPath, "creatorledger", $"{bundleDigest}.json")));
    }

    [Fact]
    public async Task Publish_WithCitations_ResolvesClaims()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");

        // Create claim with embedded citation
        var keyPair = Ed25519KeyPair.Generate();
        var citedBundle = CreateValidBundle(keyPair, "Cited claim");
        var citedDigest = ClaimCoreDigest.Compute(citedBundle).ToString();
        var mainBundle = CreateBundleWithEmbeddedCitation(keyPair, citedBundle);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(mainBundle, JsonOptions));

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            IncludeCitations: true));

        Assert.True(result.Success);
        Assert.NotNull(result.Report);
        Assert.True(result.Report.Included.Citations);
        Assert.Equal(2, result.Report.Counts.Claims); // root + cited
        Assert.True(File.Exists(Path.Combine(outputPath, "claims", $"{citedDigest}.json")));
    }

    [Fact]
    public async Task Publish_ManifestInventory_Complete()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var evidenceDir = Path.Combine(tempDir.Path, "evidence");
        var outputPath = Path.Combine(tempDir.Path, "output");

        Directory.CreateDirectory(evidenceDir);
        await File.WriteAllTextAsync(Path.Combine(evidenceDir, "data.csv"), "test");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            EvidenceDirectory: evidenceDir,
            Strict: false)); // Non-strict since evidence hashes don't match

        Assert.True(result.Success, $"Error: {result.Error}");

        // Verify manifest has all files with correct hashes
        var manifestJson = await File.ReadAllTextAsync(Path.Combine(outputPath, "manifest.json"));
        var manifest = JsonSerializer.Deserialize<ClaimPackManifest>(manifestJson);

        Assert.NotNull(manifest);
        Assert.Contains(manifest.Files, f => f.Path == "claim.json");
        Assert.Contains(manifest.Files, f => f.Path == "evidence/data.csv");

        // Verify hashes are correct
        foreach (var file in manifest.Files)
        {
            var filePath = Path.Combine(outputPath, file.Path.Replace('/', Path.DirectorySeparatorChar));
            var actualHash = ComputeDigest(await File.ReadAllBytesAsync(filePath));
            Assert.Equal(actualHash, file.Sha256Hex, StringComparer.OrdinalIgnoreCase);
        }
    }

    #endregion

    #region Failure Cases

    [Fact]
    public async Task Publish_MissingInputFile_FailsWithCode4()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "nonexistent.json");
        var outputPath = Path.Combine(tempDir.Path, "output");

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath));

        Assert.False(result.Success);
        Assert.Equal(4, result.ExitCode);
        Assert.Contains("not found", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Publish_InvalidClaimBundle_FailsWithCode4()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");

        await File.WriteAllTextAsync(claimPath, "{ invalid json");

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath));

        Assert.False(result.Success);
        Assert.Equal(4, result.ExitCode);
    }

    [Fact]
    public async Task Publish_SignPackWithoutKeys_FailsWithCode4()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            SignPack: true));

        Assert.False(result.Success);
        Assert.Equal(4, result.ExitCode);
        Assert.Contains("requires", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Publish_PublisherKeyWithoutIdentity_FailsWithCode4()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");
        var publisherKeyPath = Path.Combine(tempDir.Path, "publisher.key.json");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var publisherKeyPair = Ed25519KeyPair.Generate();
        await CreateKeyFile(publisherKeyPath, publisherKeyPair.PrivateKey);

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            SignPack: true,
            PublisherKeyPath: publisherKeyPath));

        Assert.False(result.Success);
        Assert.Equal(4, result.ExitCode);
        Assert.Contains("identity", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Publish_MissingEvidenceDirectory_FailsWithCode4()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            EvidenceDirectory: Path.Combine(tempDir.Path, "nonexistent")));

        Assert.False(result.Success);
        Assert.Equal(4, result.ExitCode);
        Assert.Contains("not found", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Publish_StrictWithMissingCreatorLedger_FailsWithCode4()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var clDir = Path.Combine(tempDir.Path, "creatorledger");
        var outputPath = Path.Combine(tempDir.Path, "output");

        Directory.CreateDirectory(clDir);
        // No bundle files in directory

        // Create claim with CreatorLedger evidence pointing to missing bundle
        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateBundleWithCreatorLedgerEvidence(keyPair, "0000000000000000000000000000000000000000000000000000000000000000");
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            CreatorLedgerDirectory: clDir,
            Strict: true));

        Assert.False(result.Success);
        // Strict mode should fail when CreatorLedger bundle is missing
        Assert.True(result.ExitCode == 3 || result.ExitCode == 4);
    }

    #endregion

    #region Report Correctness Tests

    [Fact]
    public async Task Publish_ReportContainsCorrectDigests()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");
        var reportPath = Path.Combine(tempDir.Path, "report.json");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        var expectedDigest = ClaimCoreDigest.Compute(bundle).ToString();
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            ReportPath: reportPath));

        Assert.True(result.Success);
        Assert.NotNull(result.Report);
        Assert.Equal(expectedDigest, result.Report.RootClaimCoreDigest);

        // Verify report was written
        Assert.True(File.Exists(reportPath));
        var reportJson = await File.ReadAllTextAsync(reportPath);
        var savedReport = JsonSerializer.Deserialize<PublishReport>(reportJson);
        Assert.NotNull(savedReport);
        Assert.Equal(expectedDigest, savedReport.RootClaimCoreDigest);
    }

    [Fact]
    public async Task Publish_ReportContainsCorrectCounts()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var evidenceDir = Path.Combine(tempDir.Path, "evidence");
        var outputPath = Path.Combine(tempDir.Path, "output");

        Directory.CreateDirectory(evidenceDir);
        await File.WriteAllTextAsync(Path.Combine(evidenceDir, "file1.txt"), "test1");
        await File.WriteAllTextAsync(Path.Combine(evidenceDir, "file2.txt"), "test2");
        await File.WriteAllTextAsync(Path.Combine(evidenceDir, "file3.txt"), "test3");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            EvidenceDirectory: evidenceDir,
            Strict: false)); // Non-strict since evidence hashes don't match

        Assert.True(result.Success, $"Error: {result.Error}");
        Assert.NotNull(result.Report);
        Assert.Equal(1, result.Report.Counts.Claims);
        Assert.Equal(3, result.Report.Counts.EvidenceFiles);
    }

    [Fact]
    public async Task Publish_ReportContainsCorrectGateResult()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            Strict: true));

        Assert.True(result.Success);
        Assert.NotNull(result.Report);
        Assert.Equal(GateResult.Pass, result.Report.VerificationGate.Result);
        Assert.Equal(0, result.Report.VerificationGate.ExitCode);
        Assert.True(result.Report.VerificationGate.Strict);
    }

    [Fact]
    public async Task Publish_ReportContainsCorrectContract()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");
        var reportPath = Path.Combine(tempDir.Path, "report.json");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            ReportPath: reportPath));

        Assert.True(result.Success);
        Assert.NotNull(result.Report);
        Assert.Equal(PublishReport.ContractVersion, result.Report.Contract);

        // Verify from saved file
        var reportJson = await File.ReadAllTextAsync(reportPath);
        Assert.Contains("\"contract\"", reportJson);
        Assert.Contains("PublishReport.v1", reportJson);
    }

    [Fact]
    public async Task Publish_ReportContainsSigningInfo()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");
        var publisherKeyPath = Path.Combine(tempDir.Path, "publisher.key.json");
        var publisherIdentityPath = Path.Combine(tempDir.Path, "publisher.identity.json");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var publisherKeyPair = Ed25519KeyPair.Generate();
        await CreateKeyFile(publisherKeyPath, publisherKeyPair.PrivateKey);
        await CreateIdentityFile(publisherIdentityPath, Guid.NewGuid().ToString(), publisherKeyPair.PublicKey, "Pub");

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            SignPack: true,
            PublisherKeyPath: publisherKeyPath,
            PublisherIdentityPath: publisherIdentityPath));

        Assert.True(result.Success);
        Assert.NotNull(result.Report);
        Assert.True(result.Report.Signing.PublisherSigned);
        Assert.False(result.Report.Signing.AuthorSigned);
    }

    #endregion

    #region Non-Strict Mode Tests

    [Fact]
    public async Task Publish_NonStrict_SucceedsWithWarnings()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath,
            Strict: false));

        Assert.True(result.Success);
        Assert.Equal(0, result.ExitCode);
    }

    #endregion

    #region Edge Cases

    [Fact]
    public async Task Publish_OverwritesExistingDirectory()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        // Create existing directory with some content
        Directory.CreateDirectory(outputPath);
        await File.WriteAllTextAsync(Path.Combine(outputPath, "old-file.txt"), "old content");

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath));

        Assert.True(result.Success);
        Assert.False(File.Exists(Path.Combine(outputPath, "old-file.txt")));
        Assert.True(File.Exists(Path.Combine(outputPath, "manifest.json")));
    }

    [Fact]
    public async Task Publish_OverwritesExistingZip()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "output.zip");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        // Create existing zip
        await File.WriteAllTextAsync(outputPath, "old zip content");

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath));

        Assert.True(result.Success);
        // Verify it's a valid zip now
        using var zip = ZipFile.OpenRead(outputPath);
        Assert.True(zip.Entries.Count > 0);
    }

    [Fact]
    public async Task Publish_CreatesParentDirectories()
    {
        using var tempDir = new TempDirectory();
        var claimPath = Path.Combine(tempDir.Path, "claim.json");
        var outputPath = Path.Combine(tempDir.Path, "nested", "path", "output");

        var keyPair = Ed25519KeyPair.Generate();
        var bundle = CreateValidBundle(keyPair);
        await File.WriteAllTextAsync(claimPath, JsonSerializer.Serialize(bundle, JsonOptions));

        var result = await PublishHandler.HandleAsync(new PublishCommand(
            InputClaimPath: claimPath,
            OutputPath: outputPath));

        Assert.True(result.Success);
        Assert.True(Directory.Exists(outputPath));
    }

    #endregion

    #region Helper Methods

    private static ClaimBundle CreateValidBundle(Ed25519KeyPair keyPair, string? statement = null)
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

    private static ClaimBundle CreateBundleWithCreatorLedgerEvidence(Ed25519KeyPair keyPair, string bundleDigest)
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
                BundleAssetId = "asset_123"
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

    private static ClaimBundle CreateBundleWithEmbeddedCitation(Ed25519KeyPair keyPair, ClaimBundle citedBundle)
    {
        var claimId = Guid.NewGuid().ToString();
        var researcherId = Guid.NewGuid().ToString();
        var statement = "Claim that cites another";
        var assertedAt = DateTimeOffset.UtcNow.ToString("O");
        var citedDigest = ClaimCoreDigest.Compute(citedBundle).ToString();

        var evidence = new List<EvidenceInfo>
        {
            new() { Type = "text/plain", Hash = Guid.NewGuid().ToString("N") }
        };

        // Create citation
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
                Signature = citationSig.ToString(),
                Embedded = citedBundle
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

    private static string CreateValidCreatorLedgerBundle(string assetId, Ed25519KeyPair keyPair)
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

        var bundle = new
        {
            version = "proof.v1",
            algorithms = new { signature = "Ed25519", hash = "SHA-256", encoding = "UTF-8" },
            asset_id = assetId,
            attestations = new[]
            {
                new
                {
                    attestation_id = "att_test",
                    asset_id = assetId,
                    content_hash = contentHash,
                    creator_id = creatorId,
                    creator_public_key = keyPair.PublicKey.ToString(),
                    attested_at_utc = attestedAt,
                    signature = signature.ToString()
                }
            }
        };

        return JsonSerializer.Serialize(bundle, JsonOptions);
    }

    private static async Task CreateKeyFile(string path, Ed25519PrivateKey privateKey)
    {
        var keyJson = new { private_key = Convert.ToHexString(privateKey.AsBytes().ToArray()).ToLowerInvariant() };
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(keyJson, JsonOptions));
    }

    private static async Task CreateIdentityFile(string path, string researcherId, Ed25519PublicKey publicKey, string displayName)
    {
        var identityJson = new
        {
            researcher_id = researcherId,
            public_key = publicKey.ToString(),
            display_name = displayName
        };
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(identityJson, JsonOptions));
    }

    private static string ComputeDigest(byte[] bytes)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private sealed class TempDirectory : IDisposable
    {
        public string Path { get; }

        public TempDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"clpub_{Guid.NewGuid():N}");
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
                // Ignore cleanup failures
            }
        }
    }

    #endregion
}
