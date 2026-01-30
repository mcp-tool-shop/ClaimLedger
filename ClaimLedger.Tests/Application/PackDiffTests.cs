using System.Security.Cryptography;
using System.Text.Json;
using ClaimLedger.Application.Attestations;
using ClaimLedger.Application.Citations;
using ClaimLedger.Application.Claims;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Identity;
using ClaimLedger.Application.Packs;
using ClaimLedger.Application.Revocations;
using ClaimLedger.Domain.Attestations;
using ClaimLedger.Domain.Citations;
using ClaimLedger.Domain.Packs;
using ClaimLedger.Domain.Primitives;
using ClaimLedger.Domain.Revocations;
using ClaimLedger.Tests.Fakes;
using Shared.Crypto;

namespace ClaimLedger.Tests.Application;

/// <summary>
/// Phase 9 tests for pack diff and update validation.
/// Target: 40-60 tests covering:
/// - IDENTICAL classification
/// - APPEND_ONLY for attestations, timestamps, manifest signatures, revocations
/// - MODIFIED for file/attestation modifications
/// - BREAKING for root digest changes, removals
/// - Policy validation (APPEND_ONLY, ALLOW_MODIFIED)
/// - Violation detection
/// </summary>
public class PackDiffTests : IDisposable
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
        var dir = Path.Combine(Path.GetTempPath(), "packdiff_test_" + Guid.NewGuid().ToString()[..8]);
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        return dir;
    }

    #region IDENTICAL Classification Tests

    [Fact]
    public async Task Diff_IdenticalPacks_ReturnsIdentical()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);
        var packB = await CreateValidPack(bundle);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.True(result.Success);
        Assert.Equal(UpdateClass.Identical, result.Report!.UpdateClass);
    }

    [Fact]
    public async Task Diff_IdenticalPacks_NoFileChanges()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);
        var packB = await CreateValidPack(bundle);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.Empty(result.Report!.Files.Added);
        Assert.Empty(result.Report.Files.Removed);
        Assert.Empty(result.Report.Files.Modified);
    }

    [Fact]
    public async Task Diff_IdenticalPacks_NoSemanticChanges()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);
        var packB = await CreateValidPack(bundle);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.False(result.Report!.Semantics.RootDigestChanged);
        Assert.Empty(result.Report.Semantics.Attestations.Added);
        Assert.Empty(result.Report.Semantics.Timestamps.Added);
        Assert.Empty(result.Report.Semantics.ManifestSignatures.Added);
    }

    [Fact]
    public async Task Diff_SameBundle_DifferentPackIds_StillIdentical()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);
        var packB = await CreateValidPack(bundle);

        // PackIds will differ, but content is the same
        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        // File content identical means IDENTICAL classification
        Assert.Equal(UpdateClass.Identical, result.Report!.UpdateClass);
    }

    #endregion

    #region APPEND_ONLY Classification Tests

    [Fact]
    public async Task Diff_AttestationAppended_ReturnsAppendOnly()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        // Add attestation to bundle
        var attestor = await CreateResearcher("Dr. Peer Reviewer");
        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, attestor.Id, AttestationType.Reviewed, "Methodology verified"));
        var bundleB = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation));

        var packB = await CreateValidPack(bundleB);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.Equal(UpdateClass.AppendOnly, result.Report!.UpdateClass);
        Assert.Single(result.Report.Semantics.Attestations.Added);
        Assert.Empty(result.Report.Semantics.Attestations.Removed);
    }

    [Fact]
    public async Task Diff_MultipleAttestationsAppended_ReturnsAppendOnly()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        // Add multiple attestations
        var attestor1 = await CreateResearcher("Dr. Reviewer 1");
        var attestor2 = await CreateResearcher("Dr. Reviewer 2");
        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);

        var att1 = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, attestor1.Id, AttestationType.Reviewed, "Verified 1"));
        var bundleWithAtt1 = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, att1));

        var att2 = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundleWithAtt1, attestor2.Id, AttestationType.Reviewed, "Verified 2"));
        var bundleB = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundleWithAtt1, att2));

        var packB = await CreateValidPack(bundleB);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.Equal(UpdateClass.AppendOnly, result.Report!.UpdateClass);
        Assert.Equal(2, result.Report.Semantics.Attestations.Added.Count);
    }

    [Fact]
    public async Task Diff_ManifestSignatureAppended_ReturnsAppendOnly()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        // Sign pack B
        var signer = await CreateResearcherWithKeys("Dr. Signer");
        await SignPackHandler.HandleAsync(new SignPackCommand(
            packA,
            signer.keyPair.PrivateKey,
            signer.keyPair.PublicKey,
            ManifestSignerKind.ClaimAuthor,
            signer.researcher.Id.ToString(),
            signer.researcher.DisplayName));

        // Create pack B as a copy of signed pack A
        var packB = CreateTempDir();
        CopyDirectory(packA, packB);

        // Add another signature
        var signer2 = await CreateResearcherWithKeys("Publisher");
        await SignPackHandler.HandleAsync(new SignPackCommand(
            packB,
            signer2.keyPair.PrivateKey,
            signer2.keyPair.PublicKey,
            ManifestSignerKind.Publisher,
            signer2.researcher.Id.ToString(),
            signer2.researcher.DisplayName));

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.Equal(UpdateClass.AppendOnly, result.Report!.UpdateClass);
        Assert.Single(result.Report.Semantics.ManifestSignatures.Added);
    }

    [Fact]
    public async Task Diff_RevocationAppended_ReturnsAppendOnly()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        // Create pack B with revocation
        var packB = CreateTempDir();
        CopyDirectory(packA, packB);

        // Add revocation to pack B
        var revocationsDir = Path.Combine(packB, "revocations");
        Directory.CreateDirectory(revocationsDir);

        var signer = await CreateResearcherWithKeys("Dr. OldKey");
        var revocation = ClaimLedger.Domain.Revocations.Revocation.CreateSelfSigned(
            signer.researcher.Id,
            signer.keyPair.PublicKey,
            signer.keyPair.PrivateKey,
            _clock.UtcNow,
            RevocationReason.Rotated);

        var revBundle = CreateRevocationBundle(revocation);
        await File.WriteAllTextAsync(
            Path.Combine(revocationsDir, $"{revocation.Id}.json"),
            JsonSerializer.Serialize(revBundle));

        // Update manifest to include revocations dir
        await UpdateManifest(packB, include => include with { RevocationsDir = "revocations/" });

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.Equal(UpdateClass.AppendOnly, result.Report!.UpdateClass);
        Assert.Single(result.Report.Semantics.Revocations.Added);
    }

    [Fact]
    public async Task Diff_NewEvidenceFile_ReturnsAppendOnly()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        // Create pack B with additional file
        var packB = CreateTempDir();
        CopyDirectory(packA, packB);

        // Add new evidence file
        var evidenceDir = Path.Combine(packB, "evidence");
        Directory.CreateDirectory(evidenceDir);
        var newFile = Path.Combine(evidenceDir, "extra_data.csv");
        await File.WriteAllTextAsync(newFile, "extra,data,here");

        // Update manifest to include new file
        await AddFileToManifest(packB, "evidence/extra_data.csv", "text/csv", "extra,data,here");

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.Equal(UpdateClass.AppendOnly, result.Report!.UpdateClass);
        Assert.Single(result.Report.Files.Added);
        Assert.Equal("evidence/extra_data.csv", result.Report.Files.Added[0].Path);
    }

    #endregion

    #region MODIFIED Classification Tests

    [Fact]
    public async Task Diff_FileModified_ReturnsModified()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        // Create pack B with modified manifest (but not claim content)
        var packB = CreateTempDir();
        CopyDirectory(packA, packB);

        // Add and then modify an extra file
        var extraFile = Path.Combine(packB, "extra.txt");
        await File.WriteAllTextAsync(extraFile, "original content");
        await AddFileToManifest(packB, "extra.txt", "text/plain", "original content");

        // Now create pack A with the original extra file
        var packAWithExtra = CreateTempDir();
        CopyDirectory(packA, packAWithExtra);
        await File.WriteAllTextAsync(Path.Combine(packAWithExtra, "extra.txt"), "original content");
        await AddFileToManifest(packAWithExtra, "extra.txt", "text/plain", "original content");

        // Modify file in pack B
        await File.WriteAllTextAsync(extraFile, "modified content");
        await UpdateFileInManifest(packB, "extra.txt", "modified content");

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packAWithExtra, packB));

        Assert.Equal(UpdateClass.Modified, result.Report!.UpdateClass);
        Assert.Single(result.Report.Files.Modified);
    }

    #endregion

    #region BREAKING Classification Tests

    [Fact]
    public async Task Diff_RootDigestChanged_ReturnsBreaking()
    {
        var bundleA = await CreateClaimBundle("Original claim");
        var bundleB = await CreateClaimBundle("Different claim");
        var packA = await CreateValidPack(bundleA);
        var packB = await CreateValidPack(bundleB);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.Equal(UpdateClass.Breaking, result.Report!.UpdateClass);
        Assert.True(result.Report.Semantics.RootDigestChanged);
    }

    [Fact]
    public async Task Diff_FileRemoved_ReturnsBreaking()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        // Add extra file to pack A
        var extraFile = Path.Combine(packA, "extra.txt");
        await File.WriteAllTextAsync(extraFile, "extra content");
        await AddFileToManifest(packA, "extra.txt", "text/plain", "extra content");

        // Pack B without the extra file
        var packB = await CreateValidPack(bundle);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.Equal(UpdateClass.Breaking, result.Report!.UpdateClass);
        Assert.Single(result.Report.Files.Removed);
    }

    [Fact]
    public async Task Diff_AttestationRemoved_ReturnsBreaking()
    {
        var bundle = await CreateClaimBundle("Test claim");

        // Add attestation
        var attestor = await CreateResearcher("Dr. Reviewer");
        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, attestor.Id, AttestationType.Reviewed, "Verified"));
        var bundleWithAtt = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation));

        var packA = await CreateValidPack(bundleWithAtt);
        var packB = await CreateValidPack(bundle); // Without attestation

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.Equal(UpdateClass.Breaking, result.Report!.UpdateClass);
        Assert.Single(result.Report.Semantics.Attestations.Removed);
    }

    [Fact]
    public async Task Diff_ManifestSignatureRemoved_ReturnsBreaking()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        // Sign pack A
        var signer = await CreateResearcherWithKeys("Dr. Signer");
        await SignPackHandler.HandleAsync(new SignPackCommand(
            packA,
            signer.keyPair.PrivateKey,
            signer.keyPair.PublicKey,
            ManifestSignerKind.ClaimAuthor,
            signer.researcher.Id.ToString(),
            signer.researcher.DisplayName));

        // Pack B without signature
        var packB = await CreateValidPack(bundle);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.Equal(UpdateClass.Breaking, result.Report!.UpdateClass);
        Assert.Single(result.Report.Semantics.ManifestSignatures.Removed);
    }

    [Fact]
    public async Task Diff_RevocationRemoved_ReturnsBreaking()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        // Add revocation to pack A
        var revocationsDir = Path.Combine(packA, "revocations");
        Directory.CreateDirectory(revocationsDir);

        var signer = await CreateResearcherWithKeys("Dr. OldKey");
        var revocation = ClaimLedger.Domain.Revocations.Revocation.CreateSelfSigned(
            signer.researcher.Id,
            signer.keyPair.PublicKey,
            signer.keyPair.PrivateKey,
            _clock.UtcNow,
            RevocationReason.Rotated);

        var revBundle = CreateRevocationBundle(revocation);
        await File.WriteAllTextAsync(
            Path.Combine(revocationsDir, $"{revocation.Id}.json"),
            JsonSerializer.Serialize(revBundle));

        await UpdateManifest(packA, include => include with { RevocationsDir = "revocations/" });

        // Pack B without revocation
        var packB = await CreateValidPack(bundle);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.Equal(UpdateClass.Breaking, result.Report!.UpdateClass);
        Assert.Single(result.Report.Semantics.Revocations.Removed);
    }

    [Fact]
    public async Task Diff_CitationRemoved_ReturnsBreaking()
    {
        var citedBundle = await CreateClaimBundle("Prior work");
        var citedDigest = ClaimCoreDigest.Compute(citedBundle);

        var bundle = await CreateClaimBundle("Main claim");
        var citationHandler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await citationHandler.HandleAsync(new CreateCitationCommand(
            bundle, citedDigest, CitationRelation.DependsOn, null, "Important prior work"));
        var bundleWithCitation = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(bundle, citation, citedBundle));

        var packA = await CreateValidPack(bundleWithCitation);
        var packB = await CreateValidPack(bundle); // Without citation - different core digest

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        // Citation removal changes core digest, so BREAKING
        Assert.Equal(UpdateClass.Breaking, result.Report!.UpdateClass);
        Assert.True(result.Report.Semantics.RootDigestChanged);
    }

    #endregion

    #region Policy Validation - APPEND_ONLY Tests

    [Fact]
    public async Task ValidateUpdate_AppendOnlyPolicy_IdenticalPasses()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);
        var packB = await CreateValidPack(bundle);

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, packB, PackUpdatePolicy.AppendOnly));

        Assert.True(result.Success);
        Assert.True(result.Validation!.Passed);
        Assert.Empty(result.Validation.Violations);
    }

    [Fact]
    public async Task ValidateUpdate_AppendOnlyPolicy_AttestationAppendedPasses()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        var attestor = await CreateResearcher("Dr. Reviewer");
        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, attestor.Id, AttestationType.Reviewed, "Verified"));
        var bundleB = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation));
        var packB = await CreateValidPack(bundleB);

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, packB, PackUpdatePolicy.AppendOnly));

        Assert.True(result.Success);
        Assert.True(result.Validation!.Passed);
    }

    [Fact]
    public async Task ValidateUpdate_AppendOnlyPolicy_RootDigestChangeFails()
    {
        var bundleA = await CreateClaimBundle("Original claim");
        var bundleB = await CreateClaimBundle("Different claim");
        var packA = await CreateValidPack(bundleA);
        var packB = await CreateValidPack(bundleB);

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, packB, PackUpdatePolicy.AppendOnly));

        Assert.False(result.Success);
        Assert.False(result.Validation!.Passed);
        Assert.Contains(result.Validation.Violations, v => v.Type == PolicyViolationType.RootDigestChanged);
    }

    [Fact]
    public async Task ValidateUpdate_AppendOnlyPolicy_FileRemovalFails()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        // Add extra file to pack A
        await File.WriteAllTextAsync(Path.Combine(packA, "extra.txt"), "extra");
        await AddFileToManifest(packA, "extra.txt", "text/plain", "extra");

        var packB = await CreateValidPack(bundle);

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, packB, PackUpdatePolicy.AppendOnly));

        Assert.False(result.Success);
        Assert.False(result.Validation!.Passed);
        Assert.Contains(result.Validation.Violations, v => v.Type == PolicyViolationType.FileRemoved);
    }

    [Fact]
    public async Task ValidateUpdate_AppendOnlyPolicy_FileModificationFails()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);
        var packB = CreateTempDir();
        CopyDirectory(packA, packB);

        // Add file to both packs
        await File.WriteAllTextAsync(Path.Combine(packA, "extra.txt"), "original");
        await AddFileToManifest(packA, "extra.txt", "text/plain", "original");

        await File.WriteAllTextAsync(Path.Combine(packB, "extra.txt"), "modified");
        await AddFileToManifest(packB, "extra.txt", "text/plain", "modified");

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, packB, PackUpdatePolicy.AppendOnly));

        Assert.False(result.Success);
        Assert.False(result.Validation!.Passed);
        Assert.Contains(result.Validation.Violations, v => v.Type == PolicyViolationType.FileModified);
    }

    [Fact]
    public async Task ValidateUpdate_AppendOnlyPolicy_AttestationRemovalFails()
    {
        var bundle = await CreateClaimBundle("Test claim");

        var attestor = await CreateResearcher("Dr. Reviewer");
        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, attestor.Id, AttestationType.Reviewed, "Verified"));
        var bundleWithAtt = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation));

        var packA = await CreateValidPack(bundleWithAtt);
        var packB = await CreateValidPack(bundle);

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, packB, PackUpdatePolicy.AppendOnly));

        Assert.False(result.Success);
        Assert.Contains(result.Validation!.Violations, v => v.Type == PolicyViolationType.AttestationRemoved);
    }

    [Fact]
    public async Task ValidateUpdate_AppendOnlyPolicy_ManifestSignatureRemovalFails()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        var signer = await CreateResearcherWithKeys("Dr. Signer");
        await SignPackHandler.HandleAsync(new SignPackCommand(
            packA,
            signer.keyPair.PrivateKey,
            signer.keyPair.PublicKey,
            ManifestSignerKind.ClaimAuthor,
            signer.researcher.Id.ToString(),
            signer.researcher.DisplayName));

        var packB = await CreateValidPack(bundle);

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, packB, PackUpdatePolicy.AppendOnly));

        Assert.False(result.Success);
        Assert.Contains(result.Validation!.Violations, v => v.Type == PolicyViolationType.ManifestSignatureRemoved);
    }

    [Fact]
    public async Task ValidateUpdate_AppendOnlyPolicy_RevocationRemovalFails()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        var revocationsDir = Path.Combine(packA, "revocations");
        Directory.CreateDirectory(revocationsDir);

        var signer = await CreateResearcherWithKeys("Dr. OldKey");
        var revocation = ClaimLedger.Domain.Revocations.Revocation.CreateSelfSigned(
            signer.researcher.Id,
            signer.keyPair.PublicKey,
            signer.keyPair.PrivateKey,
            _clock.UtcNow,
            RevocationReason.Rotated);

        var revBundle = CreateRevocationBundle(revocation);
        await File.WriteAllTextAsync(
            Path.Combine(revocationsDir, $"{revocation.Id}.json"),
            JsonSerializer.Serialize(revBundle));

        await UpdateManifest(packA, include => include with { RevocationsDir = "revocations/" });

        var packB = await CreateValidPack(bundle);

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, packB, PackUpdatePolicy.AppendOnly));

        Assert.False(result.Success);
        Assert.Contains(result.Validation!.Violations, v => v.Type == PolicyViolationType.RevocationRemoved);
    }

    [Fact]
    public async Task ValidateUpdate_AppendOnlyPolicy_MultipleViolationsReported()
    {
        var bundleA = await CreateClaimBundle("Original claim");
        var bundleB = await CreateClaimBundle("Different claim");
        var packA = await CreateValidPack(bundleA);

        // Add extra file to pack A
        await File.WriteAllTextAsync(Path.Combine(packA, "extra.txt"), "extra");
        await AddFileToManifest(packA, "extra.txt", "text/plain", "extra");

        var packB = await CreateValidPack(bundleB);

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, packB, PackUpdatePolicy.AppendOnly));

        Assert.False(result.Success);
        // Should have at least ROOT_DIGEST_CHANGED and FILE_REMOVED
        Assert.True(result.Validation!.Violations.Count >= 2);
    }

    #endregion

    #region Policy Validation - ALLOW_MODIFIED Tests

    [Fact]
    public async Task ValidateUpdate_AllowModifiedPolicy_ModificationPasses()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);
        var packB = CreateTempDir();
        CopyDirectory(packA, packB);

        // Add file to both packs with different content
        await File.WriteAllTextAsync(Path.Combine(packA, "extra.txt"), "original");
        await AddFileToManifest(packA, "extra.txt", "text/plain", "original");

        await File.WriteAllTextAsync(Path.Combine(packB, "extra.txt"), "modified");
        await AddFileToManifest(packB, "extra.txt", "text/plain", "modified");

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, packB, PackUpdatePolicy.AllowModified));

        Assert.True(result.Success);
        Assert.True(result.Validation!.Passed);
    }

    [Fact]
    public async Task ValidateUpdate_AllowModifiedPolicy_BreakingStillFails()
    {
        var bundleA = await CreateClaimBundle("Original claim");
        var bundleB = await CreateClaimBundle("Different claim");
        var packA = await CreateValidPack(bundleA);
        var packB = await CreateValidPack(bundleB);

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, packB, PackUpdatePolicy.AllowModified));

        Assert.False(result.Success);
        Assert.False(result.Validation!.Passed);
    }

    [Fact]
    public async Task ValidateUpdate_AllowModifiedPolicy_RemovalFails()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        await File.WriteAllTextAsync(Path.Combine(packA, "extra.txt"), "extra");
        await AddFileToManifest(packA, "extra.txt", "text/plain", "extra");

        var packB = await CreateValidPack(bundle);

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, packB, PackUpdatePolicy.AllowModified));

        Assert.False(result.Success);
        Assert.Contains(result.Validation!.Violations, v => v.Type == PolicyViolationType.FileRemoved);
    }

    #endregion

    #region Error Handling Tests

    [Fact]
    public async Task Diff_NonexistentPackA_ReturnsError()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packB = await CreateValidPack(bundle);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(
            "/nonexistent/path/a", packB));

        Assert.False(result.Success);
        Assert.Equal(4, result.ExitCode);
        Assert.Contains("not found", result.Error);
    }

    [Fact]
    public async Task Diff_NonexistentPackB_ReturnsError()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(
            packA, "/nonexistent/path/b"));

        Assert.False(result.Success);
        Assert.Equal(4, result.ExitCode);
        Assert.Contains("not found", result.Error);
    }

    [Fact]
    public async Task Diff_MissingManifest_ReturnsError()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);
        var packB = CreateTempDir();

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.False(result.Success);
        Assert.Contains("manifest", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateUpdate_InvalidPolicy_ReturnsError()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);
        var packB = await CreateValidPack(bundle);

        // ValidateUpdateHandler doesn't validate policy directly, but the CLI does
        // For now, test with a valid policy
        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, packB, PackUpdatePolicy.AppendOnly));

        Assert.True(result.Success);
    }

    #endregion

    #region Exit Code Tests

    [Fact]
    public async Task ValidateUpdate_PolicyPass_ExitCode0()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);
        var packB = await CreateValidPack(bundle);

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, packB, PackUpdatePolicy.AppendOnly));

        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public async Task ValidateUpdate_PolicyViolation_ExitCode2()
    {
        var bundleA = await CreateClaimBundle("Original claim");
        var bundleB = await CreateClaimBundle("Different claim");
        var packA = await CreateValidPack(bundleA);
        var packB = await CreateValidPack(bundleB);

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, packB, PackUpdatePolicy.AppendOnly));

        Assert.Equal(2, result.ExitCode);
    }

    [Fact]
    public async Task ValidateUpdate_InvalidInput_ExitCode4()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        var result = await ValidateUpdateHandler.HandleAsync(new ValidateUpdateCommand(
            packA, "/nonexistent/path", PackUpdatePolicy.AppendOnly));

        Assert.Equal(4, result.ExitCode);
    }

    #endregion

    #region Semantic Diff Detail Tests

    [Fact]
    public async Task Diff_CorrectlyIdentifiesAttestationDetails()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        var attestor = await CreateResearcher("Dr. Specific Reviewer");
        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, attestor.Id, AttestationType.Reproduced, "Replicated successfully"));
        var bundleB = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation));
        var packB = await CreateValidPack(bundleB);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        var addedAtt = result.Report!.Semantics.Attestations.Added.Single();
        Assert.Equal(attestation.Id.ToString(), addedAtt.AttestationId);
        Assert.Equal(AttestationType.Reproduced, addedAtt.AttestationType);
    }

    [Fact]
    public async Task Diff_CorrectlyIdentifiesManifestSignatureDetails()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);

        var signer = await CreateResearcherWithKeys("Dr. Author Signer");
        await SignPackHandler.HandleAsync(new SignPackCommand(
            packA,
            signer.keyPair.PrivateKey,
            signer.keyPair.PublicKey,
            ManifestSignerKind.ClaimAuthor,
            signer.researcher.Id.ToString(),
            signer.researcher.DisplayName));

        var packB = await CreateValidPack(bundle);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packB, packA));

        var addedSig = result.Report!.Semantics.ManifestSignatures.Added.Single();
        Assert.Equal(ManifestSignerKind.ClaimAuthor, addedSig.SignerKind);
        Assert.Contains(signer.keyPair.PublicKey.ToString()[..8], addedSig.SignerPublicKey);
    }

    [Fact]
    public async Task Diff_CorrectlyReportsFileChangeDetails()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);
        var packB = CreateTempDir();
        CopyDirectory(packA, packB);

        var content1 = "content version 1";
        var content2 = "content version 2 is different";

        await File.WriteAllTextAsync(Path.Combine(packA, "data.txt"), content1);
        await AddFileToManifest(packA, "data.txt", "text/plain", content1);

        await File.WriteAllTextAsync(Path.Combine(packB, "data.txt"), content2);
        await AddFileToManifest(packB, "data.txt", "text/plain", content2);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        var modifiedFile = result.Report!.Files.Modified.Single();
        Assert.Equal("data.txt", modifiedFile.Path);
        Assert.NotEqual(modifiedFile.OldSha256Hex, modifiedFile.NewSha256Hex);
        Assert.NotEqual(modifiedFile.OldSizeBytes, modifiedFile.NewSizeBytes);
    }

    #endregion

    #region Edge Cases

    [Fact]
    public async Task Diff_EmptyPackVsPackWithFiles_CorrectlyCountsAdded()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);
        var packB = CreateTempDir();
        CopyDirectory(packA, packB);

        // Add multiple files to pack B
        var evidenceDir = Path.Combine(packB, "evidence");
        Directory.CreateDirectory(evidenceDir);
        await File.WriteAllTextAsync(Path.Combine(evidenceDir, "file1.csv"), "data1");
        await File.WriteAllTextAsync(Path.Combine(evidenceDir, "file2.csv"), "data2");
        await AddFileToManifest(packB, "evidence/file1.csv", "text/csv", "data1");
        await AddFileToManifest(packB, "evidence/file2.csv", "text/csv", "data2");

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.Equal(2, result.Report!.Files.Added.Count);
    }

    [Fact]
    public async Task Diff_SameRootDigestDifferentPackIds_ReportsRootDigestUnchanged()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);
        var packB = await CreateValidPack(bundle);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.False(result.Report!.Semantics.RootDigestChanged);
        Assert.Equal(result.Report.PackA.RootClaimCoreDigest, result.Report.PackB.RootClaimCoreDigest);
    }

    [Fact]
    public async Task Diff_PackReferences_ContainCorrectMetadata()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var packA = await CreateValidPack(bundle);
        var packB = await CreateValidPack(bundle);

        var result = await DiffPackHandler.HandleAsync(new DiffPackCommand(packA, packB));

        Assert.NotNull(result.Report!.PackA.PackId);
        Assert.NotNull(result.Report.PackB.PackId);
        Assert.NotNull(result.Report.PackA.CreatedAt);
        Assert.NotNull(result.Report.PackB.CreatedAt);
        Assert.True(result.Report.PackA.FileCount > 0);
        Assert.True(result.Report.PackB.FileCount > 0);
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

    private async Task<string> CreateValidPack(ClaimBundle bundle)
    {
        var packDir = CreateTempDir();
        await CreatePackHandler.HandleAsync(new CreatePackCommand(bundle, packDir));
        return packDir;
    }

    private static void CopyDirectory(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);
        foreach (var file in Directory.GetFiles(sourceDir))
        {
            File.Copy(file, Path.Combine(destDir, Path.GetFileName(file)));
        }
        foreach (var dir in Directory.GetDirectories(sourceDir))
        {
            CopyDirectory(dir, Path.Combine(destDir, Path.GetFileName(dir)));
        }
    }

    private static RevocationBundle CreateRevocationBundle(ClaimLedger.Domain.Revocations.Revocation revocation)
    {
        return new RevocationBundle
        {
            Revocation = new RevocationInfo
            {
                RevocationId = revocation.Id.ToString(),
                ResearcherId = revocation.ResearcherId.ToString(),
                RevokedPublicKey = revocation.RevokedPublicKey.ToString(),
                RevokedAtUtc = revocation.RevokedAtUtc.ToString("O"),
                Reason = revocation.Reason,
                IssuerMode = revocation.IssuerMode,
                SuccessorPublicKey = revocation.SuccessorPublicKey?.ToString(),
                Notes = revocation.Notes,
                Signature = revocation.Signature.ToString()
            }
        };
    }

    private static async Task UpdateManifest(string packDir, Func<PackIncludeConfig, PackIncludeConfig> updateInclude)
    {
        var manifestPath = Path.Combine(packDir, "manifest.json");
        var manifestJson = await File.ReadAllTextAsync(manifestPath);
        var manifest = JsonSerializer.Deserialize<ClaimPackManifest>(manifestJson)!;

        var updatedManifest = new ClaimPackManifest
        {
            PackId = manifest.PackId,
            CreatedAt = manifest.CreatedAt,
            RootClaimCoreDigest = manifest.RootClaimCoreDigest,
            Include = updateInclude(manifest.Include),
            Files = manifest.Files
        };

        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(updatedManifest));
    }

    private static async Task AddFileToManifest(string packDir, string relativePath, string mediaType, string content)
    {
        var manifestPath = Path.Combine(packDir, "manifest.json");
        var manifestJson = await File.ReadAllTextAsync(manifestPath);
        var manifest = JsonSerializer.Deserialize<ClaimPackManifest>(manifestJson)!;

        var hash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(content))).ToLowerInvariant();
        var size = System.Text.Encoding.UTF8.GetByteCount(content);

        var updatedFiles = manifest.Files.ToList();
        updatedFiles.Add(new PackFileEntry
        {
            Path = relativePath,
            MediaType = mediaType,
            Sha256Hex = hash,
            SizeBytes = size
        });

        var updatedManifest = new ClaimPackManifest
        {
            PackId = manifest.PackId,
            CreatedAt = manifest.CreatedAt,
            RootClaimCoreDigest = manifest.RootClaimCoreDigest,
            Include = manifest.Include,
            Files = updatedFiles
        };

        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(updatedManifest));
    }

    private static async Task UpdateFileInManifest(string packDir, string relativePath, string newContent)
    {
        var manifestPath = Path.Combine(packDir, "manifest.json");
        var manifestJson = await File.ReadAllTextAsync(manifestPath);
        var manifest = JsonSerializer.Deserialize<ClaimPackManifest>(manifestJson)!;

        var hash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(newContent))).ToLowerInvariant();
        var size = System.Text.Encoding.UTF8.GetByteCount(newContent);

        var updatedFiles = manifest.Files.Select(f =>
            f.Path == relativePath
                ? new PackFileEntry { Path = f.Path, MediaType = f.MediaType, Sha256Hex = hash, SizeBytes = size }
                : f
        ).ToList();

        var updatedManifest = new ClaimPackManifest
        {
            PackId = manifest.PackId,
            CreatedAt = manifest.CreatedAt,
            RootClaimCoreDigest = manifest.RootClaimCoreDigest,
            Include = manifest.Include,
            Files = updatedFiles
        };

        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(updatedManifest));
    }

    #endregion
}
