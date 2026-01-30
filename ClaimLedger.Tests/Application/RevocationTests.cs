using System.Globalization;
using ClaimLedger.Application.Attestations;
using ClaimLedger.Application.Citations;
using ClaimLedger.Application.Claims;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Identity;
using ClaimLedger.Application.Revocations;
using ClaimLedger.Domain.Attestations;
using ClaimLedger.Domain.Citations;
using ClaimLedger.Domain.Primitives;
using ClaimLedger.Domain.Revocations;
using ClaimLedger.Tests.Fakes;
using Shared.Crypto;

namespace ClaimLedger.Tests.Application;

public class RevocationTests
{
    private readonly InMemoryKeyVault _keyVault = new();
    private readonly InMemoryResearcherIdentityRepository _identityRepo = new();
    private readonly InMemoryClaimRepository _claimRepo = new();
    private readonly FakeClock _clock = new();

    [Fact]
    public void RevocationRegistry_Empty_NoRevocations()
    {
        var registry = RevocationRegistry.Empty;
        var keyPair = Ed25519KeyPair.Generate();

        Assert.Null(registry.GetEarliestRevocation(keyPair.PublicKey));
        Assert.False(registry.IsRevoked(keyPair.PublicKey, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void RevocationRegistry_Add_FindsRevocation()
    {
        var registry = new RevocationRegistry();
        var keyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();
        var revokedAt = DateTimeOffset.UtcNow;

        var revocation = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            revokedAt,
            RevocationReason.Compromised);

        registry.Add(revocation);

        Assert.NotNull(registry.GetEarliestRevocation(keyPair.PublicKey));
        Assert.True(registry.IsRevoked(keyPair.PublicKey, revokedAt));
    }

    [Fact]
    public void RevocationRegistry_MultipleRevocations_UsesEarliest()
    {
        var registry = new RevocationRegistry();
        var keyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();

        var earlyTime = DateTimeOffset.Parse("2024-01-01T00:00:00Z", CultureInfo.InvariantCulture);
        var lateTime = DateTimeOffset.Parse("2024-06-01T00:00:00Z", CultureInfo.InvariantCulture);

        // Add late revocation first
        var lateRevocation = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            lateTime,
            RevocationReason.Retired);
        registry.Add(lateRevocation);

        // Add early revocation second
        var earlyRevocation = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            earlyTime,
            RevocationReason.Compromised);
        registry.Add(earlyRevocation);

        var earliest = registry.GetEarliestRevocation(keyPair.PublicKey);
        Assert.Equal(earlyTime, earliest!.RevokedAtUtc);
    }

    [Fact]
    public void RevocationRegistry_LoadFromBundle_ValidBundle_Succeeds()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();

        var revocation = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            DateTimeOffset.UtcNow,
            RevocationReason.Rotated);

        var bundle = ExportRevocationBundleHandler.Handle(revocation, "Test User");

        var loaded = RevocationRegistry.LoadFromBundle(bundle);

        Assert.NotNull(loaded);
        Assert.True(loaded!.VerifySignature());
    }

    [Fact]
    public void RevocationRegistry_LoadFromBundle_TamperedBundle_ReturnsNull()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();

        var revocation = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            DateTimeOffset.UtcNow,
            RevocationReason.Rotated);

        var bundle = ExportRevocationBundleHandler.Handle(revocation);

        // Tamper with the bundle
        var tamperedBundle = new RevocationBundle
        {
            Revocation = new RevocationInfo
            {
                RevocationId = bundle.Revocation.RevocationId,
                ResearcherId = bundle.Revocation.ResearcherId,
                RevokedPublicKey = bundle.Revocation.RevokedPublicKey,
                RevokedAtUtc = bundle.Revocation.RevokedAtUtc,
                Reason = RevocationReason.Compromised, // Tampered!
                IssuerMode = bundle.Revocation.IssuerMode,
                SuccessorPublicKey = bundle.Revocation.SuccessorPublicKey,
                Notes = bundle.Revocation.Notes,
                Signature = bundle.Revocation.Signature
            }
        };

        var loaded = RevocationRegistry.LoadFromBundle(tamperedBundle);

        Assert.Null(loaded);
    }

    [Fact]
    public async Task VerifyAgainstRevocations_NoRevocations_Passes()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var registry = RevocationRegistry.Empty;

        var result = VerifyAgainstRevocationsHandler.Handle(
            new VerifyAgainstRevocationsQuery(bundle, registry));

        Assert.True(result.IsValid);
        Assert.Empty(result.Checks.Where(c => c.IsRevoked));
    }

    [Fact]
    public async Task VerifyAgainstRevocations_KeyNotRevoked_Passes()
    {
        var bundle = await CreateClaimBundle("Test claim");

        // Create revocation for a different key
        var otherKeyPair = Ed25519KeyPair.Generate();
        var revocation = Revocation.CreateSelfSigned(
            ResearcherId.New(),
            otherKeyPair.PublicKey,
            otherKeyPair.PrivateKey,
            DateTimeOffset.UtcNow,
            RevocationReason.Compromised);

        var registry = new RevocationRegistry();
        registry.Add(revocation);

        var result = VerifyAgainstRevocationsHandler.Handle(
            new VerifyAgainstRevocationsQuery(bundle, registry));

        Assert.True(result.IsValid);
        Assert.Empty(result.Checks.Where(c => c.IsRevoked));
    }

    [Fact]
    public async Task VerifyAgainstRevocations_KeyRevokedAfterClaim_Passes()
    {
        // Create claim at T
        _clock.UtcNow = DateTimeOffset.Parse("2024-06-01T12:00:00Z", CultureInfo.InvariantCulture);
        var (bundle, keyPair, researcherId) = await CreateClaimBundleWithKeys("Test claim");

        // Revoke key at T+1 day (after claim)
        var revocation = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            DateTimeOffset.Parse("2024-06-02T12:00:00Z", CultureInfo.InvariantCulture),
            RevocationReason.Rotated);

        var registry = new RevocationRegistry();
        registry.Add(revocation);

        var result = VerifyAgainstRevocationsHandler.Handle(
            new VerifyAgainstRevocationsQuery(bundle, registry));

        Assert.True(result.IsValid);
        Assert.Empty(result.Checks.Where(c => c.IsRevoked));
    }

    [Fact]
    public async Task VerifyAgainstRevocations_KeyRevokedBeforeClaim_Fails_StrictMode()
    {
        // Revoke key at T
        var revokedAt = DateTimeOffset.Parse("2024-06-01T12:00:00Z", CultureInfo.InvariantCulture);

        // Create claim at T+1 day (after revocation)
        _clock.UtcNow = DateTimeOffset.Parse("2024-06-02T12:00:00Z", CultureInfo.InvariantCulture);
        var (bundle, keyPair, researcherId) = await CreateClaimBundleWithKeys("Test claim");

        var revocation = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            revokedAt,
            RevocationReason.Compromised);

        var registry = new RevocationRegistry();
        registry.Add(revocation);

        var result = VerifyAgainstRevocationsHandler.Handle(
            new VerifyAgainstRevocationsQuery(bundle, registry, StrictMode: true));

        Assert.False(result.IsValid);
        Assert.Single(result.Checks.Where(c => c.IsRevoked));
    }

    [Fact]
    public async Task VerifyAgainstRevocations_KeyRevokedBeforeClaim_Warns_NonStrictMode()
    {
        // Revoke key at T
        var revokedAt = DateTimeOffset.Parse("2024-06-01T12:00:00Z", CultureInfo.InvariantCulture);

        // Create claim at T+1 day (after revocation)
        _clock.UtcNow = DateTimeOffset.Parse("2024-06-02T12:00:00Z", CultureInfo.InvariantCulture);
        var (bundle, keyPair, researcherId) = await CreateClaimBundleWithKeys("Test claim");

        var revocation = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            revokedAt,
            RevocationReason.Compromised);

        var registry = new RevocationRegistry();
        registry.Add(revocation);

        var result = VerifyAgainstRevocationsHandler.Handle(
            new VerifyAgainstRevocationsQuery(bundle, registry, StrictMode: false));

        Assert.True(result.IsValid); // Non-strict mode passes
        Assert.NotEmpty(result.Warnings); // But warns
        Assert.Single(result.Checks.Where(c => c.IsRevoked));
    }

    [Fact]
    public async Task VerifyAgainstRevocations_KeyRevokedExactlyAtClaim_Fails()
    {
        // Revoke key and create claim at exact same time (boundary case)
        var exactTime = DateTimeOffset.Parse("2024-06-01T12:00:00Z", CultureInfo.InvariantCulture);
        _clock.UtcNow = exactTime;

        var (bundle, keyPair, researcherId) = await CreateClaimBundleWithKeys("Test claim");

        var revocation = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            exactTime,
            RevocationReason.Compromised);

        var registry = new RevocationRegistry();
        registry.Add(revocation);

        var result = VerifyAgainstRevocationsHandler.Handle(
            new VerifyAgainstRevocationsQuery(bundle, registry, StrictMode: true));

        // Boundary: revoked_at <= signed_at means invalid
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task VerifyAgainstRevocations_Citation_SignerRevoked_Fails()
    {
        // Create claim at T
        var claimTime = DateTimeOffset.Parse("2024-06-01T12:00:00Z", CultureInfo.InvariantCulture);
        _clock.UtcNow = claimTime;
        var (bundle, keyPair, researcherId) = await CreateClaimBundleWithKeys("Citing claim");

        // Add citation at T+1 day
        _clock.UtcNow = DateTimeOffset.Parse("2024-06-02T12:00:00Z", CultureInfo.InvariantCulture);
        var citedDigest = Digest256.Compute("cited claim"u8);
        var handler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await handler.HandleAsync(new CreateCitationCommand(
            bundle, citedDigest, CitationRelation.Cites, null, null));
        bundle = AddCitationToBundleHandler.Handle(new AddCitationToBundleCommand(bundle, citation));

        // Revoke key at T+0.5 days (between claim and citation)
        var revocation = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            DateTimeOffset.Parse("2024-06-01T18:00:00Z", CultureInfo.InvariantCulture),
            RevocationReason.Compromised);

        var registry = new RevocationRegistry();
        registry.Add(revocation);

        var result = VerifyAgainstRevocationsHandler.Handle(
            new VerifyAgainstRevocationsQuery(bundle, registry, StrictMode: true));

        // Claim is valid (before revocation), but citation is invalid
        Assert.False(result.IsValid);

        var claimCheck = result.Checks.First(c => c.SignatureType == "Claim");
        var citationCheck = result.Checks.First(c => c.SignatureType == "Citation");

        Assert.False(claimCheck.IsRevoked);
        Assert.True(citationCheck.IsRevoked);
    }

    [Fact]
    public async Task VerifyAgainstRevocations_Attestation_SignerRevoked_Fails()
    {
        // Create claim
        _clock.UtcNow = DateTimeOffset.Parse("2024-06-01T12:00:00Z", CultureInfo.InvariantCulture);
        var bundle = await CreateClaimBundle("Test claim");

        // Create attestor and add attestation
        _clock.UtcNow = DateTimeOffset.Parse("2024-06-02T12:00:00Z", CultureInfo.InvariantCulture);
        var (attestor, attestorKeyPair) = await CreateResearcherWithKeys("Dr. Attestor");

        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, attestor.Id, AttestationType.Reviewed, "Reviewed"));
        bundle = AddAttestationToBundleHandler.Handle(new AddAttestationToBundleCommand(bundle, attestation));

        // Revoke attestor key BEFORE the attestation
        var revocation = Revocation.CreateSelfSigned(
            attestor.Id,
            attestorKeyPair.PublicKey,
            attestorKeyPair.PrivateKey,
            DateTimeOffset.Parse("2024-06-01T18:00:00Z", CultureInfo.InvariantCulture),
            RevocationReason.Compromised);

        var registry = new RevocationRegistry();
        registry.Add(revocation);

        var result = VerifyAgainstRevocationsHandler.Handle(
            new VerifyAgainstRevocationsQuery(bundle, registry, StrictMode: true));

        Assert.False(result.IsValid);

        var attestationCheck = result.Checks.First(c => c.SignatureType == "Attestation");
        Assert.True(attestationCheck.IsRevoked);
    }

    [Fact]
    public void RevocationBundle_RoundTrips()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var newKeyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();

        var revocation = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            DateTimeOffset.UtcNow,
            RevocationReason.Rotated,
            successorPublicKey: newKeyPair.PublicKey,
            notes: "Test notes");

        var bundle = ExportRevocationBundleHandler.Handle(revocation, "Test User");

        // Verify bundle fields
        Assert.Equal("revocation-bundle.v1", bundle.Version);
        Assert.Equal(revocation.Id.ToString(), bundle.Revocation.RevocationId);
        Assert.Equal(researcherId.ToString(), bundle.Revocation.ResearcherId);
        Assert.Equal(keyPair.PublicKey.ToString(), bundle.Revocation.RevokedPublicKey);
        Assert.Equal(RevocationReason.Rotated, bundle.Revocation.Reason);
        Assert.Equal(IssuerMode.Self, bundle.Revocation.IssuerMode);
        Assert.Equal(newKeyPair.PublicKey.ToString(), bundle.Revocation.SuccessorPublicKey);
        Assert.Equal("Test notes", bundle.Revocation.Notes);
        Assert.NotNull(bundle.Identity);
        Assert.Equal("Test User", bundle.Identity!.DisplayName);
    }

    [Fact]
    public async Task Phase3Bundle_BackwardsCompatible_WithRevocations()
    {
        // Create a Phase 3 bundle (with citations, no revocations involved)
        var bundle = await CreateClaimBundle("Test claim");
        var citedDigest = Digest256.Compute("cited claim"u8);

        var citationHandler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await citationHandler.HandleAsync(new CreateCitationCommand(
            bundle, citedDigest, CitationRelation.Cites, null, null));
        bundle = AddCitationToBundleHandler.Handle(new AddCitationToBundleCommand(bundle, citation));

        // Verify against empty registry (no revocations)
        var registry = RevocationRegistry.Empty;
        var result = VerifyAgainstRevocationsHandler.Handle(
            new VerifyAgainstRevocationsQuery(bundle, registry));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Revocation_SuccessorChain_EachLinkValid()
    {
        var keyA = Ed25519KeyPair.Generate();
        var keyB = Ed25519KeyPair.Generate();
        var keyC = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();

        // A → B (A revokes itself, declares B as successor)
        var revocationAtoB = Revocation.CreateSelfSigned(
            researcherId,
            keyA.PublicKey,
            keyA.PrivateKey,
            DateTimeOffset.Parse("2024-01-01T00:00:00Z", CultureInfo.InvariantCulture),
            RevocationReason.Rotated,
            successorPublicKey: keyB.PublicKey);

        // B → C (B revokes itself, declares C as successor)
        var revocationBtoC = Revocation.CreateSelfSigned(
            researcherId,
            keyB.PublicKey,
            keyB.PrivateKey,
            DateTimeOffset.Parse("2024-06-01T00:00:00Z", CultureInfo.InvariantCulture),
            RevocationReason.Rotated,
            successorPublicKey: keyC.PublicKey);

        // Both revocations are independently valid
        Assert.True(revocationAtoB.VerifySignature());
        Assert.True(revocationBtoC.VerifySignature());

        // Registry tracks both
        var registry = new RevocationRegistry();
        registry.Add(revocationAtoB);
        registry.Add(revocationBtoC);

        // A is revoked as of 2024-01-01
        Assert.True(registry.IsRevoked(keyA.PublicKey, DateTimeOffset.Parse("2024-01-02T00:00:00Z", CultureInfo.InvariantCulture)));

        // B is revoked as of 2024-06-01
        Assert.False(registry.IsRevoked(keyB.PublicKey, DateTimeOffset.Parse("2024-05-01T00:00:00Z", CultureInfo.InvariantCulture)));
        Assert.True(registry.IsRevoked(keyB.PublicKey, DateTimeOffset.Parse("2024-06-02T00:00:00Z", CultureInfo.InvariantCulture)));

        // C is not revoked
        Assert.False(registry.IsRevoked(keyC.PublicKey, DateTimeOffset.Parse("2024-12-01T00:00:00Z", CultureInfo.InvariantCulture)));
    }

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

    private async Task<(ClaimBundle bundle, Ed25519KeyPair keyPair, ResearcherId researcherId)> CreateClaimBundleWithKeys(string statement)
    {
        var (researcher, keyPair) = await CreateResearcherWithKeys("Dr. Author " + Guid.NewGuid().ToString()[..8]);
        var claimHandler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);
        var claim = await claimHandler.HandleAsync(new AssertClaimCommand(
            statement,
            researcher.Id,
            Array.Empty<EvidenceInput>()));

        var exportHandler = new ExportClaimBundleHandler(_claimRepo, _identityRepo);
        var bundle = await exportHandler.HandleAsync(new ExportClaimBundleCommand(claim.Id));
        return (bundle, keyPair, researcher.Id);
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
}
