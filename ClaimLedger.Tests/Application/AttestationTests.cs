using ClaimLedger.Application.Attestations;
using ClaimLedger.Application.Claims;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Identity;
using ClaimLedger.Domain.Attestations;
using ClaimLedger.Domain.Identity;
using ClaimLedger.Tests.Fakes;
using Shared.Crypto;

namespace ClaimLedger.Tests.Application;

public class AttestationTests
{
    private readonly InMemoryKeyVault _keyVault = new();
    private readonly InMemoryResearcherIdentityRepository _identityRepo = new();
    private readonly InMemoryClaimRepository _claimRepo = new();
    private readonly FakeClock _clock = new();

    [Fact]
    public async Task CreateAttestation_ValidAttestation_Verifies()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var attestor = await CreateResearcher("Dr. Reviewer");

        var handler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await handler.HandleAsync(new CreateAttestationCommand(
            bundle,
            attestor.Id,
            AttestationType.Reviewed,
            "Reviewed methods and evidence; claim matches provided artifacts."));

        Assert.True(attestation.VerifySignature());
    }

    [Fact]
    public async Task CreateAttestation_BindsToClaimCoreDigest()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var attestor = await CreateResearcher("Dr. Reviewer");

        var handler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await handler.HandleAsync(new CreateAttestationCommand(
            bundle,
            attestor.Id,
            AttestationType.Reviewed,
            "Test attestation"));

        var expectedDigest = ClaimCoreDigest.Compute(bundle);
        Assert.Equal(expectedDigest, attestation.ClaimCoreDigest);
    }

    [Fact]
    public async Task CreateAttestation_InvalidType_Throws()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var attestor = await CreateResearcher("Dr. Reviewer");

        var handler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            handler.HandleAsync(new CreateAttestationCommand(
                bundle,
                attestor.Id,
                "INVALID_TYPE",
                "Test attestation")));
    }

    [Fact]
    public async Task VerifyAttestations_ValidAttestation_ReturnsValid()
    {
        var (bundle, _) = await CreateAttestedBundle();

        var result = VerifyAttestationsHandler.Handle(
            new VerifyAttestationsQuery(bundle, DateTimeOffset.UtcNow));

        Assert.True(result.AllValid);
        Assert.Single(result.Results);
        Assert.True(result.Results[0].IsValid);
    }

    [Fact]
    public async Task VerifyAttestations_NoAttestations_ReturnsValid()
    {
        var bundle = await CreateClaimBundle("Test claim");

        var result = VerifyAttestationsHandler.Handle(
            new VerifyAttestationsQuery(bundle, DateTimeOffset.UtcNow));

        Assert.True(result.AllValid);
        Assert.Empty(result.Results);
    }

    [Fact]
    public async Task VerifyAttestations_TamperedStatement_ReturnsBroken()
    {
        var (bundle, _) = await CreateAttestedBundle();

        // Tamper with statement
        var tamperedAttestation = new AttestationInfo
        {
            AttestationId = bundle.Attestations![0].AttestationId,
            ClaimCoreDigest = bundle.Attestations[0].ClaimCoreDigest,
            Attestor = bundle.Attestations[0].Attestor,
            AttestationType = bundle.Attestations[0].AttestationType,
            Statement = "TAMPERED STATEMENT",  // Different!
            IssuedAtUtc = bundle.Attestations[0].IssuedAtUtc,
            ExpiresAtUtc = bundle.Attestations[0].ExpiresAtUtc,
            Signature = bundle.Attestations[0].Signature
        };

        var tamperedBundle = new ClaimBundle
        {
            Version = bundle.Version,
            Algorithms = bundle.Algorithms,
            Claim = bundle.Claim,
            Researcher = bundle.Researcher,
            Attestations = new[] { tamperedAttestation }
        };

        var result = VerifyAttestationsHandler.Handle(
            new VerifyAttestationsQuery(tamperedBundle, DateTimeOffset.UtcNow));

        Assert.False(result.AllValid);
        Assert.Single(result.Results);
        Assert.False(result.Results[0].IsValid);
        Assert.Equal(AttestationCheckResult.Reasons.SignatureInvalid, result.Results[0].FailureReason);
    }

    [Fact]
    public async Task VerifyAttestations_WrongDigest_ReturnsBroken()
    {
        var (bundle, _) = await CreateAttestedBundle();

        // Tamper with digest
        var tamperedAttestation = new AttestationInfo
        {
            AttestationId = bundle.Attestations![0].AttestationId,
            ClaimCoreDigest = Digest256.Compute("wrong content"u8).ToString(),  // Wrong!
            Attestor = bundle.Attestations[0].Attestor,
            AttestationType = bundle.Attestations[0].AttestationType,
            Statement = bundle.Attestations[0].Statement,
            IssuedAtUtc = bundle.Attestations[0].IssuedAtUtc,
            ExpiresAtUtc = bundle.Attestations[0].ExpiresAtUtc,
            Signature = bundle.Attestations[0].Signature
        };

        var tamperedBundle = new ClaimBundle
        {
            Version = bundle.Version,
            Algorithms = bundle.Algorithms,
            Claim = bundle.Claim,
            Researcher = bundle.Researcher,
            Attestations = new[] { tamperedAttestation }
        };

        var result = VerifyAttestationsHandler.Handle(
            new VerifyAttestationsQuery(tamperedBundle, DateTimeOffset.UtcNow));

        Assert.False(result.AllValid);
        Assert.Equal(AttestationCheckResult.Reasons.DigestMismatch, result.Results[0].FailureReason);
    }

    [Fact]
    public async Task VerifyAttestations_ExpiredAttestation_ReturnsBroken()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var attestor = await CreateResearcher("Dr. Reviewer");

        // Create attestation that expires in the past
        var handler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await handler.HandleAsync(new CreateAttestationCommand(
            bundle,
            attestor.Id,
            AttestationType.Reviewed,
            "Test attestation",
            _clock.UtcNow.AddDays(-1)));  // Expired yesterday

        var attestedBundle = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation));

        var result = VerifyAttestationsHandler.Handle(
            new VerifyAttestationsQuery(attestedBundle, DateTimeOffset.UtcNow));

        Assert.False(result.AllValid);
        Assert.Equal(AttestationCheckResult.Reasons.Expired, result.Results[0].FailureReason);
    }

    [Fact]
    public async Task VerifyAttestations_MultipleAttestations_AllVerified()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var reviewer1 = await CreateResearcher("Dr. Reviewer1");
        var reviewer2 = await CreateResearcher("Dr. Reviewer2");

        var handler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);

        var attestation1 = await handler.HandleAsync(new CreateAttestationCommand(
            bundle,
            reviewer1.Id,
            AttestationType.Reviewed,
            "First review"));

        bundle = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation1));

        var attestation2 = await handler.HandleAsync(new CreateAttestationCommand(
            bundle,
            reviewer2.Id,
            AttestationType.Reproduced,
            "Successfully reproduced results"));

        bundle = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation2));

        var result = VerifyAttestationsHandler.Handle(
            new VerifyAttestationsQuery(bundle, DateTimeOffset.UtcNow));

        Assert.True(result.AllValid);
        Assert.Equal(2, result.Results.Count);
        Assert.All(result.Results, r => Assert.True(r.IsValid));
    }

    [Fact]
    public async Task ClaimCoreDigest_IndependentOfAttestations()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var attestor = await CreateResearcher("Dr. Reviewer");

        // Compute digest before attestation
        var digestBefore = ClaimCoreDigest.Compute(bundle);

        // Add attestation
        var handler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await handler.HandleAsync(new CreateAttestationCommand(
            bundle,
            attestor.Id,
            AttestationType.Reviewed,
            "Test attestation"));

        var attestedBundle = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation));

        // Compute digest after attestation
        var digestAfter = ClaimCoreDigest.Compute(attestedBundle);

        // Should be the same - attestations don't affect core digest
        Assert.Equal(digestBefore, digestAfter);
    }

    [Fact]
    public async Task Phase1Bundle_BackwardsCompatible()
    {
        // Create Phase 1 bundle (no attestations)
        var bundle = await CreateClaimBundle("Test claim");

        // Verify should work without attestations
        var result = VerifyAttestationsHandler.Handle(
            new VerifyAttestationsQuery(bundle, DateTimeOffset.UtcNow));

        Assert.True(result.AllValid);
        Assert.Empty(result.Results);
    }

    private async Task<ClaimBundle> CreateClaimBundle(string statement)
    {
        var researcher = await CreateResearcher("Dr. Author");
        var claimHandler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);
        var claim = await claimHandler.HandleAsync(new AssertClaimCommand(
            statement,
            researcher.Id,
            Array.Empty<EvidenceInput>()));

        var exportHandler = new ExportClaimBundleHandler(_claimRepo, _identityRepo);
        return await exportHandler.HandleAsync(new ExportClaimBundleCommand(claim.Id));
    }

    private async Task<(ClaimBundle, ClaimLedger.Domain.Attestations.Attestation)> CreateAttestedBundle()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var attestor = await CreateResearcher("Dr. Reviewer");

        var handler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await handler.HandleAsync(new CreateAttestationCommand(
            bundle,
            attestor.Id,
            AttestationType.Reviewed,
            "Reviewed and verified"));

        var attestedBundle = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation));

        return (attestedBundle, attestation);
    }

    private async Task<ResearcherIdentity> CreateResearcher(string name)
    {
        var handler = new CreateResearcherIdentityHandler(_keyVault, _identityRepo, _clock);
        return await handler.HandleAsync(new CreateResearcherIdentityCommand(name));
    }
}
