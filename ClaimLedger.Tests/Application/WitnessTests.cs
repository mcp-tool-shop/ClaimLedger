using System.Globalization;
using ClaimLedger.Application.Attestations;
using ClaimLedger.Application.Claims;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Identity;
using ClaimLedger.Application.Revocations;
using ClaimLedger.Domain.Attestations;
using ClaimLedger.Domain.Primitives;
using ClaimLedger.Domain.Revocations;
using ClaimLedger.Tests.Fakes;
using Shared.Crypto;

namespace ClaimLedger.Tests.Application;

public class WitnessTests
{
    private readonly InMemoryKeyVault _keyVault = new();
    private readonly InMemoryResearcherIdentityRepository _identityRepo = new();
    private readonly InMemoryClaimRepository _claimRepo = new();
    private readonly FakeClock _clock = new();

    [Fact]
    public async Task WitnessAttestation_CreatesValidSignature()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var (witness, witnessKeyPair) = await CreateResearcherWithKeys("Witness Service");

        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle,
            witness.Id,
            AttestationType.WitnessedAt,
            "Witnessed claim existence"));

        Assert.True(attestation.VerifySignature());
        Assert.Equal(AttestationType.WitnessedAt, attestation.Type);
    }

    [Fact]
    public async Task WitnessAttestation_BindsToClaimCoreDigest()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var expectedDigest = ClaimCoreDigest.Compute(bundle);
        var (witness, _) = await CreateResearcherWithKeys("Witness Service");

        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle,
            witness.Id,
            AttestationType.WitnessedAt,
            "Witnessed claim existence"));

        Assert.Equal(expectedDigest, attestation.ClaimCoreDigest);
    }

    [Fact]
    public async Task WitnessAttestation_HasIssuedAt()
    {
        var witnessTime = DateTimeOffset.Parse("2024-06-15T12:00:00Z", CultureInfo.InvariantCulture);
        _clock.UtcNow = witnessTime;

        var bundle = await CreateClaimBundle("Test claim");
        var (witness, _) = await CreateResearcherWithKeys("Witness Service");

        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle,
            witness.Id,
            AttestationType.WitnessedAt,
            "Witnessed claim existence"));

        Assert.Equal(witnessTime, attestation.IssuedAtUtc);
    }

    [Fact]
    public async Task WitnessAttestation_TamperedIssuedAt_FailsVerification()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var (witness, _) = await CreateResearcherWithKeys("Witness Service");

        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle,
            witness.Id,
            AttestationType.WitnessedAt,
            "Witnessed claim existence"));

        var attestedBundle = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation));

        // Tamper with issued_at
        var tamperedAttestation = new AttestationInfo
        {
            AttestationId = attestedBundle.Attestations![0].AttestationId,
            ClaimCoreDigest = attestedBundle.Attestations[0].ClaimCoreDigest,
            Attestor = attestedBundle.Attestations[0].Attestor,
            AttestationType = attestedBundle.Attestations[0].AttestationType,
            Statement = attestedBundle.Attestations[0].Statement,
            IssuedAtUtc = DateTimeOffset.UtcNow.AddDays(1).ToString("O"), // Tampered!
            Signature = attestedBundle.Attestations[0].Signature
        };

        var tamperedBundle = new ClaimBundle
        {
            Version = attestedBundle.Version,
            Algorithms = attestedBundle.Algorithms,
            Claim = attestedBundle.Claim,
            Researcher = attestedBundle.Researcher,
            Citations = attestedBundle.Citations,
            Attestations = new[] { tamperedAttestation }
        };

        var result = VerifyAttestationsHandler.Handle(
            new VerifyAttestationsQuery(tamperedBundle, DateTimeOffset.UtcNow));

        Assert.False(result.AllValid);
        Assert.Equal(AttestationCheckResult.Reasons.SignatureInvalid, result.Results[0].FailureReason);
    }

    [Fact]
    public async Task WitnessAttestation_TamperedDigest_FailsVerification()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var (witness, _) = await CreateResearcherWithKeys("Witness Service");

        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle,
            witness.Id,
            AttestationType.WitnessedAt,
            "Witnessed claim existence"));

        var attestedBundle = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation));

        // Tamper with claim_core_digest
        var wrongDigest = Digest256.Compute("wrong content"u8);
        var tamperedAttestation = new AttestationInfo
        {
            AttestationId = attestedBundle.Attestations![0].AttestationId,
            ClaimCoreDigest = wrongDigest.ToString(), // Tampered!
            Attestor = attestedBundle.Attestations[0].Attestor,
            AttestationType = attestedBundle.Attestations[0].AttestationType,
            Statement = attestedBundle.Attestations[0].Statement,
            IssuedAtUtc = attestedBundle.Attestations[0].IssuedAtUtc,
            Signature = attestedBundle.Attestations[0].Signature
        };

        var tamperedBundle = new ClaimBundle
        {
            Version = attestedBundle.Version,
            Algorithms = attestedBundle.Algorithms,
            Claim = attestedBundle.Claim,
            Researcher = attestedBundle.Researcher,
            Citations = attestedBundle.Citations,
            Attestations = new[] { tamperedAttestation }
        };

        var result = VerifyAttestationsHandler.Handle(
            new VerifyAttestationsQuery(tamperedBundle, DateTimeOffset.UtcNow));

        Assert.False(result.AllValid);
    }

    [Fact]
    public async Task WitnessAttestation_MultipleWitnesses_AllVerify()
    {
        var bundle = await CreateClaimBundle("Test claim");

        // Create multiple witness attestations
        var (witness1, _) = await CreateResearcherWithKeys("Witness 1");
        var (witness2, _) = await CreateResearcherWithKeys("Witness 2");
        var (witness3, _) = await CreateResearcherWithKeys("Witness 3");

        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);

        _clock.UtcNow = DateTimeOffset.Parse("2024-06-01T10:00:00Z", CultureInfo.InvariantCulture);
        var attest1 = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, witness1.Id, AttestationType.WitnessedAt, "Witnessed"));
        bundle = AddAttestationToBundleHandler.Handle(new AddAttestationToBundleCommand(bundle, attest1));

        _clock.UtcNow = DateTimeOffset.Parse("2024-06-01T11:00:00Z", CultureInfo.InvariantCulture);
        var attest2 = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, witness2.Id, AttestationType.WitnessedAt, "Witnessed"));
        bundle = AddAttestationToBundleHandler.Handle(new AddAttestationToBundleCommand(bundle, attest2));

        _clock.UtcNow = DateTimeOffset.Parse("2024-06-01T12:00:00Z", CultureInfo.InvariantCulture);
        var attest3 = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, witness3.Id, AttestationType.WitnessedAt, "Witnessed"));
        bundle = AddAttestationToBundleHandler.Handle(new AddAttestationToBundleCommand(bundle, attest3));

        var result = VerifyAttestationsHandler.Handle(
            new VerifyAttestationsQuery(bundle, DateTimeOffset.UtcNow));

        Assert.True(result.AllValid);
        Assert.Equal(3, result.Results.Count);
        Assert.All(result.Results, r => Assert.True(r.IsValid));
    }

    [Fact]
    public async Task WitnessAttestation_WitnessKeyRevoked_ReturnsRevoked()
    {
        // Create claim
        _clock.UtcNow = DateTimeOffset.Parse("2024-06-01T12:00:00Z", CultureInfo.InvariantCulture);
        var bundle = await CreateClaimBundle("Test claim");

        // Create witness attestation
        _clock.UtcNow = DateTimeOffset.Parse("2024-06-02T12:00:00Z", CultureInfo.InvariantCulture);
        var (witness, witnessKeyPair) = await CreateResearcherWithKeys("Witness Service");

        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, witness.Id, AttestationType.WitnessedAt, "Witnessed"));
        bundle = AddAttestationToBundleHandler.Handle(new AddAttestationToBundleCommand(bundle, attestation));

        // Revoke witness key BEFORE the attestation
        var revocation = Revocation.CreateSelfSigned(
            witness.Id,
            witnessKeyPair.PublicKey,
            witnessKeyPair.PrivateKey,
            DateTimeOffset.Parse("2024-06-01T18:00:00Z", CultureInfo.InvariantCulture),
            RevocationReason.Compromised);

        var registry = new RevocationRegistry();
        registry.Add(revocation);

        var result = VerifyAgainstRevocationsHandler.Handle(
            new VerifyAgainstRevocationsQuery(bundle, registry, StrictMode: true));

        // Should fail with REVOKED (exit code 6), not BROKEN (exit code 3)
        Assert.False(result.IsValid);

        var attestationCheck = result.Checks.First(c => c.SignatureType == "Attestation");
        Assert.True(attestationCheck.IsRevoked);
        Assert.Equal(RevocationReason.Compromised, attestationCheck.RevocationReason);
    }

    [Fact]
    public async Task WitnessAttestation_WitnessKeyRevokedExactlyAtIssuedAt_ReturnsRevoked()
    {
        // Boundary case: revoked_at == issued_at
        var exactTime = DateTimeOffset.Parse("2024-06-15T12:00:00Z", CultureInfo.InvariantCulture);

        _clock.UtcNow = DateTimeOffset.Parse("2024-06-01T12:00:00Z", CultureInfo.InvariantCulture);
        var bundle = await CreateClaimBundle("Test claim");

        _clock.UtcNow = exactTime;
        var (witness, witnessKeyPair) = await CreateResearcherWithKeys("Witness Service");

        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, witness.Id, AttestationType.WitnessedAt, "Witnessed"));
        bundle = AddAttestationToBundleHandler.Handle(new AddAttestationToBundleCommand(bundle, attestation));

        var revocation = Revocation.CreateSelfSigned(
            witness.Id,
            witnessKeyPair.PublicKey,
            witnessKeyPair.PrivateKey,
            exactTime, // Same time as attestation
            RevocationReason.Compromised);

        var registry = new RevocationRegistry();
        registry.Add(revocation);

        var result = VerifyAgainstRevocationsHandler.Handle(
            new VerifyAgainstRevocationsQuery(bundle, registry, StrictMode: true));

        // Boundary: revoked_at <= signed_at = invalid
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task WitnessAttestation_WitnessKeyRevokedAfterIssuedAt_Passes()
    {
        _clock.UtcNow = DateTimeOffset.Parse("2024-06-01T12:00:00Z", CultureInfo.InvariantCulture);
        var bundle = await CreateClaimBundle("Test claim");

        // Witness at T
        _clock.UtcNow = DateTimeOffset.Parse("2024-06-15T12:00:00Z", CultureInfo.InvariantCulture);
        var (witness, witnessKeyPair) = await CreateResearcherWithKeys("Witness Service");

        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, witness.Id, AttestationType.WitnessedAt, "Witnessed"));
        bundle = AddAttestationToBundleHandler.Handle(new AddAttestationToBundleCommand(bundle, attestation));

        // Revoke witness key at T+1 day (after attestation)
        var revocation = Revocation.CreateSelfSigned(
            witness.Id,
            witnessKeyPair.PublicKey,
            witnessKeyPair.PrivateKey,
            DateTimeOffset.Parse("2024-06-16T12:00:00Z", CultureInfo.InvariantCulture),
            RevocationReason.Rotated);

        var registry = new RevocationRegistry();
        registry.Add(revocation);

        var result = VerifyAgainstRevocationsHandler.Handle(
            new VerifyAgainstRevocationsQuery(bundle, registry, StrictMode: true));

        // Should pass - witness was not revoked at time of witnessing
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task WitnessAttestation_DoesNotAlterClaimCoreDigest()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var digestBefore = ClaimCoreDigest.Compute(bundle);

        var (witness, _) = await CreateResearcherWithKeys("Witness Service");

        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, witness.Id, AttestationType.WitnessedAt, "Witnessed"));
        bundle = AddAttestationToBundleHandler.Handle(new AddAttestationToBundleCommand(bundle, attestation));

        var digestAfter = ClaimCoreDigest.Compute(bundle);

        // Attestations are excluded from claim_core_digest
        Assert.Equal(digestBefore, digestAfter);
    }

    [Fact]
    public async Task Phase4Bundle_BackwardsCompatible_WithWitnessedAt()
    {
        // Phase 4 bundle (claim + citation + revocation-checked)
        var bundle = await CreateClaimBundle("Test claim");

        // Add a regular attestation
        var (reviewer, _) = await CreateResearcherWithKeys("Dr. Reviewer");
        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var reviewAttestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, reviewer.Id, AttestationType.Reviewed, "Reviewed"));
        bundle = AddAttestationToBundleHandler.Handle(new AddAttestationToBundleCommand(bundle, reviewAttestation));

        // Now add a witness attestation
        var (witness, _) = await CreateResearcherWithKeys("Witness Service");
        var witnessAttestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, witness.Id, AttestationType.WitnessedAt, "Witnessed"));
        bundle = AddAttestationToBundleHandler.Handle(new AddAttestationToBundleCommand(bundle, witnessAttestation));

        // Both should verify
        var result = VerifyAttestationsHandler.Handle(
            new VerifyAttestationsQuery(bundle, DateTimeOffset.UtcNow));

        Assert.True(result.AllValid);
        Assert.Equal(2, result.Results.Count);
    }

    [Fact]
    public async Task ExistingAttestationTypes_StillWork()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var (attestor, _) = await CreateResearcherWithKeys("Dr. Attestor");

        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);

        // Test each existing type still works
        var reviewed = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, attestor.Id, AttestationType.Reviewed, "Reviewed"));
        Assert.True(reviewed.VerifySignature());

        var reproduced = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, attestor.Id, AttestationType.Reproduced, "Reproduced"));
        Assert.True(reproduced.VerifySignature());

        var approved = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, attestor.Id, AttestationType.InstitutionApproved, "Approved"));
        Assert.True(approved.VerifySignature());

        var dataAvail = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle, attestor.Id, AttestationType.DataAvailabilityConfirmed, "Data available"));
        Assert.True(dataAvail.VerifySignature());
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
