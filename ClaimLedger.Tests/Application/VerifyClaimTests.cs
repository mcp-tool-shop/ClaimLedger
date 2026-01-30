using ClaimLedger.Application.Claims;
using ClaimLedger.Application.Identity;
using ClaimLedger.Application.Verification;
using ClaimLedger.Domain.Claims;
using ClaimLedger.Domain.Evidence;
using ClaimLedger.Domain.Identity;
using ClaimLedger.Domain.Primitives;
using ClaimLedger.Tests.Fakes;
using Shared.Crypto;

namespace ClaimLedger.Tests.Application;

public class VerifyClaimTests
{
    private readonly InMemoryKeyVault _keyVault = new();
    private readonly InMemoryResearcherIdentityRepository _identityRepo = new();
    private readonly InMemoryClaimRepository _claimRepo = new();
    private readonly FakeClock _clock = new();

    [Fact]
    public async Task Verify_ValidClaim_ReturnsValid()
    {
        var claim = await CreateValidClaim("Test claim");

        var result = VerifyClaimHandler.Handle(new VerifyClaimQuery(claim));

        Assert.True(result.IsValid);
        Assert.Null(result.FailureReason);
    }

    [Fact]
    public async Task Verify_TamperedStatement_ReturnsInvalid()
    {
        // Create valid claim
        var researcher = await CreateResearcher("Dr. Smith");
        var handler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);
        var originalClaim = await handler.HandleAsync(new AssertClaimCommand(
            "Original statement",
            researcher.Id,
            Array.Empty<EvidenceInput>()));

        // Create tampered claim with different statement but same signature
        var tamperedClaim = new ClaimAssertion(
            originalClaim.Id,
            "Tampered statement",  // Different!
            originalClaim.ResearcherId,
            originalClaim.ResearcherPublicKey,
            originalClaim.AssertedAtUtc,
            originalClaim.Evidence,
            originalClaim.Signature);

        var result = VerifyClaimHandler.Handle(new VerifyClaimQuery(tamperedClaim));

        Assert.False(result.IsValid);
        Assert.Equal(VerificationResult.Reasons.SignatureInvalid, result.FailureReason);
    }

    [Fact]
    public async Task Verify_TamperedEvidence_ReturnsInvalid()
    {
        // Create valid claim with evidence
        var researcher = await CreateResearcher("Dr. Smith");
        var handler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);
        var originalClaim = await handler.HandleAsync(new AssertClaimCommand(
            "Test claim",
            researcher.Id,
            new[] { new EvidenceInput("Dataset", ContentHash.Compute("original data"u8)) }));

        // Create tampered claim with different evidence hash
        var tamperedEvidence = new[]
        {
            EvidenceArtifact.Create("Dataset", ContentHash.Compute("tampered data"u8))
        };

        var tamperedClaim = new ClaimAssertion(
            originalClaim.Id,
            originalClaim.Statement,
            originalClaim.ResearcherId,
            originalClaim.ResearcherPublicKey,
            originalClaim.AssertedAtUtc,
            tamperedEvidence,  // Different!
            originalClaim.Signature);

        var result = VerifyClaimHandler.Handle(new VerifyClaimQuery(tamperedClaim));

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Verify_ClaimWithNoEvidence_ReturnsValidWithWarning()
    {
        var claim = await CreateValidClaim("Test claim");

        var result = VerifyClaimHandler.Handle(new VerifyClaimQuery(claim));

        Assert.True(result.IsValid);
        Assert.Contains("no evidence", result.Warnings.First(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Verify_WrongPublicKey_ReturnsInvalid()
    {
        // Create valid claim
        var researcher = await CreateResearcher("Dr. Smith");
        var handler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);
        var originalClaim = await handler.HandleAsync(new AssertClaimCommand(
            "Test claim",
            researcher.Id,
            Array.Empty<EvidenceInput>()));

        // Create claim with different public key
        var differentKeypair = Ed25519KeyPair.Generate();
        var tamperedClaim = new ClaimAssertion(
            originalClaim.Id,
            originalClaim.Statement,
            originalClaim.ResearcherId,
            differentKeypair.PublicKey,  // Different key!
            originalClaim.AssertedAtUtc,
            originalClaim.Evidence,
            originalClaim.Signature);

        var result = VerifyClaimHandler.Handle(new VerifyClaimQuery(tamperedClaim));

        Assert.False(result.IsValid);
    }

    private async Task<ClaimAssertion> CreateValidClaim(string statement)
    {
        var researcher = await CreateResearcher("Dr. Smith");
        var handler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);
        return await handler.HandleAsync(new AssertClaimCommand(
            statement,
            researcher.Id,
            Array.Empty<EvidenceInput>()));
    }

    private async Task<ResearcherIdentity> CreateResearcher(string name)
    {
        var handler = new CreateResearcherIdentityHandler(_keyVault, _identityRepo, _clock);
        return await handler.HandleAsync(new CreateResearcherIdentityCommand(name));
    }
}
