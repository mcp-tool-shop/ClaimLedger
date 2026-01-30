using System.Text.Json;
using ClaimLedger.Application.Claims;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Identity;
using ClaimLedger.Cli.Verification;
using ClaimLedger.Domain.Identity;
using ClaimLedger.Tests.Fakes;
using Shared.Crypto;

namespace ClaimLedger.Tests.Cli;

public class BundleVerifierTests
{
    private readonly InMemoryKeyVault _keyVault = new();
    private readonly InMemoryResearcherIdentityRepository _identityRepo = new();
    private readonly InMemoryClaimRepository _claimRepo = new();
    private readonly FakeClock _clock = new();

    [Fact]
    public async Task Verify_ValidBundle_ReturnsValid()
    {
        var bundle = await CreateValidBundle("Test scientific claim");
        var json = JsonSerializer.Serialize(bundle);

        var result = BundleVerifier.Verify(json);

        Assert.Equal(VerificationStatus.Valid, result.Status);
        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public async Task Verify_TamperedStatement_ReturnsBroken()
    {
        var bundle = await CreateValidBundle("Original claim");

        // Tamper with statement
        var tamperedBundle = new ClaimBundle
        {
            Version = bundle.Version,
            Algorithms = bundle.Algorithms,
            Claim = new ClaimInfo
            {
                ClaimId = bundle.Claim.ClaimId,
                Statement = "Tampered claim",  // Different!
                AssertedAtUtc = bundle.Claim.AssertedAtUtc,
                Evidence = bundle.Claim.Evidence,
                Signature = bundle.Claim.Signature
            },
            Researcher = bundle.Researcher
        };

        var json = JsonSerializer.Serialize(tamperedBundle);
        var result = BundleVerifier.Verify(json);

        Assert.Equal(VerificationStatus.Broken, result.Status);
        Assert.Equal(3, result.ExitCode);
    }

    [Fact]
    public async Task Verify_TamperedSignature_ReturnsBroken()
    {
        var bundle = await CreateValidBundle("Test claim");

        // Tamper with signature (flip a bit)
        var sigBytes = Convert.FromBase64String(bundle.Claim.Signature);
        sigBytes[0] ^= 0xFF;
        var tamperedSignature = Convert.ToBase64String(sigBytes);

        var tamperedBundle = new ClaimBundle
        {
            Version = bundle.Version,
            Algorithms = bundle.Algorithms,
            Claim = new ClaimInfo
            {
                ClaimId = bundle.Claim.ClaimId,
                Statement = bundle.Claim.Statement,
                AssertedAtUtc = bundle.Claim.AssertedAtUtc,
                Evidence = bundle.Claim.Evidence,
                Signature = tamperedSignature  // Corrupted!
            },
            Researcher = bundle.Researcher
        };

        var json = JsonSerializer.Serialize(tamperedBundle);
        var result = BundleVerifier.Verify(json);

        Assert.Equal(VerificationStatus.Broken, result.Status);
    }

    [Fact]
    public void Verify_InvalidJson_ReturnsInvalidInput()
    {
        var result = BundleVerifier.Verify("not json at all");

        Assert.Equal(VerificationStatus.InvalidInput, result.Status);
        Assert.Equal(4, result.ExitCode);
    }

    [Fact]
    public void Verify_WrongVersion_ReturnsInvalidInput()
    {
        var json = """{"Version": "claim-bundle.v99", "Algorithms": {}, "Claim": {}, "Researcher": {}}""";

        var result = BundleVerifier.Verify(json);

        Assert.Equal(VerificationStatus.InvalidInput, result.Status);
    }

    [Fact]
    public async Task Verify_WrongPublicKey_ReturnsBroken()
    {
        var bundle = await CreateValidBundle("Test claim");

        // Replace with different public key
        var differentKey = Ed25519KeyPair.Generate().PublicKey;
        var tamperedBundle = new ClaimBundle
        {
            Version = bundle.Version,
            Algorithms = bundle.Algorithms,
            Claim = bundle.Claim,
            Researcher = new ResearcherInfo
            {
                ResearcherId = bundle.Researcher.ResearcherId,
                PublicKey = differentKey.ToString(),  // Wrong key!
                DisplayName = bundle.Researcher.DisplayName
            }
        };

        var json = JsonSerializer.Serialize(tamperedBundle);
        var result = BundleVerifier.Verify(json);

        Assert.Equal(VerificationStatus.Broken, result.Status);
    }

    [Fact]
    public async Task Verify_BundleWithEvidence_VerifiesSignature()
    {
        var researcher = await CreateResearcher("Dr. Smith");
        var claimHandler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);

        var evidence = new[]
        {
            new EvidenceInput("Dataset", ContentHash.Compute("dataset content"u8), "https://example.com/data.csv"),
            new EvidenceInput("Code", ContentHash.Compute("source code"u8))
        };

        var claim = await claimHandler.HandleAsync(new AssertClaimCommand(
            "Model trained on this dataset",
            researcher.Id,
            evidence));

        var exportHandler = new ExportClaimBundleHandler(_claimRepo, _identityRepo);
        var bundle = await exportHandler.HandleAsync(new ExportClaimBundleCommand(claim.Id));

        var json = JsonSerializer.Serialize(bundle);
        var result = BundleVerifier.Verify(json);

        Assert.Equal(VerificationStatus.Valid, result.Status);
        Assert.Equal(2, result.Bundle!.Claim.Evidence.Count);
    }

    private async Task<ClaimBundle> CreateValidBundle(string statement)
    {
        var researcher = await CreateResearcher("Dr. Smith");
        var claimHandler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);
        var claim = await claimHandler.HandleAsync(new AssertClaimCommand(
            statement,
            researcher.Id,
            Array.Empty<EvidenceInput>()));

        var exportHandler = new ExportClaimBundleHandler(_claimRepo, _identityRepo);
        return await exportHandler.HandleAsync(new ExportClaimBundleCommand(claim.Id));
    }

    private async Task<ResearcherIdentity> CreateResearcher(string name)
    {
        var handler = new CreateResearcherIdentityHandler(_keyVault, _identityRepo, _clock);
        return await handler.HandleAsync(new CreateResearcherIdentityCommand(name));
    }
}
