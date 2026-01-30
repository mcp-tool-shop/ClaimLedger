using ClaimLedger.Domain.Claims;
using ClaimLedger.Domain.Evidence;
using ClaimLedger.Domain.Primitives;
using Shared.Crypto;

namespace ClaimLedger.Tests.Domain;

public class ClaimAssertionTests
{
    [Fact]
    public void Constructor_EmptyStatement_Throws()
    {
        var keypair = Ed25519KeyPair.Generate();
        var signature = keypair.PrivateKey.Sign("test"u8);

        Assert.Throws<ArgumentException>(() => new ClaimAssertion(
            ClaimId.New(),
            "",
            ResearcherId.New(),
            keypair.PublicKey,
            DateTimeOffset.UtcNow,
            Array.Empty<EvidenceArtifact>(),
            signature));
    }

    [Fact]
    public void ToSignable_ReturnsCorrectVersion()
    {
        var claim = CreateValidClaim();

        var signable = claim.ToSignable();

        Assert.Equal("claim.v1", signable.Version);
    }

    [Fact]
    public void ToSignable_IncludesAllEvidence()
    {
        var keypair = Ed25519KeyPair.Generate();
        var claimId = ClaimId.New();
        var researcherId = ResearcherId.New();
        var evidence = new[]
        {
            EvidenceArtifact.Create("Dataset", ContentHash.Compute("data1"u8)),
            EvidenceArtifact.Create("Code", ContentHash.Compute("code1"u8)),
        };

        var signable = new ClaimSignable
        {
            ClaimId = claimId.ToString(),
            Statement = "Test claim",
            ResearcherId = researcherId.ToString(),
            ResearcherPublicKey = keypair.PublicKey.ToString(),
            Evidence = evidence.Select(e => new EvidenceSignable
            {
                Type = e.Type,
                Hash = e.Hash.ToString(),
                Locator = e.Locator
            }).ToList(),
            AssertedAtUtc = DateTimeOffset.UtcNow.ToString("O")
        };

        var bytes = CanonicalJson.SerializeToBytes(signable);
        var signature = keypair.PrivateKey.Sign(bytes);

        var claim = new ClaimAssertion(
            claimId,
            "Test claim",
            researcherId,
            keypair.PublicKey,
            DateTimeOffset.UtcNow,
            evidence,
            signature);

        var result = claim.ToSignable();

        Assert.Equal(2, result.Evidence.Count);
        Assert.Contains(result.Evidence, e => e.Type == "Dataset");
        Assert.Contains(result.Evidence, e => e.Type == "Code");
    }

    [Fact]
    public void VerifySignature_ValidSignature_ReturnsTrue()
    {
        var claim = CreateValidClaim();

        Assert.True(claim.VerifySignature());
    }

    [Fact]
    public void VerifySignature_TamperedStatement_ReturnsFalse()
    {
        // Create a valid claim
        var keypair = Ed25519KeyPair.Generate();
        var claimId = ClaimId.New();
        var researcherId = ResearcherId.New();
        var timestamp = DateTimeOffset.UtcNow;

        // Create signable with original statement
        var originalSignable = new ClaimSignable
        {
            ClaimId = claimId.ToString(),
            Statement = "Original claim",
            ResearcherId = researcherId.ToString(),
            ResearcherPublicKey = keypair.PublicKey.ToString(),
            Evidence = Array.Empty<EvidenceSignable>(),
            AssertedAtUtc = timestamp.ToString("O")
        };

        var bytes = CanonicalJson.SerializeToBytes(originalSignable);
        var signature = keypair.PrivateKey.Sign(bytes);

        // Create claim with DIFFERENT statement but same signature
        var tamperedClaim = new ClaimAssertion(
            claimId,
            "Tampered claim",  // Different statement!
            researcherId,
            keypair.PublicKey,
            timestamp,
            Array.Empty<EvidenceArtifact>(),
            signature);

        // Signature should fail
        Assert.False(tamperedClaim.VerifySignature());
    }

    private static ClaimAssertion CreateValidClaim()
    {
        var keypair = Ed25519KeyPair.Generate();
        var claimId = ClaimId.New();
        var researcherId = ResearcherId.New();
        var timestamp = DateTimeOffset.UtcNow;

        var signable = new ClaimSignable
        {
            ClaimId = claimId.ToString(),
            Statement = "Test scientific claim",
            ResearcherId = researcherId.ToString(),
            ResearcherPublicKey = keypair.PublicKey.ToString(),
            Evidence = Array.Empty<EvidenceSignable>(),
            AssertedAtUtc = timestamp.ToString("O")
        };

        var bytes = CanonicalJson.SerializeToBytes(signable);
        var signature = keypair.PrivateKey.Sign(bytes);

        return new ClaimAssertion(
            claimId,
            "Test scientific claim",
            researcherId,
            keypair.PublicKey,
            timestamp,
            Array.Empty<EvidenceArtifact>(),
            signature);
    }
}
