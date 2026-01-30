using ClaimLedger.Domain.Citations;
using ClaimLedger.Domain.Identity;
using ClaimLedger.Domain.Primitives;
using Shared.Crypto;

namespace ClaimLedger.Tests.Domain;

public class CitationTests
{
    [Fact]
    public void CitationRelation_AllTypesAreValid()
    {
        Assert.True(CitationRelation.IsValid(CitationRelation.Cites));
        Assert.True(CitationRelation.IsValid(CitationRelation.DependsOn));
        Assert.True(CitationRelation.IsValid(CitationRelation.Reproduces));
        Assert.True(CitationRelation.IsValid(CitationRelation.Disputes));
    }

    [Fact]
    public void CitationRelation_InvalidType_ReturnsFalse()
    {
        Assert.False(CitationRelation.IsValid("INVALID"));
        Assert.False(CitationRelation.IsValid("cites")); // Case sensitive
        Assert.False(CitationRelation.IsValid(""));
    }

    [Fact]
    public void Citation_Create_ProducesVerifiableSignature()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var signer = new ResearcherIdentity(
            ResearcherId.New(),
            keyPair.PublicKey,
            "Dr. Author",
            DateTimeOffset.UtcNow);

        var citedDigest = Digest256.Compute("test claim content"u8);

        var citation = Citation.Create(
            citedDigest,
            CitationRelation.Cites,
            "doi:10.1234/test",
            "Background prior work",
            signer,
            keyPair.PrivateKey,
            DateTimeOffset.UtcNow);

        Assert.True(citation.VerifySignature());
    }

    [Fact]
    public void Citation_Reconstitute_ValidSignature_Verifies()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var signer = new ResearcherIdentity(
            ResearcherId.New(),
            keyPair.PublicKey,
            "Dr. Author",
            DateTimeOffset.UtcNow);

        var citedDigest = Digest256.Compute("test claim content"u8);

        var original = Citation.Create(
            citedDigest,
            CitationRelation.DependsOn,
            null,
            "This claim depends on the cited claim",
            signer,
            keyPair.PrivateKey,
            DateTimeOffset.UtcNow);

        // Reconstitute from stored data
        var reconstituted = Citation.Reconstitute(
            original.Id,
            original.CitedClaimCoreDigest,
            original.Relation,
            original.Locator,
            original.Notes,
            original.IssuedAtUtc,
            original.SignerId,
            original.SignerPublicKey,
            original.Signature);

        Assert.True(reconstituted.VerifySignature());
    }

    [Fact]
    public void Citation_TamperedNotes_FailsVerification()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var signer = new ResearcherIdentity(
            ResearcherId.New(),
            keyPair.PublicKey,
            "Dr. Author",
            DateTimeOffset.UtcNow);

        var citedDigest = Digest256.Compute("test claim content"u8);

        var original = Citation.Create(
            citedDigest,
            CitationRelation.Cites,
            null,
            "Original notes",
            signer,
            keyPair.PrivateKey,
            DateTimeOffset.UtcNow);

        // Reconstitute with tampered notes
        var tampered = Citation.Reconstitute(
            original.Id,
            original.CitedClaimCoreDigest,
            original.Relation,
            original.Locator,
            "TAMPERED NOTES",  // Different!
            original.IssuedAtUtc,
            original.SignerId,
            original.SignerPublicKey,
            original.Signature);

        Assert.False(tampered.VerifySignature());
    }

    [Fact]
    public void Citation_TamperedRelation_FailsVerification()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var signer = new ResearcherIdentity(
            ResearcherId.New(),
            keyPair.PublicKey,
            "Dr. Author",
            DateTimeOffset.UtcNow);

        var citedDigest = Digest256.Compute("test claim content"u8);

        var original = Citation.Create(
            citedDigest,
            CitationRelation.Cites,
            null,
            null,
            signer,
            keyPair.PrivateKey,
            DateTimeOffset.UtcNow);

        // Reconstitute with tampered relation
        var tampered = Citation.Reconstitute(
            original.Id,
            original.CitedClaimCoreDigest,
            CitationRelation.Disputes,  // Different!
            original.Locator,
            original.Notes,
            original.IssuedAtUtc,
            original.SignerId,
            original.SignerPublicKey,
            original.Signature);

        Assert.False(tampered.VerifySignature());
    }

    [Fact]
    public void Citation_TamperedDigest_FailsVerification()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var signer = new ResearcherIdentity(
            ResearcherId.New(),
            keyPair.PublicKey,
            "Dr. Author",
            DateTimeOffset.UtcNow);

        var citedDigest = Digest256.Compute("test claim content"u8);
        var wrongDigest = Digest256.Compute("different content"u8);

        var original = Citation.Create(
            citedDigest,
            CitationRelation.Cites,
            null,
            null,
            signer,
            keyPair.PrivateKey,
            DateTimeOffset.UtcNow);

        // Reconstitute with wrong digest
        var tampered = Citation.Reconstitute(
            original.Id,
            wrongDigest,  // Different!
            original.Relation,
            original.Locator,
            original.Notes,
            original.IssuedAtUtc,
            original.SignerId,
            original.SignerPublicKey,
            original.Signature);

        Assert.False(tampered.VerifySignature());
    }

    [Fact]
    public void Citation_InvalidRelation_Throws()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var signer = new ResearcherIdentity(
            ResearcherId.New(),
            keyPair.PublicKey,
            "Dr. Author",
            DateTimeOffset.UtcNow);

        var citedDigest = Digest256.Compute("test claim content"u8);

        Assert.Throws<ArgumentException>(() => Citation.Create(
            citedDigest,
            "INVALID_RELATION",
            null,
            null,
            signer,
            keyPair.PrivateKey,
            DateTimeOffset.UtcNow));
    }

    [Fact]
    public void CitationId_New_GeneratesUniqueIds()
    {
        var id1 = CitationId.New();
        var id2 = CitationId.New();

        Assert.NotEqual(id1, id2);
    }

    [Fact]
    public void CitationId_Parse_RoundTrips()
    {
        var original = CitationId.New();
        var parsed = CitationId.Parse(original.ToString());

        Assert.Equal(original, parsed);
    }
}
