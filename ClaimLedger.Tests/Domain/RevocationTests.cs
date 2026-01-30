using System.Globalization;
using ClaimLedger.Domain.Primitives;
using ClaimLedger.Domain.Revocations;
using Shared.Crypto;

namespace ClaimLedger.Tests.Domain;

public class RevocationTests
{
    [Fact]
    public void RevocationReason_AllTypesAreValid()
    {
        Assert.True(RevocationReason.IsValid(RevocationReason.Compromised));
        Assert.True(RevocationReason.IsValid(RevocationReason.Rotated));
        Assert.True(RevocationReason.IsValid(RevocationReason.Retired));
        Assert.True(RevocationReason.IsValid(RevocationReason.Other));
    }

    [Fact]
    public void RevocationReason_InvalidType_ReturnsFalse()
    {
        Assert.False(RevocationReason.IsValid("INVALID"));
        Assert.False(RevocationReason.IsValid("compromised")); // Case sensitive
        Assert.False(RevocationReason.IsValid(""));
    }

    [Fact]
    public void IssuerMode_AllTypesAreValid()
    {
        Assert.True(IssuerMode.IsValid(IssuerMode.Self));
        Assert.True(IssuerMode.IsValid(IssuerMode.Successor));
    }

    [Fact]
    public void IssuerMode_InvalidType_ReturnsFalse()
    {
        Assert.False(IssuerMode.IsValid("INVALID"));
        Assert.False(IssuerMode.IsValid("self")); // Case sensitive
        Assert.False(IssuerMode.IsValid(""));
    }

    [Fact]
    public void Revocation_CreateSelfSigned_ProducesVerifiableSignature()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();

        var revocation = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            DateTimeOffset.UtcNow,
            RevocationReason.Rotated,
            notes: "Test revocation");

        Assert.True(revocation.VerifySignature());
        Assert.Equal(IssuerMode.Self, revocation.IssuerMode);
        Assert.Equal(keyPair.PublicKey, revocation.SignerPublicKey);
    }

    [Fact]
    public void Revocation_CreateSelfSigned_WithSuccessor_Verifies()
    {
        var oldKeyPair = Ed25519KeyPair.Generate();
        var newKeyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();

        var revocation = Revocation.CreateSelfSigned(
            researcherId,
            oldKeyPair.PublicKey,
            oldKeyPair.PrivateKey,
            DateTimeOffset.UtcNow,
            RevocationReason.Rotated,
            successorPublicKey: newKeyPair.PublicKey,
            notes: "Rotating to new key");

        Assert.True(revocation.VerifySignature());
        Assert.Equal(IssuerMode.Self, revocation.IssuerMode);
        Assert.Equal(newKeyPair.PublicKey, revocation.SuccessorPublicKey);
    }

    [Fact]
    public void Revocation_CreateSuccessorSigned_ProducesVerifiableSignature()
    {
        var oldKeyPair = Ed25519KeyPair.Generate();
        var newKeyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();

        var revocation = Revocation.CreateSuccessorSigned(
            researcherId,
            oldKeyPair.PublicKey,
            newKeyPair.PublicKey,
            newKeyPair.PrivateKey,
            DateTimeOffset.UtcNow,
            RevocationReason.Compromised,
            notes: "Key was compromised");

        Assert.True(revocation.VerifySignature());
        Assert.Equal(IssuerMode.Successor, revocation.IssuerMode);
        Assert.Equal(newKeyPair.PublicKey, revocation.SignerPublicKey);
        Assert.Equal(newKeyPair.PublicKey, revocation.SuccessorPublicKey);
    }

    [Fact]
    public void Revocation_Reconstitute_SelfSigned_Verifies()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();

        var original = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            DateTimeOffset.UtcNow,
            RevocationReason.Retired);

        var reconstituted = Revocation.Reconstitute(
            original.Id,
            original.ResearcherId,
            original.RevokedPublicKey,
            original.RevokedAtUtc,
            original.Reason,
            original.IssuerMode,
            original.SuccessorPublicKey,
            original.Notes,
            original.Signature);

        Assert.True(reconstituted.VerifySignature());
    }

    [Fact]
    public void Revocation_Reconstitute_SuccessorSigned_Verifies()
    {
        var oldKeyPair = Ed25519KeyPair.Generate();
        var newKeyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();

        var original = Revocation.CreateSuccessorSigned(
            researcherId,
            oldKeyPair.PublicKey,
            newKeyPair.PublicKey,
            newKeyPair.PrivateKey,
            DateTimeOffset.UtcNow,
            RevocationReason.Compromised);

        var reconstituted = Revocation.Reconstitute(
            original.Id,
            original.ResearcherId,
            original.RevokedPublicKey,
            original.RevokedAtUtc,
            original.Reason,
            original.IssuerMode,
            original.SuccessorPublicKey,
            original.Notes,
            original.Signature);

        Assert.True(reconstituted.VerifySignature());
    }

    [Fact]
    public void Revocation_TamperedReason_FailsVerification()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();

        var original = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            DateTimeOffset.UtcNow,
            RevocationReason.Rotated);

        var tampered = Revocation.Reconstitute(
            original.Id,
            original.ResearcherId,
            original.RevokedPublicKey,
            original.RevokedAtUtc,
            RevocationReason.Compromised, // Different!
            original.IssuerMode,
            original.SuccessorPublicKey,
            original.Notes,
            original.Signature);

        Assert.False(tampered.VerifySignature());
    }

    [Fact]
    public void Revocation_TamperedRevokedAt_FailsVerification()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();
        var originalTime = DateTimeOffset.UtcNow;

        var original = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            originalTime,
            RevocationReason.Retired);

        var tampered = Revocation.Reconstitute(
            original.Id,
            original.ResearcherId,
            original.RevokedPublicKey,
            originalTime.AddDays(-1), // Different!
            original.Reason,
            original.IssuerMode,
            original.SuccessorPublicKey,
            original.Notes,
            original.Signature);

        Assert.False(tampered.VerifySignature());
    }

    [Fact]
    public void Revocation_TamperedSuccessor_FailsVerification()
    {
        var oldKeyPair = Ed25519KeyPair.Generate();
        var newKeyPair = Ed25519KeyPair.Generate();
        var wrongKeyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();

        var original = Revocation.CreateSelfSigned(
            researcherId,
            oldKeyPair.PublicKey,
            oldKeyPair.PrivateKey,
            DateTimeOffset.UtcNow,
            RevocationReason.Rotated,
            successorPublicKey: newKeyPair.PublicKey);

        var tampered = Revocation.Reconstitute(
            original.Id,
            original.ResearcherId,
            original.RevokedPublicKey,
            original.RevokedAtUtc,
            original.Reason,
            original.IssuerMode,
            wrongKeyPair.PublicKey, // Different!
            original.Notes,
            original.Signature);

        Assert.False(tampered.VerifySignature());
    }

    [Fact]
    public void Revocation_TamperedNotes_FailsVerification()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();

        var original = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            DateTimeOffset.UtcNow,
            RevocationReason.Retired,
            notes: "Original notes");

        var tampered = Revocation.Reconstitute(
            original.Id,
            original.ResearcherId,
            original.RevokedPublicKey,
            original.RevokedAtUtc,
            original.Reason,
            original.IssuerMode,
            original.SuccessorPublicKey,
            "Tampered notes", // Different!
            original.Signature);

        Assert.False(tampered.VerifySignature());
    }

    [Fact]
    public void Revocation_InvalidReason_Throws()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();

        Assert.Throws<ArgumentException>(() => Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            DateTimeOffset.UtcNow,
            "INVALID_REASON"));
    }

    [Fact]
    public void Revocation_Reconstitute_SuccessorSigned_WithoutSuccessorKey_Throws()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();

        Assert.Throws<ArgumentException>(() => Revocation.Reconstitute(
            RevocationId.New(),
            researcherId,
            keyPair.PublicKey,
            DateTimeOffset.UtcNow,
            RevocationReason.Compromised,
            IssuerMode.Successor,
            null, // Missing successor key!
            null,
            Ed25519Signature.Parse(Convert.ToBase64String(new byte[64]))));
    }

    [Fact]
    public void Revocation_Invalidates_SignatureAtOrAfterRevocationTime()
    {
        var keyPair = Ed25519KeyPair.Generate();
        var researcherId = ResearcherId.New();
        var revokedAt = DateTimeOffset.Parse("2024-06-15T12:00:00Z", CultureInfo.InvariantCulture);

        var revocation = Revocation.CreateSelfSigned(
            researcherId,
            keyPair.PublicKey,
            keyPair.PrivateKey,
            revokedAt,
            RevocationReason.Compromised);

        // Signature BEFORE revocation: valid
        Assert.False(revocation.Invalidates(revokedAt.AddMinutes(-1)));
        Assert.False(revocation.Invalidates(revokedAt.AddDays(-1)));

        // Signature AT revocation time: invalid (boundary case)
        Assert.True(revocation.Invalidates(revokedAt));

        // Signature AFTER revocation: invalid
        Assert.True(revocation.Invalidates(revokedAt.AddMinutes(1)));
        Assert.True(revocation.Invalidates(revokedAt.AddDays(1)));
    }

    [Fact]
    public void RevocationId_New_GeneratesUniqueIds()
    {
        var id1 = RevocationId.New();
        var id2 = RevocationId.New();

        Assert.NotEqual(id1, id2);
    }

    [Fact]
    public void RevocationId_Parse_RoundTrips()
    {
        var original = RevocationId.New();
        var parsed = RevocationId.Parse(original.ToString());

        Assert.Equal(original, parsed);
    }

    [Fact]
    public void RevocationId_Empty_Throws()
    {
        Assert.Throws<ArgumentException>(() => new RevocationId(Guid.Empty));
    }
}
