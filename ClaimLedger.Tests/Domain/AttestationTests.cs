using ClaimLedger.Domain.Attestations;
using ClaimLedger.Domain.Primitives;
using Shared.Crypto;

namespace ClaimLedger.Tests.Domain;

public class AttestationTests
{
    [Fact]
    public void Constructor_EmptyStatement_Throws()
    {
        var keypair = Ed25519KeyPair.Generate();
        var signature = keypair.PrivateKey.Sign("test"u8);
        var digest = Digest256.Compute("claim content"u8);

        Assert.Throws<ArgumentException>(() => new Attestation(
            AttestationId.New(),
            digest,
            ResearcherId.New(),
            keypair.PublicKey,
            "Dr. Smith",
            AttestationType.Reviewed,
            "",  // Empty!
            DateTimeOffset.UtcNow,
            null,
            signature));
    }

    [Fact]
    public void Constructor_InvalidType_Throws()
    {
        var keypair = Ed25519KeyPair.Generate();
        var signature = keypair.PrivateKey.Sign("test"u8);
        var digest = Digest256.Compute("claim content"u8);

        Assert.Throws<ArgumentException>(() => new Attestation(
            AttestationId.New(),
            digest,
            ResearcherId.New(),
            keypair.PublicKey,
            "Dr. Smith",
            "INVALID_TYPE",  // Invalid!
            "Valid statement",
            DateTimeOffset.UtcNow,
            null,
            signature));
    }

    [Fact]
    public void ToSignable_ReturnsCorrectContract()
    {
        var attestation = CreateValidAttestation();

        var signable = attestation.ToSignable();

        Assert.Equal("AttestationSignable.v1", signable.Contract);
    }

    [Fact]
    public void VerifySignature_ValidSignature_ReturnsTrue()
    {
        var attestation = CreateValidAttestation();

        Assert.True(attestation.VerifySignature());
    }

    [Fact]
    public void VerifySignature_TamperedStatement_ReturnsFalse()
    {
        // Create valid attestation
        var keypair = Ed25519KeyPair.Generate();
        var attestationId = AttestationId.New();
        var attestorId = ResearcherId.New();
        var digest = Digest256.Compute("claim content"u8);
        var timestamp = DateTimeOffset.UtcNow;

        // Create signable with original statement
        var originalSignable = new AttestationSignable
        {
            Contract = "AttestationSignable.v1",
            AttestationId = attestationId.ToString(),
            ClaimCoreDigest = digest.ToString(),
            Attestor = new AttestorIdentity
            {
                ResearcherId = attestorId.ToString(),
                PublicKey = keypair.PublicKey.ToString(),
                DisplayName = "Dr. Smith"
            },
            AttestationType = AttestationType.Reviewed,
            Statement = "Original statement",
            IssuedAtUtc = timestamp.ToString("O"),
            ExpiresAtUtc = null,
            Policy = null
        };

        var bytes = CanonicalJson.SerializeToBytes(originalSignable);
        var signature = keypair.PrivateKey.Sign(bytes);

        // Create attestation with DIFFERENT statement but same signature
        var tampered = new Attestation(
            attestationId,
            digest,
            attestorId,
            keypair.PublicKey,
            "Dr. Smith",
            AttestationType.Reviewed,
            "Tampered statement",  // Different!
            timestamp,
            null,
            signature);

        Assert.False(tampered.VerifySignature());
    }

    [Fact]
    public void IsExpired_NotExpired_ReturnsFalse()
    {
        var attestation = CreateValidAttestation(expiresAt: DateTimeOffset.UtcNow.AddDays(30));

        Assert.False(attestation.IsExpired(DateTimeOffset.UtcNow));
    }

    [Fact]
    public void IsExpired_Expired_ReturnsTrue()
    {
        var attestation = CreateValidAttestation(expiresAt: DateTimeOffset.UtcNow.AddDays(-1));

        Assert.True(attestation.IsExpired(DateTimeOffset.UtcNow));
    }

    [Fact]
    public void IsExpired_NoExpiration_ReturnsFalse()
    {
        var attestation = CreateValidAttestation(expiresAt: null);

        Assert.False(attestation.IsExpired(DateTimeOffset.UtcNow));
    }

    private static Attestation CreateValidAttestation(DateTimeOffset? expiresAt = null)
    {
        var keypair = Ed25519KeyPair.Generate();
        var attestationId = AttestationId.New();
        var attestorId = ResearcherId.New();
        var digest = Digest256.Compute("claim content"u8);
        var timestamp = DateTimeOffset.UtcNow;

        var signable = new AttestationSignable
        {
            Contract = "AttestationSignable.v1",
            AttestationId = attestationId.ToString(),
            ClaimCoreDigest = digest.ToString(),
            Attestor = new AttestorIdentity
            {
                ResearcherId = attestorId.ToString(),
                PublicKey = keypair.PublicKey.ToString(),
                DisplayName = "Dr. Smith"
            },
            AttestationType = AttestationType.Reviewed,
            Statement = "Test attestation statement",
            IssuedAtUtc = timestamp.ToString("O"),
            ExpiresAtUtc = expiresAt?.ToString("O"),
            Policy = null
        };

        var bytes = CanonicalJson.SerializeToBytes(signable);
        var signature = keypair.PrivateKey.Sign(bytes);

        return new Attestation(
            attestationId,
            digest,
            attestorId,
            keypair.PublicKey,
            "Dr. Smith",
            AttestationType.Reviewed,
            "Test attestation statement",
            timestamp,
            expiresAt,
            signature);
    }
}
