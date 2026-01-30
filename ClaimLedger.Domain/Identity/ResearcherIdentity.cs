using ClaimLedger.Domain.Primitives;
using Shared.Crypto;

namespace ClaimLedger.Domain.Identity;

/// <summary>
/// Represents a researcher's cryptographic identity.
/// Immutable. Private keys are stored externally in a vault.
/// </summary>
public sealed class ResearcherIdentity
{
    public ResearcherId Id { get; }
    public Ed25519PublicKey PublicKey { get; }
    public string? DisplayName { get; }
    public DateTimeOffset CreatedAtUtc { get; }

    public ResearcherIdentity(
        ResearcherId id,
        Ed25519PublicKey publicKey,
        string? displayName,
        DateTimeOffset createdAtUtc)
    {
        Id = id;
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        DisplayName = displayName;
        CreatedAtUtc = createdAtUtc;
    }

    /// <summary>
    /// Creates a new researcher identity from a keypair.
    /// The private key should be stored in a vault separately.
    /// </summary>
    public static ResearcherIdentity Create(
        Ed25519PublicKey publicKey,
        string? displayName,
        DateTimeOffset createdAtUtc)
    {
        return new ResearcherIdentity(
            ResearcherId.New(),
            publicKey,
            displayName,
            createdAtUtc);
    }
}
