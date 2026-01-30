using ClaimLedger.Domain.Primitives;
using ClaimLedger.Domain.Revocations;
using Shared.Crypto;

namespace ClaimLedger.Application.Revocations;

/// <summary>
/// Command to create a self-signed key revocation.
/// </summary>
public sealed record CreateSelfSignedRevocationCommand(
    ResearcherId ResearcherId,
    Ed25519PublicKey RevokedPublicKey,
    Ed25519PrivateKey RevokedPrivateKey,
    string Reason,
    DateTimeOffset? RevokedAtUtc = null,
    Ed25519PublicKey? SuccessorPublicKey = null,
    string? Notes = null);

/// <summary>
/// Command to create a successor-signed key revocation.
/// </summary>
public sealed record CreateSuccessorSignedRevocationCommand(
    ResearcherId ResearcherId,
    Ed25519PublicKey RevokedPublicKey,
    Ed25519PublicKey SuccessorPublicKey,
    Ed25519PrivateKey SuccessorPrivateKey,
    string Reason,
    DateTimeOffset? RevokedAtUtc = null,
    string? Notes = null);

/// <summary>
/// Handler for creating revocations.
/// </summary>
public static class CreateRevocationHandler
{
    public static Revocation HandleSelfSigned(CreateSelfSignedRevocationCommand command)
    {
        var revokedAt = command.RevokedAtUtc ?? DateTimeOffset.UtcNow;

        return Revocation.CreateSelfSigned(
            command.ResearcherId,
            command.RevokedPublicKey,
            command.RevokedPrivateKey,
            revokedAt,
            command.Reason,
            command.SuccessorPublicKey,
            command.Notes);
    }

    public static Revocation HandleSuccessorSigned(CreateSuccessorSignedRevocationCommand command)
    {
        var revokedAt = command.RevokedAtUtc ?? DateTimeOffset.UtcNow;

        return Revocation.CreateSuccessorSigned(
            command.ResearcherId,
            command.RevokedPublicKey,
            command.SuccessorPublicKey,
            command.SuccessorPrivateKey,
            revokedAt,
            command.Reason,
            command.Notes);
    }
}

/// <summary>
/// Exports a revocation to a bundle.
/// </summary>
public static class ExportRevocationBundleHandler
{
    public static RevocationBundle Handle(Revocation revocation, string? displayName = null)
    {
        return new RevocationBundle
        {
            Revocation = new RevocationInfo
            {
                RevocationId = revocation.Id.ToString(),
                ResearcherId = revocation.ResearcherId.ToString(),
                RevokedPublicKey = revocation.RevokedPublicKey.ToString(),
                RevokedAtUtc = revocation.RevokedAtUtc.ToString("O"),
                Reason = revocation.Reason,
                IssuerMode = revocation.IssuerMode,
                SuccessorPublicKey = revocation.SuccessorPublicKey?.ToString(),
                Notes = revocation.Notes,
                Signature = revocation.Signature.ToString()
            },
            Identity = displayName != null
                ? new IdentityInfo
                {
                    ResearcherId = revocation.ResearcherId.ToString(),
                    DisplayName = displayName
                }
                : null
        };
    }
}
