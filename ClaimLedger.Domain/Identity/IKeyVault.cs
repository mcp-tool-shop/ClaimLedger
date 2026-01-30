using ClaimLedger.Domain.Primitives;
using Shared.Crypto;

namespace ClaimLedger.Domain.Identity;

/// <summary>
/// Secure storage for researcher private keys.
/// </summary>
public interface IKeyVault
{
    Task StoreAsync(ResearcherId researcherId, Ed25519PrivateKey privateKey, CancellationToken ct = default);
    Task<Ed25519PrivateKey?> RetrieveAsync(ResearcherId researcherId, CancellationToken ct = default);
    Task<bool> ExistsAsync(ResearcherId researcherId, CancellationToken ct = default);
}
