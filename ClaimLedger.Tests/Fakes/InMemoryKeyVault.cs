using System.Collections.Concurrent;
using ClaimLedger.Domain.Identity;
using ClaimLedger.Domain.Primitives;
using Shared.Crypto;

namespace ClaimLedger.Tests.Fakes;

/// <summary>
/// In-memory key vault for testing.
/// </summary>
public sealed class InMemoryKeyVault : IKeyVault
{
    private readonly ConcurrentDictionary<ResearcherId, Ed25519PrivateKey> _keys = new();

    public Task StoreAsync(ResearcherId researcherId, Ed25519PrivateKey privateKey, CancellationToken ct = default)
    {
        _keys[researcherId] = privateKey;
        return Task.CompletedTask;
    }

    public Task<Ed25519PrivateKey?> RetrieveAsync(ResearcherId researcherId, CancellationToken ct = default)
    {
        _keys.TryGetValue(researcherId, out var key);
        return Task.FromResult(key);
    }

    public Task<bool> ExistsAsync(ResearcherId researcherId, CancellationToken ct = default)
    {
        return Task.FromResult(_keys.ContainsKey(researcherId));
    }
}
