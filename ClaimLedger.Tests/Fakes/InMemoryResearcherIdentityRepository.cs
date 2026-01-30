using System.Collections.Concurrent;
using ClaimLedger.Domain.Identity;
using ClaimLedger.Domain.Primitives;

namespace ClaimLedger.Tests.Fakes;

/// <summary>
/// In-memory researcher identity repository for testing.
/// </summary>
public sealed class InMemoryResearcherIdentityRepository : IResearcherIdentityRepository
{
    private readonly ConcurrentDictionary<ResearcherId, ResearcherIdentity> _identities = new();

    public Task<ResearcherIdentity?> GetByIdAsync(ResearcherId id, CancellationToken ct = default)
    {
        _identities.TryGetValue(id, out var identity);
        return Task.FromResult(identity);
    }

    public Task SaveAsync(ResearcherIdentity identity, CancellationToken ct = default)
    {
        _identities[identity.Id] = identity;
        return Task.CompletedTask;
    }
}
