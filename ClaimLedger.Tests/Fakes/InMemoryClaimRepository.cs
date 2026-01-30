using System.Collections.Concurrent;
using ClaimLedger.Domain.Claims;
using ClaimLedger.Domain.Primitives;

namespace ClaimLedger.Tests.Fakes;

/// <summary>
/// In-memory claim repository for testing.
/// </summary>
public sealed class InMemoryClaimRepository : IClaimRepository
{
    private readonly ConcurrentDictionary<ClaimId, ClaimAssertion> _claims = new();

    public Task<ClaimAssertion?> GetByIdAsync(ClaimId id, CancellationToken ct = default)
    {
        _claims.TryGetValue(id, out var claim);
        return Task.FromResult(claim);
    }

    public Task SaveAsync(ClaimAssertion claim, CancellationToken ct = default)
    {
        _claims[claim.Id] = claim;
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<ClaimAssertion>> GetByResearcherAsync(ResearcherId researcherId, CancellationToken ct = default)
    {
        var claims = _claims.Values
            .Where(c => c.ResearcherId == researcherId)
            .ToList();
        return Task.FromResult<IReadOnlyList<ClaimAssertion>>(claims);
    }
}
