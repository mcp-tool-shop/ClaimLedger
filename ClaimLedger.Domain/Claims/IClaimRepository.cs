using ClaimLedger.Domain.Primitives;

namespace ClaimLedger.Domain.Claims;

/// <summary>
/// Repository for claim assertions.
/// </summary>
public interface IClaimRepository
{
    Task<ClaimAssertion?> GetByIdAsync(ClaimId id, CancellationToken ct = default);
    Task SaveAsync(ClaimAssertion claim, CancellationToken ct = default);
    Task<IReadOnlyList<ClaimAssertion>> GetByResearcherAsync(ResearcherId researcherId, CancellationToken ct = default);
}
