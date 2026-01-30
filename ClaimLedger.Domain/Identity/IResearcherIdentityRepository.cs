using ClaimLedger.Domain.Primitives;

namespace ClaimLedger.Domain.Identity;

/// <summary>
/// Repository for researcher identities.
/// </summary>
public interface IResearcherIdentityRepository
{
    Task<ResearcherIdentity?> GetByIdAsync(ResearcherId id, CancellationToken ct = default);
    Task SaveAsync(ResearcherIdentity identity, CancellationToken ct = default);
}
