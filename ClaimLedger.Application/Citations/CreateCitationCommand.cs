using ClaimLedger.Application.Export;
using ClaimLedger.Application.Primitives;
using ClaimLedger.Domain.Citations;
using ClaimLedger.Domain.Identity;
using ClaimLedger.Domain.Primitives;
using Shared.Crypto;

namespace ClaimLedger.Application.Citations;

/// <summary>
/// Command to create a citation from one claim to another.
/// </summary>
public sealed record CreateCitationCommand(
    ClaimBundle CitingBundle,
    Digest256 CitedClaimCoreDigest,
    string Relation,
    string? Locator,
    string? Notes);

/// <summary>
/// Handler for creating citations.
/// </summary>
public sealed class CreateCitationHandler
{
    private readonly IKeyVault _keyVault;
    private readonly IResearcherIdentityRepository _identityRepo;
    private readonly IClock _clock;

    public CreateCitationHandler(
        IKeyVault keyVault,
        IResearcherIdentityRepository identityRepo,
        IClock clock)
    {
        _keyVault = keyVault;
        _identityRepo = identityRepo;
        _clock = clock;
    }

    public async Task<Citation> HandleAsync(
        CreateCitationCommand command,
        CancellationToken ct = default)
    {
        if (!CitationRelation.IsValid(command.Relation))
            throw new ArgumentException($"Invalid citation relation: {command.Relation}");

        // Get the claim author (citations are signed by claim author)
        var researcherId = ResearcherId.Parse(command.CitingBundle.Researcher.ResearcherId);
        var researcher = await _identityRepo.GetByIdAsync(researcherId, ct)
            ?? throw new InvalidOperationException($"Researcher not found: {researcherId}");

        // Get private key for signing
        var privateKey = await _keyVault.RetrieveAsync(researcherId, ct)
            ?? throw new InvalidOperationException("Private key not found for researcher");

        return Citation.Create(
            command.CitedClaimCoreDigest,
            command.Relation,
            command.Locator,
            command.Notes,
            researcher,
            privateKey,
            _clock.UtcNow);
    }
}

/// <summary>
/// Command to add a citation to a claim bundle.
/// </summary>
public sealed record AddCitationToBundleCommand(
    ClaimBundle Bundle,
    Citation Citation,
    ClaimBundle? EmbeddedBundle = null);

/// <summary>
/// Handler for adding citations to bundles.
/// </summary>
public static class AddCitationToBundleHandler
{
    public static ClaimBundle Handle(AddCitationToBundleCommand command)
    {
        var citationInfo = new CitationInfo
        {
            CitationId = command.Citation.Id.ToString(),
            CitedClaimCoreDigest = command.Citation.CitedClaimCoreDigest.ToString(),
            Relation = command.Citation.Relation,
            Locator = command.Citation.Locator,
            Notes = command.Citation.Notes,
            IssuedAtUtc = command.Citation.IssuedAtUtc.ToString("O"),
            Signature = command.Citation.Signature.ToString(),
            Embedded = command.EmbeddedBundle
        };

        var existingCitations = command.Bundle.Citations ?? Array.Empty<CitationInfo>();
        var newCitations = existingCitations.Append(citationInfo).ToList();

        return new ClaimBundle
        {
            Version = command.Bundle.Version,
            Algorithms = command.Bundle.Algorithms,
            Claim = command.Bundle.Claim,
            Researcher = command.Bundle.Researcher,
            Citations = newCitations,
            Attestations = command.Bundle.Attestations
        };
    }
}
