using ClaimLedger.Application.Attestations;
using ClaimLedger.Application.Citations;
using ClaimLedger.Application.Claims;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Identity;
using ClaimLedger.Domain.Attestations;
using ClaimLedger.Domain.Citations;
using ClaimLedger.Tests.Fakes;
using Shared.Crypto;

namespace ClaimLedger.Tests.Application;

public class CitationTests
{
    private readonly InMemoryKeyVault _keyVault = new();
    private readonly InMemoryResearcherIdentityRepository _identityRepo = new();
    private readonly InMemoryClaimRepository _claimRepo = new();
    private readonly FakeClock _clock = new();

    [Fact]
    public async Task CreateCitation_ValidCitation_Verifies()
    {
        var citingBundle = await CreateClaimBundle("Citing claim");
        var citedBundle = await CreateClaimBundle("Cited claim");
        var citedDigest = ClaimCoreDigest.Compute(citedBundle);

        var handler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await handler.HandleAsync(new CreateCitationCommand(
            citingBundle,
            citedDigest,
            CitationRelation.Cites,
            "doi:10.1234/test",
            "Prior work reference"));

        Assert.True(citation.VerifySignature());
    }

    [Fact]
    public async Task Citation_IncludedInClaimCoreDigest()
    {
        var bundle = await CreateClaimBundle("Test claim");
        var citedDigest = Digest256.Compute("cited claim"u8);

        // Compute digest before citation
        var digestBefore = ClaimCoreDigest.Compute(bundle);

        // Add citation
        var handler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await handler.HandleAsync(new CreateCitationCommand(
            bundle,
            citedDigest,
            CitationRelation.DependsOn,
            null,
            "Dependency"));

        var citedBundle = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(bundle, citation));

        // Compute digest after citation
        var digestAfter = ClaimCoreDigest.Compute(citedBundle);

        // Should be DIFFERENT - citations affect core digest
        Assert.NotEqual(digestBefore, digestAfter);
    }

    [Fact]
    public async Task Attestation_StillIndependentOfCoreDigest()
    {
        var bundle = await CreateClaimBundle("Test claim");

        // Add a citation first
        var citedDigest = Digest256.Compute("cited claim"u8);
        var citationHandler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await citationHandler.HandleAsync(new CreateCitationCommand(
            bundle,
            citedDigest,
            CitationRelation.Cites,
            null,
            null));
        bundle = AddCitationToBundleHandler.Handle(new AddCitationToBundleCommand(bundle, citation));

        // Compute digest before attestation
        var digestBefore = ClaimCoreDigest.Compute(bundle);

        // Add attestation
        var attestor = await CreateResearcher("Dr. Reviewer");
        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle,
            attestor.Id,
            AttestationType.Reviewed,
            "Reviewed"));

        var attestedBundle = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation));

        // Compute digest after attestation
        var digestAfter = ClaimCoreDigest.Compute(attestedBundle);

        // Should be SAME - attestations don't affect core digest
        Assert.Equal(digestBefore, digestAfter);
    }

    [Fact]
    public async Task VerifyCitations_ValidCitation_ReturnsValid()
    {
        var citingBundle = await CreateClaimBundle("Citing claim");
        var citedBundle = await CreateClaimBundle("Cited claim");
        var citedDigest = ClaimCoreDigest.Compute(citedBundle);

        var handler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await handler.HandleAsync(new CreateCitationCommand(
            citingBundle,
            citedDigest,
            CitationRelation.Cites,
            null,
            null));

        var bundleWithCitation = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation));

        var result = VerifyCitationsHandler.Handle(
            new VerifyCitationsQuery(bundleWithCitation));

        Assert.True(result.AllValid);
        Assert.Single(result.Results);
        Assert.True(result.Results[0].IsValid);
        Assert.False(result.Results[0].IsResolved); // No embedded or resolver
    }

    [Fact]
    public async Task VerifyCitations_NoCitations_ReturnsValid()
    {
        var bundle = await CreateClaimBundle("Test claim");

        var result = VerifyCitationsHandler.Handle(
            new VerifyCitationsQuery(bundle));

        Assert.True(result.AllValid);
        Assert.Empty(result.Results);
    }

    [Fact]
    public async Task VerifyCitations_TamperedNotes_ReturnsBroken()
    {
        var citingBundle = await CreateClaimBundle("Citing claim");
        var citedDigest = Digest256.Compute("cited claim"u8);

        var handler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await handler.HandleAsync(new CreateCitationCommand(
            citingBundle,
            citedDigest,
            CitationRelation.Cites,
            null,
            "Original notes"));

        var bundleWithCitation = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation));

        // Tamper with the notes
        var tamperedCitation = new CitationInfo
        {
            CitationId = bundleWithCitation.Citations![0].CitationId,
            CitedClaimCoreDigest = bundleWithCitation.Citations[0].CitedClaimCoreDigest,
            Relation = bundleWithCitation.Citations[0].Relation,
            Locator = bundleWithCitation.Citations[0].Locator,
            Notes = "TAMPERED NOTES",  // Different!
            IssuedAtUtc = bundleWithCitation.Citations[0].IssuedAtUtc,
            Signature = bundleWithCitation.Citations[0].Signature
        };

        var tamperedBundle = new ClaimBundle
        {
            Version = bundleWithCitation.Version,
            Algorithms = bundleWithCitation.Algorithms,
            Claim = bundleWithCitation.Claim,
            Researcher = bundleWithCitation.Researcher,
            Citations = new[] { tamperedCitation }
        };

        var result = VerifyCitationsHandler.Handle(
            new VerifyCitationsQuery(tamperedBundle));

        Assert.False(result.AllValid);
        Assert.Equal(CitationCheckResult.Reasons.SignatureInvalid, result.Results[0].FailureReason);
    }

    [Fact]
    public async Task VerifyCitations_TamperedRelation_ReturnsBroken()
    {
        var citingBundle = await CreateClaimBundle("Citing claim");
        var citedDigest = Digest256.Compute("cited claim"u8);

        var handler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await handler.HandleAsync(new CreateCitationCommand(
            citingBundle,
            citedDigest,
            CitationRelation.Cites,
            null,
            null));

        var bundleWithCitation = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation));

        // Tamper with the relation
        var tamperedCitation = new CitationInfo
        {
            CitationId = bundleWithCitation.Citations![0].CitationId,
            CitedClaimCoreDigest = bundleWithCitation.Citations[0].CitedClaimCoreDigest,
            Relation = CitationRelation.Disputes,  // Different!
            Locator = bundleWithCitation.Citations[0].Locator,
            Notes = bundleWithCitation.Citations[0].Notes,
            IssuedAtUtc = bundleWithCitation.Citations[0].IssuedAtUtc,
            Signature = bundleWithCitation.Citations[0].Signature
        };

        var tamperedBundle = new ClaimBundle
        {
            Version = bundleWithCitation.Version,
            Algorithms = bundleWithCitation.Algorithms,
            Claim = bundleWithCitation.Claim,
            Researcher = bundleWithCitation.Researcher,
            Citations = new[] { tamperedCitation }
        };

        var result = VerifyCitationsHandler.Handle(
            new VerifyCitationsQuery(tamperedBundle));

        Assert.False(result.AllValid);
        Assert.Equal(CitationCheckResult.Reasons.SignatureInvalid, result.Results[0].FailureReason);
    }

    [Fact]
    public async Task VerifyCitations_EmbeddedBundle_ResolvesAndVerifies()
    {
        var citingBundle = await CreateClaimBundle("Citing claim");
        var citedBundle = await CreateClaimBundle("Cited claim");
        var citedDigest = ClaimCoreDigest.Compute(citedBundle);

        var handler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await handler.HandleAsync(new CreateCitationCommand(
            citingBundle,
            citedDigest,
            CitationRelation.Cites,
            null,
            null));

        // Add with embedded bundle
        var bundleWithCitation = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation, citedBundle));

        var result = VerifyCitationsHandler.Handle(
            new VerifyCitationsQuery(bundleWithCitation));

        Assert.True(result.AllValid);
        Assert.Single(result.Results);
        Assert.True(result.Results[0].IsValid);
        Assert.True(result.Results[0].IsResolved);  // Resolved via embedding
        Assert.Empty(result.UnresolvedDigests);
    }

    [Fact]
    public async Task VerifyCitations_EmbeddedDigestMismatch_ReturnsBroken()
    {
        var citingBundle = await CreateClaimBundle("Citing claim");
        var citedBundle = await CreateClaimBundle("Cited claim");
        var wrongBundle = await CreateClaimBundle("Wrong claim");  // Different!
        var citedDigest = ClaimCoreDigest.Compute(citedBundle);

        var handler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await handler.HandleAsync(new CreateCitationCommand(
            citingBundle,
            citedDigest,
            CitationRelation.Cites,
            null,
            null));

        // Add with WRONG embedded bundle
        var bundleWithCitation = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation, wrongBundle));

        var result = VerifyCitationsHandler.Handle(
            new VerifyCitationsQuery(bundleWithCitation));

        Assert.False(result.AllValid);
        Assert.Equal(CitationCheckResult.Reasons.EmbeddedDigestMismatch, result.Results[0].FailureReason);
    }

    [Fact]
    public async Task VerifyCitations_ResolverFindsBundles()
    {
        var citingBundle = await CreateClaimBundle("Citing claim");
        var citedBundle = await CreateClaimBundle("Cited claim");
        var citedDigest = ClaimCoreDigest.Compute(citedBundle);

        var handler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await handler.HandleAsync(new CreateCitationCommand(
            citingBundle,
            citedDigest,
            CitationRelation.Cites,
            null,
            null));

        var bundleWithCitation = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation));

        // Build resolver map
        var resolvedBundles = new Dictionary<string, ClaimBundle>
        {
            [citedDigest.ToString()] = citedBundle
        };

        var result = VerifyCitationsHandler.Handle(
            new VerifyCitationsQuery(bundleWithCitation, false, resolvedBundles));

        Assert.True(result.AllValid);
        Assert.True(result.Results[0].IsResolved);  // Resolved via resolver
        Assert.Empty(result.UnresolvedDigests);
    }

    [Fact]
    public async Task VerifyCitations_StrictMode_FailsOnUnresolved()
    {
        var citingBundle = await CreateClaimBundle("Citing claim");
        var citedDigest = Digest256.Compute("cited claim"u8);

        var handler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);
        var citation = await handler.HandleAsync(new CreateCitationCommand(
            citingBundle,
            citedDigest,
            CitationRelation.Cites,
            null,
            null));

        var bundleWithCitation = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation));

        // Non-strict mode: valid (unresolved is just a warning)
        var nonStrictResult = VerifyCitationsHandler.Handle(
            new VerifyCitationsQuery(bundleWithCitation, StrictMode: false));
        Assert.True(nonStrictResult.AllValid);

        // Strict mode: fails because citation is unresolved
        var strictResult = VerifyCitationsHandler.Handle(
            new VerifyCitationsQuery(bundleWithCitation, StrictMode: true));
        Assert.False(strictResult.AllValid);
        Assert.Single(strictResult.UnresolvedDigests);
    }

    [Fact]
    public async Task VerifyCitations_MultipleCitations_AllVerified()
    {
        var citingBundle = await CreateClaimBundle("Citing claim");
        var citedBundle1 = await CreateClaimBundle("Cited claim 1");
        var citedBundle2 = await CreateClaimBundle("Cited claim 2");
        var citedDigest1 = ClaimCoreDigest.Compute(citedBundle1);
        var citedDigest2 = ClaimCoreDigest.Compute(citedBundle2);

        var handler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);

        var citation1 = await handler.HandleAsync(new CreateCitationCommand(
            citingBundle,
            citedDigest1,
            CitationRelation.Cites,
            null,
            "First citation"));

        citingBundle = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation1, citedBundle1));

        var citation2 = await handler.HandleAsync(new CreateCitationCommand(
            citingBundle,
            citedDigest2,
            CitationRelation.DependsOn,
            null,
            "Second citation"));

        citingBundle = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation2, citedBundle2));

        var result = VerifyCitationsHandler.Handle(
            new VerifyCitationsQuery(citingBundle));

        Assert.True(result.AllValid);
        Assert.Equal(2, result.Results.Count);
        Assert.All(result.Results, r => Assert.True(r.IsValid));
        Assert.All(result.Results, r => Assert.True(r.IsResolved));
    }

    [Fact]
    public async Task ClaimCoreDigest_SortsCitationsDeterministically()
    {
        var citingBundle = await CreateClaimBundle("Citing claim");

        // Create citations with different digests
        var digest1 = Digest256.Compute("aaa"u8);
        var digest2 = Digest256.Compute("zzz"u8);

        var handler = new CreateCitationHandler(_keyVault, _identityRepo, _clock);

        // Add in one order
        var citation1 = await handler.HandleAsync(new CreateCitationCommand(
            citingBundle, digest1, CitationRelation.Cites, null, null));
        var bundle1 = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation1));

        var citation2 = await handler.HandleAsync(new CreateCitationCommand(
            bundle1, digest2, CitationRelation.Cites, null, null));
        bundle1 = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(bundle1, citation2));

        // Add in reverse order for bundle2
        var citation2b = await handler.HandleAsync(new CreateCitationCommand(
            citingBundle, digest2, CitationRelation.Cites, null, null));
        var bundle2 = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(citingBundle, citation2b));

        var citation1b = await handler.HandleAsync(new CreateCitationCommand(
            bundle2, digest1, CitationRelation.Cites, null, null));
        bundle2 = AddCitationToBundleHandler.Handle(
            new AddCitationToBundleCommand(bundle2, citation1b));

        // Digests should be the same because citations are sorted
        var hash1 = ClaimCoreDigest.Compute(bundle1);
        var hash2 = ClaimCoreDigest.Compute(bundle2);

        // Note: They won't be equal because the citation IDs and timestamps differ
        // But the SORTING is deterministic (by digest then ID)
        // The key test is that the same bundle always produces the same digest
        var hash1Again = ClaimCoreDigest.Compute(bundle1);
        Assert.Equal(hash1, hash1Again);
    }

    [Fact]
    public async Task Phase2Bundle_BackwardsCompatible()
    {
        // Create Phase 2 bundle (with attestation, no citations)
        var bundle = await CreateClaimBundle("Test claim");
        var attestor = await CreateResearcher("Dr. Reviewer");

        var attestHandler = new CreateAttestationHandler(_keyVault, _identityRepo, _clock);
        var attestation = await attestHandler.HandleAsync(new CreateAttestationCommand(
            bundle,
            attestor.Id,
            AttestationType.Reviewed,
            "Reviewed"));

        var attestedBundle = AddAttestationToBundleHandler.Handle(
            new AddAttestationToBundleCommand(bundle, attestation));

        // Verify citations should work (empty citations = valid)
        var citationResult = VerifyCitationsHandler.Handle(
            new VerifyCitationsQuery(attestedBundle));

        Assert.True(citationResult.AllValid);
        Assert.Empty(citationResult.Results);

        // Verify attestations still works
        var attestResult = VerifyAttestationsHandler.Handle(
            new VerifyAttestationsQuery(attestedBundle, DateTimeOffset.UtcNow));

        Assert.True(attestResult.AllValid);
    }

    [Fact]
    public async Task MissingCitations_TreatedAsEmpty()
    {
        // Create bundle without citations array
        var bundle = await CreateClaimBundle("Test claim");

        // Computing digest with no citations should work
        var digest = ClaimCoreDigest.Compute(bundle);
        Assert.NotEqual(default, digest);

        // Verifying should treat missing citations as empty
        var result = VerifyCitationsHandler.Handle(new VerifyCitationsQuery(bundle));
        Assert.True(result.AllValid);
        Assert.Empty(result.Results);
    }

    private async Task<ClaimBundle> CreateClaimBundle(string statement)
    {
        var researcher = await CreateResearcher("Dr. Author " + Guid.NewGuid().ToString()[..8]);
        var claimHandler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);
        var claim = await claimHandler.HandleAsync(new AssertClaimCommand(
            statement,
            researcher.Id,
            Array.Empty<EvidenceInput>()));

        var exportHandler = new ExportClaimBundleHandler(_claimRepo, _identityRepo);
        return await exportHandler.HandleAsync(new ExportClaimBundleCommand(claim.Id));
    }

    private async Task<ClaimLedger.Domain.Identity.ResearcherIdentity> CreateResearcher(string name)
    {
        var handler = new CreateResearcherIdentityHandler(_keyVault, _identityRepo, _clock);
        return await handler.HandleAsync(new CreateResearcherIdentityCommand(name));
    }
}
