using ClaimLedger.Application.Claims;
using ClaimLedger.Application.Identity;
using ClaimLedger.Domain.Identity;
using ClaimLedger.Domain.Primitives;
using ClaimLedger.Tests.Fakes;
using Shared.Crypto;

namespace ClaimLedger.Tests.Application;

public class AssertClaimTests
{
    private readonly InMemoryKeyVault _keyVault = new();
    private readonly InMemoryResearcherIdentityRepository _identityRepo = new();
    private readonly InMemoryClaimRepository _claimRepo = new();
    private readonly FakeClock _clock = new();

    [Fact]
    public async Task AssertClaim_CreatesValidSignature()
    {
        var researcher = await CreateResearcher("Dr. Smith");
        var handler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);

        var claim = await handler.HandleAsync(new AssertClaimCommand(
            "Neural networks improve accuracy by 15%",
            researcher.Id,
            Array.Empty<EvidenceInput>()));

        Assert.True(claim.VerifySignature());
    }

    [Fact]
    public async Task AssertClaim_IncludesEvidenceInSignature()
    {
        var researcher = await CreateResearcher("Dr. Smith");
        var handler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);

        var evidence = new[]
        {
            new EvidenceInput("Dataset", ContentHash.Compute("training data"u8)),
            new EvidenceInput("Code", ContentHash.Compute("model.py"u8), "https://github.com/example/repo")
        };

        var claim = await handler.HandleAsync(new AssertClaimCommand(
            "Model achieves 95% accuracy",
            researcher.Id,
            evidence));

        Assert.Equal(2, claim.Evidence.Count);
        Assert.True(claim.VerifySignature());
    }

    [Fact]
    public async Task AssertClaim_PersistsClaim()
    {
        var researcher = await CreateResearcher("Dr. Smith");
        var handler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);

        var claim = await handler.HandleAsync(new AssertClaimCommand(
            "Test claim",
            researcher.Id,
            Array.Empty<EvidenceInput>()));

        var retrieved = await _claimRepo.GetByIdAsync(claim.Id);
        Assert.NotNull(retrieved);
        Assert.Equal(claim.Statement, retrieved.Statement);
    }

    [Fact]
    public async Task AssertClaim_EmptyStatement_Throws()
    {
        var researcher = await CreateResearcher("Dr. Smith");
        var handler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            handler.HandleAsync(new AssertClaimCommand(
                "",
                researcher.Id,
                Array.Empty<EvidenceInput>())));
    }

    [Fact]
    public async Task AssertClaim_UnknownResearcher_Throws()
    {
        var handler = new AssertClaimHandler(_keyVault, _identityRepo, _claimRepo, _clock);
        var unknownId = ResearcherId.New();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            handler.HandleAsync(new AssertClaimCommand(
                "Test claim",
                unknownId,
                Array.Empty<EvidenceInput>())));
    }

    private async Task<ResearcherIdentity> CreateResearcher(string name)
    {
        var handler = new CreateResearcherIdentityHandler(_keyVault, _identityRepo, _clock);
        return await handler.HandleAsync(new CreateResearcherIdentityCommand(name));
    }
}
