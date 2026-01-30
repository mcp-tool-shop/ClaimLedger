using ClaimLedger.Application.Identity;
using ClaimLedger.Tests.Fakes;

namespace ClaimLedger.Tests.Application;

public class CreateResearcherIdentityTests
{
    private readonly InMemoryKeyVault _keyVault = new();
    private readonly InMemoryResearcherIdentityRepository _identityRepo = new();
    private readonly FakeClock _clock = new();

    [Fact]
    public async Task CreateIdentity_StoresPublicKeyInRepository()
    {
        var handler = new CreateResearcherIdentityHandler(_keyVault, _identityRepo, _clock);

        var identity = await handler.HandleAsync(new CreateResearcherIdentityCommand("Dr. Smith"));

        var retrieved = await _identityRepo.GetByIdAsync(identity.Id);
        Assert.NotNull(retrieved);
        Assert.Equal("Dr. Smith", retrieved.DisplayName);
        Assert.Equal(identity.PublicKey, retrieved.PublicKey);
    }

    [Fact]
    public async Task CreateIdentity_StoresPrivateKeyInVault()
    {
        var handler = new CreateResearcherIdentityHandler(_keyVault, _identityRepo, _clock);

        var identity = await handler.HandleAsync(new CreateResearcherIdentityCommand("Dr. Smith"));

        var privateKey = await _keyVault.RetrieveAsync(identity.Id);
        Assert.NotNull(privateKey);
    }

    [Fact]
    public async Task CreateIdentity_UsesClockTimestamp()
    {
        _clock.UtcNow = new DateTimeOffset(2024, 1, 15, 10, 30, 0, TimeSpan.Zero);
        var handler = new CreateResearcherIdentityHandler(_keyVault, _identityRepo, _clock);

        var identity = await handler.HandleAsync(new CreateResearcherIdentityCommand("Dr. Smith"));

        Assert.Equal(_clock.UtcNow, identity.CreatedAtUtc);
    }

    [Fact]
    public async Task CreateIdentity_AllowsNullDisplayName()
    {
        var handler = new CreateResearcherIdentityHandler(_keyVault, _identityRepo, _clock);

        var identity = await handler.HandleAsync(new CreateResearcherIdentityCommand(null));

        Assert.Null(identity.DisplayName);
    }
}
