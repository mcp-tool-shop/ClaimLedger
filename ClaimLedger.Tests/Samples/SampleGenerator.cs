using System.Text.Json;
using ClaimLedger.Application.Claims;
using ClaimLedger.Application.Export;
using ClaimLedger.Application.Identity;
using ClaimLedger.Domain.Identity;
using ClaimLedger.Tests.Fakes;
using Shared.Crypto;

namespace ClaimLedger.Tests.Samples;

/// <summary>
/// Generates sample claim bundles for documentation.
/// Run with: dotnet test --filter "FullyQualifiedName~GenerateSampleBundle"
/// </summary>
public class SampleGenerator
{
    [Fact]
    public async Task GenerateSampleBundle()
    {
        // Arrange
        var keyVault = new InMemoryKeyVault();
        var identityRepo = new InMemoryResearcherIdentityRepository();
        var claimRepo = new InMemoryClaimRepository();
        var clock = new FakeClock();

        var identityHandler = new CreateResearcherIdentityHandler(keyVault, identityRepo, clock);
        var claimHandler = new AssertClaimHandler(keyVault, identityRepo, claimRepo, clock);
        var exportHandler = new ExportClaimBundleHandler(claimRepo, identityRepo);

        // Create researcher
        var researcher = await identityHandler.HandleAsync(new CreateResearcherIdentityCommand("Dr. Jane Smith"));

        // Create claim with evidence
        var evidence = new[]
        {
            new EvidenceInput("Dataset", ContentHash.Compute("sample dataset content for training"u8), "https://example.com/dataset.csv"),
            new EvidenceInput("Code", ContentHash.Compute("model.py source code"u8), "https://github.com/example/model")
        };

        var claim = await claimHandler.HandleAsync(new AssertClaimCommand(
            "The proposed neural network architecture achieves 94.7% accuracy on the MNIST benchmark",
            researcher.Id,
            evidence));

        // Export bundle
        var bundle = await exportHandler.HandleAsync(new ExportClaimBundleCommand(claim.Id));

        // Output to JSON
        var json = JsonSerializer.Serialize(bundle, new JsonSerializerOptions { WriteIndented = true });

        // Write to samples directory
        var samplesDir = Path.Combine(
            Directory.GetCurrentDirectory(),
            "..", "..", "..", "..", "samples");

        if (Directory.Exists(samplesDir))
        {
            var bundlePath = Path.Combine(samplesDir, "sample-claim.json");
            await File.WriteAllTextAsync(bundlePath, json);
        }

        // Assert bundle is valid
        Assert.Equal("claim-bundle.v1", bundle.Version);
        Assert.Equal(2, bundle.Claim.Evidence.Count);
    }
}
