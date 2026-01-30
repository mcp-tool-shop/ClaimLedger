using ClaimLedger.Domain.Evidence;
using Shared.Crypto;

namespace ClaimLedger.Tests.Domain;

public class EvidenceArtifactTests
{
    [Theory]
    [InlineData("Dataset")]
    [InlineData("Code")]
    [InlineData("Paper")]
    [InlineData("Notebook")]
    [InlineData("Other")]
    public void Create_ValidType_Succeeds(string type)
    {
        var hash = ContentHash.Compute("test content"u8);
        var artifact = EvidenceArtifact.Create(type, hash, "https://example.com/file");

        Assert.Equal(type, artifact.Type);
        Assert.Equal(hash, artifact.Hash);
    }

    [Fact]
    public void Create_InvalidType_Throws()
    {
        var hash = ContentHash.Compute("test content"u8);

        Assert.Throws<ArgumentException>(() =>
            EvidenceArtifact.Create("InvalidType", hash));
    }

    [Fact]
    public void Create_CaseInsensitiveType_Normalizes()
    {
        var hash = ContentHash.Compute("test content"u8);
        var artifact = EvidenceArtifact.Create("dataset", hash);

        Assert.Equal("Dataset", artifact.Type);
    }

    [Fact]
    public void Create_NullLocator_Allowed()
    {
        var hash = ContentHash.Compute("test content"u8);
        var artifact = EvidenceArtifact.Create("Dataset", hash);

        Assert.Null(artifact.Locator);
    }
}
