using ClaimLedger.Domain.Primitives;

namespace ClaimLedger.Tests.Domain;

public class PrimitiveIdTests
{
    [Fact]
    public void ClaimId_New_CreatesUniqueIds()
    {
        var id1 = ClaimId.New();
        var id2 = ClaimId.New();

        Assert.NotEqual(id1, id2);
    }

    [Fact]
    public void ClaimId_RejectsEmptyGuid()
    {
        Assert.Throws<ArgumentException>(() => new ClaimId(Guid.Empty));
    }

    [Fact]
    public void ClaimId_Parse_RoundTrips()
    {
        var original = ClaimId.New();
        var parsed = ClaimId.Parse(original.ToString());

        Assert.Equal(original, parsed);
    }

    [Fact]
    public void ResearcherId_New_CreatesUniqueIds()
    {
        var id1 = ResearcherId.New();
        var id2 = ResearcherId.New();

        Assert.NotEqual(id1, id2);
    }

    [Fact]
    public void ResearcherId_RejectsEmptyGuid()
    {
        Assert.Throws<ArgumentException>(() => new ResearcherId(Guid.Empty));
    }

    [Fact]
    public void EvidenceId_New_CreatesUniqueIds()
    {
        var id1 = EvidenceId.New();
        var id2 = EvidenceId.New();

        Assert.NotEqual(id1, id2);
    }

    [Fact]
    public void EvidenceId_RejectsEmptyGuid()
    {
        Assert.Throws<ArgumentException>(() => new EvidenceId(Guid.Empty));
    }
}
