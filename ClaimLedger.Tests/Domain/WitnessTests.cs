using ClaimLedger.Domain.Attestations;

namespace ClaimLedger.Tests.Domain;

public class WitnessTests
{
    [Fact]
    public void AttestationType_WitnessedAt_IsValid()
    {
        Assert.True(AttestationType.IsValid(AttestationType.WitnessedAt));
    }

    [Fact]
    public void AttestationType_WitnessedAt_InAllTypes()
    {
        Assert.Contains(AttestationType.WitnessedAt, AttestationType.All);
    }

    [Fact]
    public void AttestationType_WitnessedAt_HasCorrectValue()
    {
        Assert.Equal("WITNESSED_AT", AttestationType.WitnessedAt);
    }

    [Fact]
    public void AttestationType_AllExistingTypes_StillValid()
    {
        // Ensure we didn't break existing types
        Assert.True(AttestationType.IsValid(AttestationType.Reviewed));
        Assert.True(AttestationType.IsValid(AttestationType.Reproduced));
        Assert.True(AttestationType.IsValid(AttestationType.InstitutionApproved));
        Assert.True(AttestationType.IsValid(AttestationType.DataAvailabilityConfirmed));
    }
}
