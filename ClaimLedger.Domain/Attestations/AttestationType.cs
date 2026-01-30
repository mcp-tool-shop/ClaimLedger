namespace ClaimLedger.Domain.Attestations;

/// <summary>
/// Types of attestation that can be made about a claim.
/// Start small, extend later.
/// </summary>
public static class AttestationType
{
    /// <summary>
    /// Attestor reviewed the claim and evidence.
    /// </summary>
    public const string Reviewed = "REVIEWED";

    /// <summary>
    /// Attestor reproduced the claimed results.
    /// </summary>
    public const string Reproduced = "REPRODUCED";

    /// <summary>
    /// Institution approved/endorsed the claim.
    /// </summary>
    public const string InstitutionApproved = "INSTITUTION_APPROVED";

    /// <summary>
    /// Attestor confirmed data availability.
    /// </summary>
    public const string DataAvailabilityConfirmed = "DATA_AVAILABILITY_CONFIRMED";

    /// <summary>
    /// Witness timestamp: attestor witnessed claim existence at issued_at time.
    /// Proves a specific key signed at time T, binding to claim_core_digest.
    /// </summary>
    public const string WitnessedAt = "WITNESSED_AT";

    private static readonly HashSet<string> ValidTypes = new(StringComparer.Ordinal)
    {
        Reviewed,
        Reproduced,
        InstitutionApproved,
        DataAvailabilityConfirmed,
        WitnessedAt
    };

    public static bool IsValid(string type) => ValidTypes.Contains(type);

    public static IEnumerable<string> All => ValidTypes;
}
