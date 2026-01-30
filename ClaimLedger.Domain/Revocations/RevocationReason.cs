namespace ClaimLedger.Domain.Revocations;

/// <summary>
/// Valid revocation reason types.
/// </summary>
public static class RevocationReason
{
    /// <summary>
    /// Key was stolen or leaked.
    /// </summary>
    public const string Compromised = "COMPROMISED";

    /// <summary>
    /// Planned key rotation (should have successor key).
    /// </summary>
    public const string Rotated = "ROTATED";

    /// <summary>
    /// Identity is no longer active.
    /// </summary>
    public const string Retired = "RETIRED";

    /// <summary>
    /// Unspecified reason.
    /// </summary>
    public const string Other = "OTHER";

    private static readonly HashSet<string> ValidReasons = new(StringComparer.Ordinal)
    {
        Compromised,
        Rotated,
        Retired,
        Other
    };

    public static IReadOnlyCollection<string> All => ValidReasons;

    public static bool IsValid(string reason) => ValidReasons.Contains(reason);
}
