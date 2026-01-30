namespace ClaimLedger.Domain.Revocations;

/// <summary>
/// Who signed the revocation.
/// </summary>
public static class IssuerMode
{
    /// <summary>
    /// Revocation is signed by the key being revoked.
    /// </summary>
    public const string Self = "SELF";

    /// <summary>
    /// Revocation is signed by the successor key.
    /// Requires successor_public_key to be present.
    /// </summary>
    public const string Successor = "SUCCESSOR";

    private static readonly HashSet<string> ValidModes = new(StringComparer.Ordinal)
    {
        Self,
        Successor
    };

    public static IReadOnlyCollection<string> All => ValidModes;

    public static bool IsValid(string mode) => ValidModes.Contains(mode);
}
