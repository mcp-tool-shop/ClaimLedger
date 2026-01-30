namespace ClaimLedger.Domain.Citations;

/// <summary>
/// Valid citation relation types.
/// </summary>
public static class CitationRelation
{
    /// <summary>
    /// General citation - references prior work.
    /// </summary>
    public const string Cites = "CITES";

    /// <summary>
    /// This claim depends on the cited claim being true.
    /// </summary>
    public const string DependsOn = "DEPENDS_ON";

    /// <summary>
    /// This claim reproduces the results of the cited claim.
    /// </summary>
    public const string Reproduces = "REPRODUCES";

    /// <summary>
    /// This claim disputes the cited claim.
    /// </summary>
    public const string Disputes = "DISPUTES";

    private static readonly HashSet<string> ValidRelations = new(StringComparer.Ordinal)
    {
        Cites,
        DependsOn,
        Reproduces,
        Disputes
    };

    public static IReadOnlyCollection<string> All => ValidRelations;

    public static bool IsValid(string relation) => ValidRelations.Contains(relation);
}
