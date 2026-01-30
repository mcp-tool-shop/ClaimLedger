namespace ClaimLedger.Domain.Evidence;

/// <summary>
/// Categories of evidence that can support a claim.
/// </summary>
public static class EvidenceType
{
    public const string Dataset = "Dataset";
    public const string Code = "Code";
    public const string Paper = "Paper";
    public const string Notebook = "Notebook";
    public const string Other = "Other";

    private static readonly HashSet<string> ValidTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        Dataset, Code, Paper, Notebook, Other
    };

    public static bool IsValid(string type) => ValidTypes.Contains(type);

    public static string Normalize(string type)
    {
        if (!IsValid(type))
            throw new ArgumentException($"Invalid evidence type: {type}", nameof(type));

        return type switch
        {
            _ when type.Equals(Dataset, StringComparison.OrdinalIgnoreCase) => Dataset,
            _ when type.Equals(Code, StringComparison.OrdinalIgnoreCase) => Code,
            _ when type.Equals(Paper, StringComparison.OrdinalIgnoreCase) => Paper,
            _ when type.Equals(Notebook, StringComparison.OrdinalIgnoreCase) => Notebook,
            _ => Other
        };
    }
}
