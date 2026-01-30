using System.Text.Json;
using ClaimLedger.Application.Export;

namespace ClaimLedger.Cli.Verification;

/// <summary>
/// Inspects claim bundles for display.
/// </summary>
public static class BundleInspector
{
    /// <summary>
    /// Parses and inspects a bundle for display purposes.
    /// No cryptographic verification is performed.
    /// </summary>
    public static InspectionResult Inspect(string bundleJson)
    {
        try
        {
            var bundle = JsonSerializer.Deserialize<ClaimBundle>(bundleJson)
                ?? throw new JsonException("Bundle is null");

            return InspectionResult.Success(bundle);
        }
        catch (JsonException ex)
        {
            return InspectionResult.Failed($"Failed to parse bundle: {ex.Message}");
        }
    }

    /// <summary>
    /// Formats bundle for console display.
    /// </summary>
    public static string FormatForDisplay(ClaimBundle bundle)
    {
        var lines = new List<string>
        {
            $"Claim Bundle: {bundle.Version}",
            $"  Claim ID:    {bundle.Claim.ClaimId}",
            $"  Asserted:    {bundle.Claim.AssertedAtUtc}",
            $"  Algorithms:  {bundle.Algorithms.Signature}, {bundle.Algorithms.Hash}, {bundle.Algorithms.Encoding}",
            "",
            "Statement:",
            $"  {bundle.Claim.Statement}",
            "",
            $"Evidence: {bundle.Claim.Evidence.Count}"
        };

        foreach (var evidence in bundle.Claim.Evidence)
        {
            var locator = string.IsNullOrEmpty(evidence.Locator) ? "" : $" ({evidence.Locator})";
            lines.Add($"  - {evidence.Type}: {Truncate(evidence.Hash, 16)}...{locator}");
        }

        lines.Add("");
        lines.Add("Researcher:");
        lines.Add($"  ID:     {bundle.Researcher.ResearcherId}");
        lines.Add($"  Key:    {Truncate(bundle.Researcher.PublicKey, 24)}...");

        if (!string.IsNullOrEmpty(bundle.Researcher.DisplayName))
        {
            lines.Add($"  Name:   {bundle.Researcher.DisplayName}");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string Truncate(string s, int maxLength)
        => s.Length <= maxLength ? s : s[..maxLength];
}

/// <summary>
/// Result of bundle inspection.
/// </summary>
public sealed class InspectionResult
{
    public bool IsSuccess { get; }
    public ClaimBundle? Bundle { get; }
    public string? ErrorMessage { get; }

    private InspectionResult(bool isSuccess, ClaimBundle? bundle, string? errorMessage)
    {
        IsSuccess = isSuccess;
        Bundle = bundle;
        ErrorMessage = errorMessage;
    }

    public static InspectionResult Success(ClaimBundle bundle)
        => new(true, bundle, null);

    public static InspectionResult Failed(string error)
        => new(false, null, error);
}
