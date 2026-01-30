using System.Text.Json;
using ClaimLedger.Application.Export;
using ClaimLedger.Domain.Claims;
using Shared.Crypto;

namespace ClaimLedger.Cli.Verification;

/// <summary>
/// Verifies claim bundles without database access.
/// </summary>
public static class BundleVerifier
{
    /// <summary>
    /// Verifies a claim bundle from JSON.
    /// </summary>
    public static CliVerificationResult Verify(string bundleJson, IReadOnlyDictionary<string, string>? evidenceFiles = null)
    {
        ClaimBundle bundle;
        try
        {
            bundle = JsonSerializer.Deserialize<ClaimBundle>(bundleJson)
                ?? throw new JsonException("Bundle is null");
        }
        catch (JsonException ex)
        {
            return CliVerificationResult.InvalidInput($"Failed to parse bundle: {ex.Message}");
        }

        return Verify(bundle, evidenceFiles);
    }

    /// <summary>
    /// Verifies a parsed claim bundle.
    /// </summary>
    public static CliVerificationResult Verify(ClaimBundle bundle, IReadOnlyDictionary<string, string>? evidenceFiles = null)
    {
        // Check version
        if (bundle.Version != "claim-bundle.v1")
        {
            return CliVerificationResult.InvalidInput($"Unsupported bundle version: {bundle.Version}");
        }

        // Check algorithms
        if (bundle.Algorithms.Signature != "Ed25519")
        {
            return CliVerificationResult.InvalidInput($"Unsupported signature algorithm: {bundle.Algorithms.Signature}");
        }

        if (bundle.Algorithms.Hash != "SHA-256")
        {
            return CliVerificationResult.InvalidInput($"Unsupported hash algorithm: {bundle.Algorithms.Hash}");
        }

        // Parse public key
        Ed25519PublicKey publicKey;
        try
        {
            publicKey = Ed25519PublicKey.Parse(bundle.Researcher.PublicKey);
        }
        catch (Exception ex)
        {
            return CliVerificationResult.Broken($"Invalid public key: {ex.Message}");
        }

        // Parse signature
        Ed25519Signature signature;
        try
        {
            signature = Ed25519Signature.Parse(bundle.Claim.Signature);
        }
        catch (Exception ex)
        {
            return CliVerificationResult.Broken($"Invalid signature: {ex.Message}");
        }

        // Build signable for verification
        var signable = new ClaimSignable
        {
            Version = "claim.v1",
            ClaimId = bundle.Claim.ClaimId,
            Statement = bundle.Claim.Statement,
            ResearcherId = bundle.Researcher.ResearcherId,
            ResearcherPublicKey = bundle.Researcher.PublicKey,
            Evidence = bundle.Claim.Evidence.Select(e => new EvidenceSignable
            {
                Type = e.Type,
                Hash = e.Hash,
                Locator = e.Locator
            }).ToList(),
            AssertedAtUtc = bundle.Claim.AssertedAtUtc
        };

        // Verify signature
        var bytes = CanonicalJson.SerializeToBytes(signable);
        if (!publicKey.Verify(bytes, signature))
        {
            return CliVerificationResult.Broken("Signature verification failed");
        }

        // Verify evidence hashes if files provided
        var warnings = new List<string>();
        var evidenceMatches = new List<(string type, string hash, bool matched)>();

        if (evidenceFiles != null && evidenceFiles.Count > 0)
        {
            foreach (var evidence in bundle.Claim.Evidence)
            {
                if (evidenceFiles.TryGetValue(evidence.Hash, out var filePath))
                {
                    try
                    {
                        using var stream = File.OpenRead(filePath);
                        var fileHash = ContentHash.Compute(stream);
                        if (fileHash.ToString() != evidence.Hash)
                        {
                            return CliVerificationResult.Broken(
                                $"Evidence hash mismatch for {evidence.Type}: expected {evidence.Hash}, got {fileHash}");
                        }
                        evidenceMatches.Add((evidence.Type, evidence.Hash, true));
                    }
                    catch (Exception ex)
                    {
                        warnings.Add($"Could not verify evidence {evidence.Type}: {ex.Message}");
                    }
                }
            }
        }

        return CliVerificationResult.Valid(bundle, warnings);
    }
}

/// <summary>
/// Result of CLI verification with exit codes.
/// </summary>
public sealed class CliVerificationResult
{
    public VerificationStatus Status { get; }
    public string? Message { get; }
    public ClaimBundle? Bundle { get; }
    public IReadOnlyList<string> Warnings { get; }

    private CliVerificationResult(
        VerificationStatus status,
        string? message,
        ClaimBundle? bundle,
        IReadOnlyList<string>? warnings)
    {
        Status = status;
        Message = message;
        Bundle = bundle;
        Warnings = warnings ?? Array.Empty<string>();
    }

    public static CliVerificationResult Valid(ClaimBundle bundle, IReadOnlyList<string>? warnings = null)
        => new(VerificationStatus.Valid, null, bundle, warnings);

    public static CliVerificationResult Broken(string reason)
        => new(VerificationStatus.Broken, reason, null, null);

    public static CliVerificationResult InvalidInput(string reason)
        => new(VerificationStatus.InvalidInput, reason, null, null);

    public static CliVerificationResult Error(string message)
        => new(VerificationStatus.Error, message, null, null);

    public int ExitCode => Status switch
    {
        VerificationStatus.Valid => 0,
        VerificationStatus.Broken => 3,
        VerificationStatus.InvalidInput => 4,
        VerificationStatus.Error => 5,
        _ => 5
    };
}

/// <summary>
/// Verification status codes.
/// </summary>
public enum VerificationStatus
{
    Valid = 0,
    Broken = 3,
    InvalidInput = 4,
    Error = 5
}
