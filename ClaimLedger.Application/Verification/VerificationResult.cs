namespace ClaimLedger.Application.Verification;

/// <summary>
/// Result of claim verification.
/// Only checks cryptographic validity - not truth.
/// </summary>
public sealed class VerificationResult
{
    public bool IsValid { get; }
    public string? FailureReason { get; }
    public IReadOnlyList<string> Warnings { get; }

    private VerificationResult(bool isValid, string? failureReason, IReadOnlyList<string>? warnings = null)
    {
        IsValid = isValid;
        FailureReason = failureReason;
        Warnings = warnings ?? Array.Empty<string>();
    }

    public static VerificationResult Valid(IReadOnlyList<string>? warnings = null)
        => new(true, null, warnings);

    public static VerificationResult Invalid(string reason)
        => new(false, reason);

    /// <summary>
    /// Common failure reasons.
    /// </summary>
    public static class Reasons
    {
        public const string SignatureInvalid = "Signature verification failed";
        public const string PublicKeyMismatch = "Public key does not match researcher";
        public const string ClaimIdMismatch = "Claim ID in signable does not match";
        public const string StatementMismatch = "Statement in signable does not match";
        public const string EvidenceMismatch = "Evidence in signable does not match";
        public const string TimestampMismatch = "Timestamp in signable does not match";
        public const string VersionUnsupported = "Unsupported claim version";
        public const string MalformedBundle = "Bundle is malformed or incomplete";
    }
}
