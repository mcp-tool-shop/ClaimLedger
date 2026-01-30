namespace ClaimLedger.Domain.Timestamps;

/// <summary>
/// Parsed TSTInfo from an RFC 3161 timestamp token.
/// Contains only the fields we need for verification.
/// </summary>
public sealed class TstInfo
{
    /// <summary>
    /// Hash algorithm OID used for the message imprint.
    /// Must be SHA-256 (2.16.840.1.101.3.4.2.1) for v1.
    /// </summary>
    public required string HashAlgorithmOid { get; init; }

    /// <summary>
    /// The hashed message (message imprint) from the TSA.
    /// For ClaimLedger, this should be SHA256(claim_core_digest_bytes).
    /// </summary>
    public required byte[] HashedMessage { get; init; }

    /// <summary>
    /// The time at which the TSA created the timestamp (genTime).
    /// </summary>
    public required DateTimeOffset GenTime { get; init; }

    /// <summary>
    /// Optional: TSA policy OID.
    /// </summary>
    public string? PolicyOid { get; init; }

    /// <summary>
    /// Optional: Serial number of the token (hex).
    /// </summary>
    public string? SerialNumberHex { get; init; }

    /// <summary>
    /// Optional: Nonce value if present.
    /// </summary>
    public string? NonceHex { get; init; }

    /// <summary>
    /// SHA-256 OID constant.
    /// </summary>
    public const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    /// <summary>
    /// id-ct-TSTInfo OID for RFC 3161 timestamp tokens.
    /// </summary>
    public const string TstInfoContentTypeOid = "1.2.840.113549.1.9.16.1.4";

    /// <summary>
    /// Time Stamping EKU OID.
    /// </summary>
    public const string TimeStampingEkuOid = "1.3.6.1.5.5.7.3.8";

    /// <summary>
    /// Whether the hash algorithm is SHA-256 (required for v1).
    /// </summary>
    public bool IsSha256 => HashAlgorithmOid == Sha256Oid;
}
