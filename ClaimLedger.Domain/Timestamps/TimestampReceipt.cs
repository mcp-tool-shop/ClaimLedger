using Shared.Crypto;

namespace ClaimLedger.Domain.Timestamps;

/// <summary>
/// RFC 3161 timestamp receipt attached to a claim bundle.
///
/// CONTRACT: TimestampReceiptRFC3161.v1
///
/// A timestamp receipt proves that a TSA witnessed the claim_core_digest
/// at a specific point in time.
///
/// The message imprint is:
///   SHA-256(bytes_from_hex(claim_core_digest))
///
/// This is NOT the claim JSON, but the digest-of-digest for stability.
/// </summary>
public sealed class TimestampReceipt
{
    /// <summary>
    /// Contract version. Frozen.
    /// </summary>
    public const string ContractVersion = "TimestampReceiptRFC3161.v1";

    /// <summary>
    /// Unique identifier for this receipt.
    /// </summary>
    public TimestampReceiptId ReceiptId { get; }

    /// <summary>
    /// The claim_core_digest this receipt timestamps.
    /// </summary>
    public Digest256 ClaimCoreDigest { get; }

    /// <summary>
    /// The message imprint = SHA256(claim_core_digest_bytes).
    /// Stored for verification without recomputation.
    /// </summary>
    public byte[] MessageImprint { get; }

    /// <summary>
    /// Raw DER-encoded TSA token (CMS SignedData containing TSTInfo).
    /// </summary>
    public byte[] TokenDer { get; }

    /// <summary>
    /// Parsed TSTInfo from the token.
    /// </summary>
    public TstInfo TstInfo { get; }

    /// <summary>
    /// TSA metadata extracted from the token.
    /// </summary>
    public TsaInfo Tsa { get; }

    private TimestampReceipt(
        TimestampReceiptId receiptId,
        Digest256 claimCoreDigest,
        byte[] messageImprint,
        byte[] tokenDer,
        TstInfo tstInfo,
        TsaInfo tsa)
    {
        ReceiptId = receiptId;
        ClaimCoreDigest = claimCoreDigest;
        MessageImprint = messageImprint;
        TokenDer = tokenDer;
        TstInfo = tstInfo;
        Tsa = tsa;
    }

    /// <summary>
    /// Creates a timestamp receipt from a validated TSA token.
    /// </summary>
    /// <param name="claimCoreDigest">The claim_core_digest being timestamped.</param>
    /// <param name="tokenDer">The raw DER-encoded TSA token.</param>
    /// <param name="tstInfo">Parsed TSTInfo from the token.</param>
    /// <param name="tsa">TSA metadata from the token.</param>
    /// <returns>A new TimestampReceipt.</returns>
    public static TimestampReceipt Create(
        Digest256 claimCoreDigest,
        byte[] tokenDer,
        TstInfo tstInfo,
        TsaInfo tsa)
    {
        // Compute expected message imprint: SHA256(claim_core_digest_bytes)
        var digestBytes = claimCoreDigest.AsBytes().ToArray();
        var expectedImprint = Digest256.Compute(digestBytes);

        return new TimestampReceipt(
            TimestampReceiptId.New(),
            claimCoreDigest,
            expectedImprint.AsBytes().ToArray(),
            tokenDer,
            tstInfo,
            tsa);
    }

    /// <summary>
    /// Reconstitutes a receipt from stored data (e.g., from bundle JSON).
    /// </summary>
    public static TimestampReceipt FromStored(
        TimestampReceiptId receiptId,
        Digest256 claimCoreDigest,
        byte[] messageImprint,
        byte[] tokenDer,
        TstInfo tstInfo,
        TsaInfo tsa)
    {
        return new TimestampReceipt(
            receiptId,
            claimCoreDigest,
            messageImprint,
            tokenDer,
            tstInfo,
            tsa);
    }

    /// <summary>
    /// Verifies that the token's message imprint matches our claim_core_digest.
    /// </summary>
    public bool VerifyBinding()
    {
        // Expected: SHA256(claim_core_digest_bytes)
        var digestBytes = ClaimCoreDigest.AsBytes().ToArray();
        var expectedImprint = Digest256.Compute(digestBytes);

        // Compare with token's imprint
        return TstInfo.HashedMessage.AsSpan().SequenceEqual(expectedImprint.AsBytes());
    }

    /// <summary>
    /// The timestamp from the TSA (genTime).
    /// </summary>
    public DateTimeOffset IssuedAt => TstInfo.GenTime;
}

/// <summary>
/// TSA metadata extracted from the token.
/// </summary>
public sealed class TsaInfo
{
    /// <summary>
    /// TSA policy OID (if present).
    /// </summary>
    public string? PolicyOid { get; init; }

    /// <summary>
    /// Token serial number (hex).
    /// </summary>
    public string? SerialNumberHex { get; init; }

    /// <summary>
    /// SHA-256 fingerprint of the signer certificate (hex).
    /// </summary>
    public string? CertFingerprintSha256Hex { get; init; }

    /// <summary>
    /// Subject name from the signer certificate.
    /// </summary>
    public string? CertSubject { get; init; }
}
