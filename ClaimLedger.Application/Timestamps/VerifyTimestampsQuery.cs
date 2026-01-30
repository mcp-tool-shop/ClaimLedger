using System.Security.Cryptography.X509Certificates;
using ClaimLedger.Application.Export;
using ClaimLedger.Domain.Timestamps;
using Shared.Crypto;

namespace ClaimLedger.Application.Timestamps;

/// <summary>
/// Query to verify timestamp receipts in a claim bundle.
/// </summary>
public sealed record VerifyTimestampsQuery(
    ClaimBundle Bundle,
    X509Certificate2Collection? TrustAnchors = null,
    bool Strict = false);

/// <summary>
/// Result of verifying a single timestamp receipt.
/// </summary>
public sealed class TimestampCheckResult
{
    public required string ReceiptId { get; init; }
    public required DateTimeOffset IssuedAt { get; init; }
    public required bool IsValid { get; init; }
    public required bool IsTrusted { get; init; }
    public string? TsaSubject { get; init; }
    public string? Warning { get; init; }
    public string? Error { get; init; }

    public static class Reasons
    {
        public const string CmsSignatureInvalid = "CMS_SIGNATURE_INVALID";
        public const string TstInfoParseFailed = "TSTINFO_PARSE_FAILED";
        public const string HashAlgorithmUnsupported = "HASH_ALGORITHM_UNSUPPORTED";
        public const string ImprintMismatch = "IMPRINT_MISMATCH";
        public const string TrustFailed = "TRUST_FAILED";
    }
}

/// <summary>
/// Result of verifying all timestamp receipts.
/// </summary>
public sealed class VerifyTimestampsResult
{
    public required bool AllValid { get; init; }
    public required bool AllTrusted { get; init; }
    public required IReadOnlyList<TimestampCheckResult> Results { get; init; }

    /// <summary>
    /// The earliest trusted timestamp (for priority claims).
    /// </summary>
    public DateTimeOffset? EarliestTrustedTimestamp { get; init; }
}

/// <summary>
/// Handles verification of timestamp receipts.
/// </summary>
public static class VerifyTimestampsHandler
{
    /// <summary>
    /// Verifies all timestamp receipts in a bundle.
    ///
    /// Level 1 (always): Token integrity + binding check
    /// Level 2 (if trust anchors provided): Certificate chain validation
    /// </summary>
    public static VerifyTimestampsResult Handle(VerifyTimestampsQuery query)
    {
        var bundle = query.Bundle;

        // If no timestamp receipts, nothing to verify
        if (bundle.TimestampReceipts == null || bundle.TimestampReceipts.Count == 0)
        {
            return new VerifyTimestampsResult
            {
                AllValid = true,
                AllTrusted = true,
                Results = Array.Empty<TimestampCheckResult>()
            };
        }

        // Compute expected claim_core_digest
        var expectedDigest = ClaimCoreDigest.Compute(bundle);

        var results = new List<TimestampCheckResult>();
        var allValid = true;
        var allTrusted = true;
        DateTimeOffset? earliestTrusted = null;

        foreach (var receiptInfo in bundle.TimestampReceipts)
        {
            var result = VerifyReceipt(receiptInfo, expectedDigest, query.TrustAnchors, query.Strict);
            results.Add(result);

            if (!result.IsValid)
            {
                allValid = false;
            }
            if (!result.IsTrusted)
            {
                allTrusted = false;
            }

            if (result.IsValid && result.IsTrusted)
            {
                if (earliestTrusted == null || result.IssuedAt < earliestTrusted)
                {
                    earliestTrusted = result.IssuedAt;
                }
            }
        }

        return new VerifyTimestampsResult
        {
            AllValid = allValid,
            AllTrusted = allTrusted,
            Results = results,
            EarliestTrustedTimestamp = earliestTrusted
        };
    }

    private static TimestampCheckResult VerifyReceipt(
        TimestampReceiptInfo receiptInfo,
        Digest256 expectedDigest,
        X509Certificate2Collection? trustAnchors,
        bool strict)
    {
        // 1. Decode token from base64
        byte[] tokenDer;
        try
        {
            tokenDer = Convert.FromBase64String(receiptInfo.TsaTokenDerBase64);
        }
        catch
        {
            return new TimestampCheckResult
            {
                ReceiptId = receiptInfo.ReceiptId,
                IssuedAt = DateTimeOffset.MinValue,
                IsValid = false,
                IsTrusted = false,
                Error = "Invalid base64 token data"
            };
        }

        // 2. Decode and verify CMS signature
        var decodeResult = Rfc3161TokenDecoder.DecodeAndVerifySignature(tokenDer);
        if (!decodeResult.Success)
        {
            return new TimestampCheckResult
            {
                ReceiptId = receiptInfo.ReceiptId,
                IssuedAt = DateTimeOffset.MinValue,
                IsValid = false,
                IsTrusted = false,
                Error = $"{TimestampCheckResult.Reasons.CmsSignatureInvalid}: {decodeResult.Error}"
            };
        }

        // 3. Parse TSTInfo
        TstInfo tstInfo;
        try
        {
            tstInfo = TstInfoParser.Parse(decodeResult.TstInfoDer!);
        }
        catch (Exception ex)
        {
            return new TimestampCheckResult
            {
                ReceiptId = receiptInfo.ReceiptId,
                IssuedAt = DateTimeOffset.MinValue,
                IsValid = false,
                IsTrusted = false,
                Error = $"{TimestampCheckResult.Reasons.TstInfoParseFailed}: {ex.Message}"
            };
        }

        // 4. Verify hash algorithm is SHA-256
        if (!tstInfo.IsSha256)
        {
            return new TimestampCheckResult
            {
                ReceiptId = receiptInfo.ReceiptId,
                IssuedAt = tstInfo.GenTime,
                IsValid = false,
                IsTrusted = false,
                Error = $"{TimestampCheckResult.Reasons.HashAlgorithmUnsupported}: {tstInfo.HashAlgorithmOid}"
            };
        }

        // 5. Verify message imprint binding
        var digestBytes = expectedDigest.AsBytes().ToArray();
        var expectedImprint = Digest256.Compute(digestBytes);

        if (!tstInfo.HashedMessage.AsSpan().SequenceEqual(expectedImprint.AsBytes()))
        {
            return new TimestampCheckResult
            {
                ReceiptId = receiptInfo.ReceiptId,
                IssuedAt = tstInfo.GenTime,
                IsValid = false,
                IsTrusted = false,
                Error = TimestampCheckResult.Reasons.ImprintMismatch
            };
        }

        // Level 1 passed - signature valid and binding correct
        var isValid = true;
        var tsaSubject = decodeResult.SignerCertificate?.Subject;

        // 6. Trust verification (Level 2)
        var trustResult = TsaTrustVerifier.VerifyTrust(
            decodeResult.SignerCertificate!,
            tstInfo.GenTime,
            trustAnchors,
            strict);

        if (trustResult.Error != null)
        {
            // In strict mode, trust failure is an error
            return new TimestampCheckResult
            {
                ReceiptId = receiptInfo.ReceiptId,
                IssuedAt = tstInfo.GenTime,
                IsValid = false,
                IsTrusted = false,
                TsaSubject = tsaSubject,
                Error = $"{TimestampCheckResult.Reasons.TrustFailed}: {trustResult.Error}"
            };
        }

        return new TimestampCheckResult
        {
            ReceiptId = receiptInfo.ReceiptId,
            IssuedAt = tstInfo.GenTime,
            IsValid = isValid,
            IsTrusted = trustResult.IsTrusted,
            TsaSubject = tsaSubject,
            Warning = trustResult.Warning
        };
    }
}
