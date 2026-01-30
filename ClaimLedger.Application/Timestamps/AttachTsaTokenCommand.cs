using ClaimLedger.Application.Export;
using ClaimLedger.Domain.Timestamps;
using Shared.Crypto;

namespace ClaimLedger.Application.Timestamps;

/// <summary>
/// Command to attach a TSA token to a claim bundle.
/// </summary>
public sealed record AttachTsaTokenCommand(
    ClaimBundle Bundle,
    byte[] TokenBytes);

/// <summary>
/// Result of attaching a TSA token.
/// </summary>
public sealed class AttachTsaTokenResult
{
    public required bool Success { get; init; }
    public string? Error { get; init; }
    public TimestampReceipt? Receipt { get; init; }
}

/// <summary>
/// Handles attaching a TSA token to a claim bundle.
/// </summary>
public static class AttachTsaTokenHandler
{
    /// <summary>
    /// Attaches a TSA token to a claim bundle.
    ///
    /// Steps:
    /// 1. Normalize token input (PEM, base64, DER)
    /// 2. Decode and verify CMS signature
    /// 3. Parse TSTInfo
    /// 4. Verify message imprint matches claim_core_digest
    /// 5. Create TimestampReceipt
    /// </summary>
    public static AttachTsaTokenResult Handle(AttachTsaTokenCommand command)
    {
        // 1. Normalize token bytes
        byte[] tokenDer;
        try
        {
            tokenDer = Rfc3161TokenDecoder.NormalizeTokenBytes(command.TokenBytes);
        }
        catch (Exception ex)
        {
            return new AttachTsaTokenResult
            {
                Success = false,
                Error = $"Failed to normalize token: {ex.Message}"
            };
        }

        // 2. Decode and verify CMS signature
        var decodeResult = Rfc3161TokenDecoder.DecodeAndVerifySignature(tokenDer);
        if (!decodeResult.Success)
        {
            return new AttachTsaTokenResult
            {
                Success = false,
                Error = decodeResult.Error
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
            return new AttachTsaTokenResult
            {
                Success = false,
                Error = $"Failed to parse TSTInfo: {ex.Message}"
            };
        }

        // 4. Verify hash algorithm is SHA-256 (v1 requirement)
        if (!tstInfo.IsSha256)
        {
            return new AttachTsaTokenResult
            {
                Success = false,
                Error = $"Unsupported hash algorithm: {tstInfo.HashAlgorithmOid}. Only SHA-256 is supported in v1."
            };
        }

        // 5. Compute expected message imprint and verify binding
        var coreDigest = ClaimCoreDigest.Compute(command.Bundle);
        var digestBytes = coreDigest.AsBytes().ToArray();
        var expectedImprint = Digest256.Compute(digestBytes);

        if (!tstInfo.HashedMessage.AsSpan().SequenceEqual(expectedImprint.AsBytes()))
        {
            return new AttachTsaTokenResult
            {
                Success = false,
                Error = "Message imprint mismatch: token does not match claim_core_digest"
            };
        }

        // 6. Extract TSA info
        var tsaInfo = Rfc3161TokenDecoder.ExtractTsaInfo(decodeResult.SignerCertificate!, tstInfo);

        // 7. Create receipt
        var receipt = TimestampReceipt.Create(coreDigest, tokenDer, tstInfo, tsaInfo);

        return new AttachTsaTokenResult
        {
            Success = true,
            Receipt = receipt
        };
    }
}
