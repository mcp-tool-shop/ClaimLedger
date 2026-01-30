using ClaimLedger.Application.Export;
using ClaimLedger.Domain.Timestamps;

namespace ClaimLedger.Application.Timestamps;

/// <summary>
/// Command to add a timestamp receipt to a bundle.
/// </summary>
public sealed record AddTimestampToBundleCommand(
    ClaimBundle Bundle,
    TimestampReceipt Receipt);

/// <summary>
/// Handles adding a timestamp receipt to a bundle.
/// </summary>
public static class AddTimestampToBundleHandler
{
    /// <summary>
    /// Adds a timestamp receipt to a bundle, returning a new bundle with the receipt appended.
    /// </summary>
    public static ClaimBundle Handle(AddTimestampToBundleCommand command)
    {
        var receipt = command.Receipt;

        var receiptInfo = new TimestampReceiptInfo
        {
            ReceiptId = receipt.ReceiptId.ToString(),
            Subject = new TimestampSubjectInfo
            {
                DigestHex = receipt.ClaimCoreDigest.ToString()
            },
            MessageImprintHex = Convert.ToHexString(receipt.MessageImprint).ToLowerInvariant(),
            TsaTokenDerBase64 = Convert.ToBase64String(receipt.TokenDer),
            IssuedAt = receipt.IssuedAt.ToString("O"),
            Tsa = new TimestampTsaInfo
            {
                PolicyOid = receipt.Tsa.PolicyOid,
                SerialNumberHex = receipt.Tsa.SerialNumberHex,
                CertFingerprintSha256Hex = receipt.Tsa.CertFingerprintSha256Hex
            }
        };

        // Append to existing receipts
        var existingReceipts = command.Bundle.TimestampReceipts ?? Array.Empty<TimestampReceiptInfo>();
        var newReceipts = existingReceipts.Append(receiptInfo).ToList();

        return new ClaimBundle
        {
            Version = command.Bundle.Version,
            Algorithms = command.Bundle.Algorithms,
            Claim = command.Bundle.Claim,
            Researcher = command.Bundle.Researcher,
            Citations = command.Bundle.Citations,
            Attestations = command.Bundle.Attestations,
            TimestampReceipts = newReceipts
        };
    }
}
