using System.Formats.Asn1;
using System.Security.Cryptography;
using ClaimLedger.Application.Export;
using Shared.Crypto;

namespace ClaimLedger.Application.Timestamps;

/// <summary>
/// Command to create an RFC 3161 timestamp request (.tsq) for a claim bundle.
/// </summary>
public sealed record CreateTsaRequestCommand(
    ClaimBundle Bundle,
    bool IncludeCertRequest = true,
    byte[]? Nonce = null);

/// <summary>
/// Handles creation of RFC 3161 timestamp requests.
///
/// The request asks a TSA to timestamp:
///   SHA-256(bytes_from_hex(claim_core_digest))
/// </summary>
public static class CreateTsaRequestHandler
{
    /// <summary>
    /// OID for SHA-256: 2.16.840.1.101.3.4.2.1
    /// </summary>
    private static readonly Oid Sha256Oid = new("2.16.840.1.101.3.4.2.1");

    /// <summary>
    /// Creates an RFC 3161 TimeStampReq (DER-encoded).
    ///
    /// TimeStampReq ::= SEQUENCE {
    ///    version         INTEGER { v1(1) },
    ///    messageImprint  MessageImprint,
    ///    reqPolicy       TSAPolicyId OPTIONAL,
    ///    nonce           INTEGER OPTIONAL,
    ///    certReq         BOOLEAN DEFAULT FALSE,
    ///    extensions      [0] IMPLICIT Extensions OPTIONAL
    /// }
    ///
    /// MessageImprint ::= SEQUENCE {
    ///    hashAlgorithm   AlgorithmIdentifier,
    ///    hashedMessage   OCTET STRING
    /// }
    /// </summary>
    public static byte[] Handle(CreateTsaRequestCommand command)
    {
        // Compute claim_core_digest
        var coreDigest = ClaimCoreDigest.Compute(command.Bundle);

        // Compute message imprint: SHA256(claim_core_digest_bytes)
        var digestBytes = coreDigest.AsBytes().ToArray();
        var messageImprint = SHA256.HashData(digestBytes);

        // Build the ASN.1 request
        var writer = new AsnWriter(AsnEncodingRules.DER);

        // TimeStampReq SEQUENCE
        using (writer.PushSequence())
        {
            // version INTEGER (1)
            writer.WriteInteger(1);

            // messageImprint SEQUENCE
            using (writer.PushSequence())
            {
                // hashAlgorithm AlgorithmIdentifier SEQUENCE
                using (writer.PushSequence())
                {
                    // algorithm OID
                    writer.WriteObjectIdentifier(Sha256Oid.Value!);
                    // parameters NULL (implicit for SHA-256)
                    writer.WriteNull();
                }

                // hashedMessage OCTET STRING
                writer.WriteOctetString(messageImprint);
            }

            // nonce INTEGER (optional)
            if (command.Nonce != null && command.Nonce.Length > 0)
            {
                writer.WriteInteger(new System.Numerics.BigInteger(command.Nonce, isUnsigned: true, isBigEndian: true));
            }

            // certReq BOOLEAN (only if true, since default is false)
            if (command.IncludeCertRequest)
            {
                writer.WriteBoolean(true);
            }
        }

        return writer.Encode();
    }
}
