using System.Formats.Asn1;
using System.Globalization;
using ClaimLedger.Domain.Timestamps;

namespace ClaimLedger.Application.Timestamps;

/// <summary>
/// Parses TSTInfo (RFC 3161) from DER-encoded ASN.1.
///
/// TSTInfo ::= SEQUENCE {
///    version         INTEGER { v1(1) },
///    policy          TSAPolicyId,
///    messageImprint  MessageImprint,
///    serialNumber    INTEGER,
///    genTime         GeneralizedTime,
///    accuracy        [0] Accuracy OPTIONAL,
///    ordering        BOOLEAN DEFAULT FALSE,
///    nonce           INTEGER OPTIONAL,
///    tsa             [1] GeneralName OPTIONAL,
///    extensions      [2] IMPLICIT Extensions OPTIONAL
/// }
///
/// MessageImprint ::= SEQUENCE {
///    hashAlgorithm   AlgorithmIdentifier,
///    hashedMessage   OCTET STRING
/// }
/// </summary>
public static class TstInfoParser
{
    /// <summary>
    /// Parses TSTInfo from DER-encoded bytes.
    /// </summary>
    public static TstInfo Parse(ReadOnlyMemory<byte> tstInfoDer)
    {
        var reader = new AsnReader(tstInfoDer, AsnEncodingRules.DER);

        // TSTInfo is a SEQUENCE
        var tstInfoReader = reader.ReadSequence();

        // version INTEGER
        _ = tstInfoReader.ReadInteger(); // Skip version, should be 1

        // policy TSAPolicyId (OID)
        var policyOid = tstInfoReader.ReadObjectIdentifier();

        // messageImprint SEQUENCE
        var messageImprintReader = tstInfoReader.ReadSequence();

        // hashAlgorithm AlgorithmIdentifier SEQUENCE
        var hashAlgReader = messageImprintReader.ReadSequence();
        var hashAlgOid = hashAlgReader.ReadObjectIdentifier();

        // Skip optional algorithm parameters (often NULL or absent)
        if (hashAlgReader.HasData)
        {
            hashAlgReader.ReadEncodedValue(); // consume any remaining data
        }

        // hashedMessage OCTET STRING
        var hashedMessage = messageImprintReader.ReadOctetString();

        // serialNumber INTEGER
        var serialNumber = tstInfoReader.ReadInteger();
        var serialNumberHex = serialNumber.ToByteArray(isUnsigned: true, isBigEndian: true);

        // genTime GeneralizedTime
        var genTime = tstInfoReader.ReadGeneralizedTime();

        // Optional fields - we only care about nonce
        string? nonceHex = null;

        // Try to read optional fields
        while (tstInfoReader.HasData)
        {
            var tag = tstInfoReader.PeekTag();

            if (tag == Asn1Tag.Sequence)
            {
                // accuracy - skip it
                tstInfoReader.ReadSequence();
            }
            else if (tag == Asn1Tag.Boolean)
            {
                // ordering - skip it
                tstInfoReader.ReadBoolean();
            }
            else if (tag == Asn1Tag.Integer)
            {
                // nonce INTEGER
                var nonce = tstInfoReader.ReadInteger();
                nonceHex = Convert.ToHexString(nonce.ToByteArray(isUnsigned: true, isBigEndian: true));
            }
            else if (tag.TagClass == TagClass.ContextSpecific)
            {
                // Context-specific tags [0], [1], [2] - skip them
                tstInfoReader.ReadEncodedValue();
            }
            else
            {
                // Unknown, skip
                tstInfoReader.ReadEncodedValue();
            }
        }

        return new TstInfo
        {
            HashAlgorithmOid = hashAlgOid,
            HashedMessage = hashedMessage,
            GenTime = genTime,
            PolicyOid = policyOid,
            SerialNumberHex = Convert.ToHexString(serialNumberHex),
            NonceHex = nonceHex
        };
    }
}
