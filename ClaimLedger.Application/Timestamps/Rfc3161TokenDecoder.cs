using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ClaimLedger.Domain.Timestamps;

namespace ClaimLedger.Application.Timestamps;

/// <summary>
/// Decodes and verifies RFC 3161 timestamp tokens.
///
/// Uses System.Security.Cryptography.Pkcs.SignedCms for CMS parsing
/// and signature verification.
/// </summary>
public static class Rfc3161TokenDecoder
{
    /// <summary>
    /// Result of decoding a timestamp token.
    /// </summary>
    public sealed class DecodeResult
    {
        public required bool Success { get; init; }
        public string? Error { get; init; }
        public SignedCms? Cms { get; init; }
        public byte[]? TstInfoDer { get; init; }
        public X509Certificate2? SignerCertificate { get; init; }
    }

    /// <summary>
    /// Normalizes input token bytes from various formats:
    /// - Raw DER bytes
    /// - PEM-wrapped base64
    /// - Plain base64 text
    /// </summary>
    public static byte[] NormalizeTokenBytes(byte[] input)
    {
        // Check if it's PEM format
        var text = Encoding.ASCII.GetString(input);
        if (text.Contains("-----BEGIN"))
        {
            return ExtractFromPem(text);
        }

        // Check if it looks like base64 (all printable ASCII, no binary)
        if (IsLikelyBase64(input))
        {
            try
            {
                return Convert.FromBase64String(text.Trim());
            }
            catch
            {
                // Not valid base64, treat as raw DER
            }
        }

        // Assume raw DER
        return input;
    }

    /// <summary>
    /// Decodes a timestamp token and verifies its CMS signature.
    /// Does NOT verify trust chain - only that the signature is valid
    /// using the embedded signer certificate.
    /// </summary>
    public static DecodeResult DecodeAndVerifySignature(byte[] tokenDer)
    {
        try
        {
            var cms = new SignedCms();
            cms.Decode(tokenDer);

            // Verify content type is TSTInfo
            if (cms.ContentInfo.ContentType.Value != TstInfo.TstInfoContentTypeOid)
            {
                return new DecodeResult
                {
                    Success = false,
                    Error = $"Invalid content type: expected {TstInfo.TstInfoContentTypeOid}, got {cms.ContentInfo.ContentType.Value}"
                };
            }

            // Verify CMS signature (signature only, no trust validation)
            try
            {
                cms.CheckSignature(verifySignatureOnly: true);
            }
            catch (CryptographicException ex)
            {
                return new DecodeResult
                {
                    Success = false,
                    Error = $"CMS signature verification failed: {ex.Message}"
                };
            }

            // Extract signer certificate
            if (cms.SignerInfos.Count == 0)
            {
                return new DecodeResult
                {
                    Success = false,
                    Error = "No signer information in CMS"
                };
            }

            var signerCert = cms.SignerInfos[0].Certificate;
            if (signerCert == null)
            {
                return new DecodeResult
                {
                    Success = false,
                    Error = "No signer certificate embedded in CMS"
                };
            }

            return new DecodeResult
            {
                Success = true,
                Cms = cms,
                TstInfoDer = cms.ContentInfo.Content,
                SignerCertificate = signerCert
            };
        }
        catch (CryptographicException ex)
        {
            return new DecodeResult
            {
                Success = false,
                Error = $"Failed to decode CMS: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Extracts TSA metadata from the signer certificate.
    /// </summary>
    public static TsaInfo ExtractTsaInfo(X509Certificate2 signerCert, TstInfo tstInfo)
    {
        // Compute SHA-256 fingerprint of the certificate
        var certBytes = signerCert.RawData;
        var fingerprint = SHA256.HashData(certBytes);

        return new TsaInfo
        {
            PolicyOid = tstInfo.PolicyOid,
            SerialNumberHex = tstInfo.SerialNumberHex,
            CertFingerprintSha256Hex = Convert.ToHexString(fingerprint).ToLowerInvariant(),
            CertSubject = signerCert.Subject
        };
    }

    private static byte[] ExtractFromPem(string pem)
    {
        // Find base64 content between PEM headers
        var lines = pem.Split('\n')
            .Select(l => l.Trim())
            .Where(l => !l.StartsWith("-----", StringComparison.Ordinal))
            .ToList();

        var base64 = string.Join("", lines);
        return Convert.FromBase64String(base64);
    }

    private static bool IsLikelyBase64(byte[] data)
    {
        if (data.Length == 0) return false;

        // Check if all bytes are printable ASCII (base64 characters)
        foreach (var b in data)
        {
            if (b < 0x20 || b > 0x7E)
            {
                // Allow newlines and carriage returns
                if (b != 0x0A && b != 0x0D)
                    return false;
            }
        }

        return true;
    }
}
