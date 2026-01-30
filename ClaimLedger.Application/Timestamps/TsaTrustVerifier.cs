using System.Security.Cryptography.X509Certificates;
using ClaimLedger.Domain.Timestamps;

namespace ClaimLedger.Application.Timestamps;

/// <summary>
/// Verifies TSA certificate trust chains.
///
/// OFFLINE ONLY: No OCSP or CRL fetching.
/// Trust anchors must be provided locally via --tsa-trust-dir.
/// </summary>
public static class TsaTrustVerifier
{
    /// <summary>
    /// Result of trust verification.
    /// </summary>
    public sealed class TrustResult
    {
        public required bool IsTrusted { get; init; }
        public string? Warning { get; init; }
        public string? Error { get; init; }

        /// <summary>
        /// The certificate chain that was built (if successful).
        /// </summary>
        public IReadOnlyList<string>? ChainSubjects { get; init; }

        public static TrustResult Trusted(IReadOnlyList<string>? chain = null) =>
            new() { IsTrusted = true, ChainSubjects = chain };

        public static TrustResult Untrusted(string warning) =>
            new() { IsTrusted = false, Warning = warning };

        public static TrustResult Failed(string error) =>
            new() { IsTrusted = false, Error = error };
    }

    /// <summary>
    /// Verifies the TSA signer certificate against provided trust anchors.
    /// </summary>
    /// <param name="signerCert">The TSA signer certificate.</param>
    /// <param name="genTime">The timestamp from the token (for validity check).</param>
    /// <param name="trustAnchors">Trusted root and intermediate certificates.</param>
    /// <param name="strict">If true, any chain failure is an error; otherwise it's a warning.</param>
    public static TrustResult VerifyTrust(
        X509Certificate2 signerCert,
        DateTimeOffset genTime,
        X509Certificate2Collection? trustAnchors,
        bool strict)
    {
        // If no trust anchors provided, we can only do Level 1 verification
        if (trustAnchors == null || trustAnchors.Count == 0)
        {
            if (strict)
            {
                return TrustResult.Failed("No trust anchors provided and --strict-tsa is enabled");
            }
            return TrustResult.Untrusted("No trust anchors provided; TSA certificate not verified");
        }

        // Check certificate validity at genTime
        if (genTime < signerCert.NotBefore || genTime > signerCert.NotAfter)
        {
            var msg = $"Signer certificate was not valid at timestamp time ({genTime:O}). " +
                      $"Certificate valid from {signerCert.NotBefore:O} to {signerCert.NotAfter:O}";
            if (strict)
            {
                return TrustResult.Failed(msg);
            }
            return TrustResult.Untrusted(msg);
        }

        // Check for Time Stamping EKU
        var hasTimeStampingEku = false;
        foreach (var ext in signerCert.Extensions)
        {
            if (ext is X509EnhancedKeyUsageExtension eku)
            {
                foreach (var oid in eku.EnhancedKeyUsages)
                {
                    if (oid.Value == TstInfo.TimeStampingEkuOid)
                    {
                        hasTimeStampingEku = true;
                        break;
                    }
                }
            }
        }

        if (!hasTimeStampingEku)
        {
            var msg = "Signer certificate does not have Time Stamping EKU (1.3.6.1.5.5.7.3.8)";
            if (strict)
            {
                return TrustResult.Failed(msg);
            }
            // Warning only in non-strict mode (some TSAs don't use EKU)
        }

        // Build certificate chain
        using var chain = new X509Chain();

        // Configure chain policy for offline verification
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = genTime.UtcDateTime;

        // Use custom root trust (net8.0 feature)
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

        // Separate roots from intermediates
        foreach (var cert in trustAnchors)
        {
            // Self-signed certificates are roots
            if (cert.Subject == cert.Issuer)
            {
                chain.ChainPolicy.CustomTrustStore.Add(cert);
            }
            else
            {
                chain.ChainPolicy.ExtraStore.Add(cert);
            }
        }

        // Build the chain
        var chainBuilt = chain.Build(signerCert);

        // Collect chain subjects for reporting
        var chainSubjects = chain.ChainElements
            .Select(e => e.Certificate.Subject)
            .ToList();

        if (!chainBuilt)
        {
            // Check what failed
            var statusMessages = chain.ChainStatus
                .Select(s => s.StatusInformation)
                .Where(s => !string.IsNullOrEmpty(s))
                .ToList();

            var msg = $"Certificate chain validation failed: {string.Join("; ", statusMessages)}";

            if (strict)
            {
                return TrustResult.Failed(msg);
            }
            return TrustResult.Untrusted(msg);
        }

        return TrustResult.Trusted(chainSubjects);
    }

    /// <summary>
    /// Loads certificates from a directory.
    /// Supports .cer, .crt, .pem, .der files.
    /// </summary>
    public static X509Certificate2Collection LoadCertificatesFromDirectory(string directoryPath)
    {
        var collection = new X509Certificate2Collection();

        if (!Directory.Exists(directoryPath))
        {
            return collection;
        }

        var extensions = new[] { "*.cer", "*.crt", "*.pem", "*.der" };

        foreach (var pattern in extensions)
        {
            foreach (var file in Directory.GetFiles(directoryPath, pattern))
            {
                try
                {
                    var cert = LoadCertificate(file);
                    if (cert != null)
                    {
                        collection.Add(cert);
                    }
                }
                catch
                {
                    // Skip invalid certificates
                }
            }
        }

        return collection;
    }

    private static X509Certificate2? LoadCertificate(string filePath)
    {
        var bytes = File.ReadAllBytes(filePath);

        // Try to detect format
        var text = System.Text.Encoding.ASCII.GetString(bytes);
        if (text.Contains("-----BEGIN CERTIFICATE-----"))
        {
            // PEM format
            return X509Certificate2.CreateFromPem(text);
        }

        // Try DER format
        return new X509Certificate2(bytes);
    }
}
