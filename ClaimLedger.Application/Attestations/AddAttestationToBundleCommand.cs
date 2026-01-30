using ClaimLedger.Application.Export;
using ClaimLedger.Domain.Attestations;

namespace ClaimLedger.Application.Attestations;

/// <summary>
/// Command to add an attestation to a claim bundle.
/// </summary>
public sealed record AddAttestationToBundleCommand(
    ClaimBundle Bundle,
    Attestation Attestation);

/// <summary>
/// Handles adding attestations to bundles.
/// </summary>
public static class AddAttestationToBundleHandler
{
    /// <summary>
    /// Returns a new bundle with the attestation added.
    /// Original bundle is unchanged.
    /// </summary>
    public static ClaimBundle Handle(AddAttestationToBundleCommand command)
    {
        var bundle = command.Bundle;
        var attestation = command.Attestation;

        // Convert attestation to info
        var attestationInfo = new AttestationInfo
        {
            AttestationId = attestation.Id.ToString(),
            ClaimCoreDigest = attestation.ClaimCoreDigest.ToString(),
            Attestor = new AttestorInfo
            {
                ResearcherId = attestation.AttestorId.ToString(),
                PublicKey = attestation.AttestorPublicKey.ToString(),
                DisplayName = attestation.AttestorDisplayName
            },
            AttestationType = attestation.Type,
            Statement = attestation.Statement,
            IssuedAtUtc = attestation.IssuedAtUtc.ToString("O"),
            ExpiresAtUtc = attestation.ExpiresAtUtc?.ToString("O"),
            Signature = attestation.Signature.ToString()
        };

        // Build new attestations list
        var existingAttestations = bundle.Attestations ?? Array.Empty<AttestationInfo>();
        var newAttestations = existingAttestations.Append(attestationInfo).ToList();

        // Return new bundle with attestation added
        return new ClaimBundle
        {
            Version = bundle.Version,
            Algorithms = bundle.Algorithms,
            Claim = bundle.Claim,
            Researcher = bundle.Researcher,
            Attestations = newAttestations
        };
    }
}
