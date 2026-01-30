using System.Globalization;
using ClaimLedger.Application.Export;
using ClaimLedger.Domain.Citations;
using ClaimLedger.Domain.Primitives;
using Shared.Crypto;

namespace ClaimLedger.Application.Citations;

/// <summary>
/// Query to verify all citations in a claim bundle.
/// </summary>
public sealed record VerifyCitationsQuery(
    ClaimBundle Bundle,
    bool StrictMode = false,
    IReadOnlyDictionary<string, ClaimBundle>? ResolvedBundles = null);

/// <summary>
/// Result of citation verification.
/// </summary>
public sealed class CitationVerificationResult
{
    public required bool AllValid { get; init; }
    public required IReadOnlyList<CitationCheckResult> Results { get; init; }
    public required IReadOnlyList<string> UnresolvedDigests { get; init; }
}

/// <summary>
/// Result of checking a single citation.
/// </summary>
public sealed class CitationCheckResult
{
    public required string CitationId { get; init; }
    public required string CitedDigest { get; init; }
    public required bool IsValid { get; init; }
    public required bool IsResolved { get; init; }
    public string? FailureReason { get; init; }

    public static class Reasons
    {
        public const string SignatureInvalid = "SIGNATURE_INVALID";
        public const string InvalidRelation = "INVALID_RELATION";
        public const string EmbeddedDigestMismatch = "EMBEDDED_DIGEST_MISMATCH";
        public const string Unresolved = "UNRESOLVED";
    }
}

/// <summary>
/// Handler for verifying citations.
/// </summary>
public static class VerifyCitationsHandler
{
    public static CitationVerificationResult Handle(VerifyCitationsQuery query)
    {
        var bundle = query.Bundle;

        if (bundle.Citations == null || bundle.Citations.Count == 0)
        {
            return new CitationVerificationResult
            {
                AllValid = true,
                Results = Array.Empty<CitationCheckResult>(),
                UnresolvedDigests = Array.Empty<string>()
            };
        }

        var results = new List<CitationCheckResult>();
        var unresolvedDigests = new List<string>();
        var signerPublicKey = Ed25519PublicKey.Parse(bundle.Researcher.PublicKey);
        var signerId = ResearcherId.Parse(bundle.Researcher.ResearcherId);

        foreach (var citation in bundle.Citations)
        {
            var result = VerifyCitation(
                citation,
                signerPublicKey,
                signerId,
                query.ResolvedBundles);

            results.Add(result);

            if (!result.IsResolved)
            {
                unresolvedDigests.Add(citation.CitedClaimCoreDigest);
            }
        }

        var allValid = results.All(r => r.IsValid);

        // In strict mode, unresolved citations are failures
        if (query.StrictMode && unresolvedDigests.Count > 0)
        {
            allValid = false;
        }

        return new CitationVerificationResult
        {
            AllValid = allValid,
            Results = results,
            UnresolvedDigests = unresolvedDigests
        };
    }

    private static CitationCheckResult VerifyCitation(
        CitationInfo citation,
        Ed25519PublicKey signerPublicKey,
        ResearcherId signerId,
        IReadOnlyDictionary<string, ClaimBundle>? resolvedBundles)
    {
        // Check relation is valid
        if (!CitationRelation.IsValid(citation.Relation))
        {
            return new CitationCheckResult
            {
                CitationId = citation.CitationId,
                CitedDigest = citation.CitedClaimCoreDigest,
                IsValid = false,
                IsResolved = false,
                FailureReason = CitationCheckResult.Reasons.InvalidRelation
            };
        }

        // Verify signature
        var citationId = CitationId.Parse(citation.CitationId);
        var citedDigest = Digest256.Parse(citation.CitedClaimCoreDigest);
        var issuedAt = DateTimeOffset.Parse(citation.IssuedAtUtc, CultureInfo.InvariantCulture);
        var signature = Ed25519Signature.Parse(citation.Signature);

        var reconstructed = Citation.Reconstitute(
            citationId,
            citedDigest,
            citation.Relation,
            citation.Locator,
            citation.Notes,
            issuedAt,
            signerId,
            signerPublicKey,
            signature);

        if (!reconstructed.VerifySignature())
        {
            return new CitationCheckResult
            {
                CitationId = citation.CitationId,
                CitedDigest = citation.CitedClaimCoreDigest,
                IsValid = false,
                IsResolved = false,
                FailureReason = CitationCheckResult.Reasons.SignatureInvalid
            };
        }

        // Check embedded bundle if present
        bool isResolved = false;
        if (citation.Embedded != null)
        {
            var embeddedDigest = ClaimCoreDigest.Compute(citation.Embedded);
            if (embeddedDigest.ToString() != citation.CitedClaimCoreDigest)
            {
                return new CitationCheckResult
                {
                    CitationId = citation.CitationId,
                    CitedDigest = citation.CitedClaimCoreDigest,
                    IsValid = false,
                    IsResolved = false,
                    FailureReason = CitationCheckResult.Reasons.EmbeddedDigestMismatch
                };
            }
            isResolved = true;
        }

        // Check resolved bundles from resolver
        if (!isResolved && resolvedBundles != null &&
            resolvedBundles.TryGetValue(citation.CitedClaimCoreDigest, out var resolved))
        {
            var resolvedDigest = ClaimCoreDigest.Compute(resolved);
            if (resolvedDigest.ToString() == citation.CitedClaimCoreDigest)
            {
                isResolved = true;
            }
        }

        return new CitationCheckResult
        {
            CitationId = citation.CitationId,
            CitedDigest = citation.CitedClaimCoreDigest,
            IsValid = true,
            IsResolved = isResolved
        };
    }
}
