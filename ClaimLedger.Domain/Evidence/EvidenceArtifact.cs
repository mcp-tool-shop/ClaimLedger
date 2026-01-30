using ClaimLedger.Domain.Primitives;
using Shared.Crypto;

namespace ClaimLedger.Domain.Evidence;

/// <summary>
/// Reference to evidence supporting a claim.
/// Evidence is referenced by hash, not embedded.
/// The actual artifact may or may not be available - the hash is what matters.
/// </summary>
public sealed class EvidenceArtifact
{
    public EvidenceId Id { get; }
    public string Type { get; }
    public ContentHash Hash { get; }
    public string? Locator { get; }

    public EvidenceArtifact(
        EvidenceId id,
        string type,
        ContentHash hash,
        string? locator = null)
    {
        if (!EvidenceType.IsValid(type))
            throw new ArgumentException($"Invalid evidence type: {type}", nameof(type));

        Id = id;
        Type = EvidenceType.Normalize(type);
        Hash = hash;
        Locator = locator;
    }

    /// <summary>
    /// Creates a new evidence artifact with a generated ID.
    /// </summary>
    public static EvidenceArtifact Create(
        string type,
        ContentHash hash,
        string? locator = null)
    {
        return new EvidenceArtifact(EvidenceId.New(), type, hash, locator);
    }
}
