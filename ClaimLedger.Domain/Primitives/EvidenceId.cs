namespace ClaimLedger.Domain.Primitives;

/// <summary>
/// Strongly-typed identifier for an evidence artifact.
/// </summary>
public readonly struct EvidenceId : IEquatable<EvidenceId>
{
    public Guid Value { get; }

    public EvidenceId(Guid value)
    {
        if (value == Guid.Empty)
            throw new ArgumentException("EvidenceId cannot be empty", nameof(value));
        Value = value;
    }

    public static EvidenceId New() => new(Guid.NewGuid());

    public static EvidenceId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string s, out EvidenceId result)
    {
        if (Guid.TryParse(s, out var guid) && guid != Guid.Empty)
        {
            result = new EvidenceId(guid);
            return true;
        }
        result = default;
        return false;
    }

    public override string ToString() => Value.ToString("D");

    public bool Equals(EvidenceId other) => Value.Equals(other.Value);
    public override bool Equals(object? obj) => obj is EvidenceId other && Equals(other);
    public override int GetHashCode() => Value.GetHashCode();

    public static bool operator ==(EvidenceId left, EvidenceId right) => left.Equals(right);
    public static bool operator !=(EvidenceId left, EvidenceId right) => !left.Equals(right);
}
