namespace ClaimLedger.Domain.Primitives;

/// <summary>
/// Strongly-typed identifier for a scientific claim.
/// </summary>
public readonly struct ClaimId : IEquatable<ClaimId>
{
    public Guid Value { get; }

    public ClaimId(Guid value)
    {
        if (value == Guid.Empty)
            throw new ArgumentException("ClaimId cannot be empty", nameof(value));
        Value = value;
    }

    public static ClaimId New() => new(Guid.NewGuid());

    public static ClaimId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string s, out ClaimId result)
    {
        if (Guid.TryParse(s, out var guid) && guid != Guid.Empty)
        {
            result = new ClaimId(guid);
            return true;
        }
        result = default;
        return false;
    }

    public override string ToString() => Value.ToString("D");

    public bool Equals(ClaimId other) => Value.Equals(other.Value);
    public override bool Equals(object? obj) => obj is ClaimId other && Equals(other);
    public override int GetHashCode() => Value.GetHashCode();

    public static bool operator ==(ClaimId left, ClaimId right) => left.Equals(right);
    public static bool operator !=(ClaimId left, ClaimId right) => !left.Equals(right);
}
