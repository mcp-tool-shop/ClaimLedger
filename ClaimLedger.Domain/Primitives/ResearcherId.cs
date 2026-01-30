namespace ClaimLedger.Domain.Primitives;

/// <summary>
/// Strongly-typed identifier for a researcher.
/// </summary>
public readonly struct ResearcherId : IEquatable<ResearcherId>
{
    public Guid Value { get; }

    public ResearcherId(Guid value)
    {
        if (value == Guid.Empty)
            throw new ArgumentException("ResearcherId cannot be empty", nameof(value));
        Value = value;
    }

    public static ResearcherId New() => new(Guid.NewGuid());

    public static ResearcherId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string s, out ResearcherId result)
    {
        if (Guid.TryParse(s, out var guid) && guid != Guid.Empty)
        {
            result = new ResearcherId(guid);
            return true;
        }
        result = default;
        return false;
    }

    public override string ToString() => Value.ToString("D");

    public bool Equals(ResearcherId other) => Value.Equals(other.Value);
    public override bool Equals(object? obj) => obj is ResearcherId other && Equals(other);
    public override int GetHashCode() => Value.GetHashCode();

    public static bool operator ==(ResearcherId left, ResearcherId right) => left.Equals(right);
    public static bool operator !=(ResearcherId left, ResearcherId right) => !left.Equals(right);
}
