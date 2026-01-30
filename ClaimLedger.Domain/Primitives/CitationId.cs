namespace ClaimLedger.Domain.Primitives;

/// <summary>
/// Strongly-typed citation identifier.
/// </summary>
public readonly struct CitationId : IEquatable<CitationId>
{
    public Guid Value { get; }

    public CitationId(Guid value)
    {
        if (value == Guid.Empty)
            throw new ArgumentException("CitationId cannot be empty", nameof(value));
        Value = value;
    }

    public static CitationId New() => new(Guid.NewGuid());

    public static CitationId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string s, out CitationId result)
    {
        if (Guid.TryParse(s, out var guid) && guid != Guid.Empty)
        {
            result = new CitationId(guid);
            return true;
        }
        result = default;
        return false;
    }

    public bool Equals(CitationId other) => Value.Equals(other.Value);
    public override bool Equals(object? obj) => obj is CitationId other && Equals(other);
    public override int GetHashCode() => Value.GetHashCode();
    public override string ToString() => Value.ToString();

    public static bool operator ==(CitationId left, CitationId right) => left.Equals(right);
    public static bool operator !=(CitationId left, CitationId right) => !left.Equals(right);
}
