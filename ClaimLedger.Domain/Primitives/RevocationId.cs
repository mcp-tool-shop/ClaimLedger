namespace ClaimLedger.Domain.Primitives;

/// <summary>
/// Strongly-typed revocation identifier.
/// </summary>
public readonly struct RevocationId : IEquatable<RevocationId>
{
    public Guid Value { get; }

    public RevocationId(Guid value)
    {
        if (value == Guid.Empty)
            throw new ArgumentException("RevocationId cannot be empty", nameof(value));
        Value = value;
    }

    public static RevocationId New() => new(Guid.NewGuid());

    public static RevocationId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string s, out RevocationId result)
    {
        if (Guid.TryParse(s, out var guid) && guid != Guid.Empty)
        {
            result = new RevocationId(guid);
            return true;
        }
        result = default;
        return false;
    }

    public bool Equals(RevocationId other) => Value.Equals(other.Value);
    public override bool Equals(object? obj) => obj is RevocationId other && Equals(other);
    public override int GetHashCode() => Value.GetHashCode();
    public override string ToString() => Value.ToString();

    public static bool operator ==(RevocationId left, RevocationId right) => left.Equals(right);
    public static bool operator !=(RevocationId left, RevocationId right) => !left.Equals(right);
}
