namespace ClaimLedger.Domain.Primitives;

/// <summary>
/// Strongly-typed identifier for an attestation.
/// </summary>
public readonly struct AttestationId : IEquatable<AttestationId>
{
    public Guid Value { get; }

    public AttestationId(Guid value)
    {
        if (value == Guid.Empty)
            throw new ArgumentException("AttestationId cannot be empty", nameof(value));
        Value = value;
    }

    public static AttestationId New() => new(Guid.NewGuid());

    public static AttestationId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string s, out AttestationId result)
    {
        if (Guid.TryParse(s, out var guid) && guid != Guid.Empty)
        {
            result = new AttestationId(guid);
            return true;
        }
        result = default;
        return false;
    }

    public override string ToString() => Value.ToString("D");

    public bool Equals(AttestationId other) => Value.Equals(other.Value);
    public override bool Equals(object? obj) => obj is AttestationId other && Equals(other);
    public override int GetHashCode() => Value.GetHashCode();

    public static bool operator ==(AttestationId left, AttestationId right) => left.Equals(right);
    public static bool operator !=(AttestationId left, AttestationId right) => !left.Equals(right);
}
