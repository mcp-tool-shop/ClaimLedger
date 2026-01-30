namespace ClaimLedger.Domain.Timestamps;

/// <summary>
/// Unique identifier for a timestamp receipt.
/// </summary>
public readonly struct TimestampReceiptId : IEquatable<TimestampReceiptId>
{
    private readonly Guid _value;

    private TimestampReceiptId(Guid value) => _value = value;

    public static TimestampReceiptId New() => new(Guid.NewGuid());

    public static TimestampReceiptId Parse(string s) => new(Guid.Parse(s));

    public static bool TryParse(string? s, out TimestampReceiptId result)
    {
        if (Guid.TryParse(s, out var guid))
        {
            result = new TimestampReceiptId(guid);
            return true;
        }
        result = default;
        return false;
    }

    public override string ToString() => _value.ToString();

    public bool Equals(TimestampReceiptId other) => _value.Equals(other._value);
    public override bool Equals(object? obj) => obj is TimestampReceiptId other && Equals(other);
    public override int GetHashCode() => _value.GetHashCode();

    public static bool operator ==(TimestampReceiptId left, TimestampReceiptId right) => left.Equals(right);
    public static bool operator !=(TimestampReceiptId left, TimestampReceiptId right) => !left.Equals(right);
}
