using ClaimLedger.Application.Primitives;

namespace ClaimLedger.Tests.Fakes;

/// <summary>
/// Deterministic clock for testing.
/// </summary>
public sealed class FakeClock : IClock
{
    public DateTimeOffset UtcNow { get; set; } = new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero);

    public void Advance(TimeSpan duration) => UtcNow = UtcNow.Add(duration);
}
