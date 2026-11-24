namespace eDocumentReader.Core.Transport;

public enum CardInterface { Unknown, Contact, Contactless }

/// <summary>Raw byte transport to a card (PC/SC, simulator, replay). No APDU semantics, no retries.</summary>
public interface ICardTransport : IDisposable
{
    string Name { get; }
    byte[] Atr { get; }
    /// <summary>Negotiated transmission protocol ("T=0", "T=1", ...).</summary>
    string Protocol { get; }
    CardInterface Interface { get; }
    byte[] Transmit(byte[] command);
    /// <summary>Reader control (SCardControl); throws <see cref="NotSupportedException"/> if unavailable.</summary>
    byte[] Control(uint controlCode, byte[] input);
    /// <summary>Resets the card (cold/warm reset). All security states are lost.</summary>
    void Reset(bool cold);
}
