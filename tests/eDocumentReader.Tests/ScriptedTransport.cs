using eDocumentReader.Core.Transport;
using eDocumentReader.Core.Util;

namespace eDocumentReader.Tests;

/// <summary>Replays a fixed APDU exchange; expected commands may be null to accept any command.</summary>
public sealed class ScriptedTransport(params (string? Command, string Response)[] script) : ICardTransport
{
    private int index;
    public List<byte[]> Sent { get; } = [];
    public string Name => "Script";
    public byte[] Atr => Hex.Parse("3B80800101");
    public string Protocol => "T=1";
    public CardInterface Interface => CardInterface.Contactless;

    public byte[] Transmit(byte[] command)
    {
        Sent.Add(command);
        if (index >= script.Length) throw new InvalidOperationException($"Unerwartetes Kommando {Hex.Of(command)}");
        var (expected, response) = script[index++];
        if (expected != null) Assert.Equal(Hex.Compact(Hex.Parse(expected)), Hex.Compact(command));
        return Hex.Parse(response);
    }

    public byte[] Control(uint controlCode, byte[] input) => throw new NotSupportedException();
    public void Reset(bool cold) { }
    public void Dispose() { }
}
