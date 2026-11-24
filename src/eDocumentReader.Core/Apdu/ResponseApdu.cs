using eDocumentReader.Core.Util;

namespace eDocumentReader.Core.Apdu;

public sealed class ResponseApdu
{
    public byte[] Data { get; }
    public StatusWord Status { get; }

    public ResponseApdu(byte[] data, StatusWord status)
    {
        Data = data;
        Status = status;
    }

    public static ResponseApdu Parse(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < 2) throw new FormatException("Antwort-APDU kürzer als 2 Bytes (SW1-SW2 fehlt).");
        return new ResponseApdu(raw[..^2].ToArray(), new StatusWord(raw[^2], raw[^1]));
    }

    public byte[] ToBytes() => [.. Data, Status.Sw1, Status.Sw2];

    public override string ToString() => Data.Length == 0 ? Status.ToString() : $"{Hex.Of(Data)} {Status}";
}
