using eDocumentReader.Core.Util;

namespace eDocumentReader.Core.Apdu;

public enum ApduCase { Case1, Case2Short, Case3Short, Case4Short, Case2Extended, Case3Extended, Case4Extended }

/// <summary>
/// Command APDU according to ISO/IEC 7816-4:2005, 5.1 (Table 1, Figures 3 and 4).
/// Ne = 0 means "no Le field"; Ne = 256 (short) / 65536 (extended) are the maximum values encoded as '00' / '0000'.
/// </summary>
public sealed class CommandApdu
{
    public byte Cla { get; }
    public byte Ins { get; }
    public byte P1 { get; }
    public byte P2 { get; }
    public byte[] Data { get; }
    /// <summary>Maximum number of expected response bytes; 0 = Le absent.</summary>
    public int Ne { get; }
    public bool ForceExtended { get; }

    public CommandApdu(byte cla, byte ins, byte p1, byte p2, byte[]? data = null, int ne = 0, bool forceExtended = false)
    {
        Data = data ?? [];
        if (Data.Length > 65535) throw new ArgumentOutOfRangeException(nameof(data), "Nc > 65535 nicht kodierbar.");
        if (ne is < 0 or > 65536) throw new ArgumentOutOfRangeException(nameof(ne));
        Cla = cla; Ins = ins; P1 = p1; P2 = p2; Ne = ne; ForceExtended = forceExtended;
    }

    public bool IsExtended => ForceExtended || Data.Length > 255 || Ne > 256;
    public bool IsChained => (Cla & 0x80) == 0 && (Cla & 0x10) != 0;
    public bool IsSecureMessaging => (Cla & 0x80) == 0 && (Cla & 0x0C) != 0;

    public ApduCase Case => (Data.Length > 0, Ne > 0, IsExtended) switch
    {
        (false, false, _) => ApduCase.Case1,
        (false, true, false) => ApduCase.Case2Short,
        (true, false, false) => ApduCase.Case3Short,
        (true, true, false) => ApduCase.Case4Short,
        (false, true, true) => ApduCase.Case2Extended,
        (true, false, true) => ApduCase.Case3Extended,
        _ => ApduCase.Case4Extended,
    };

    public byte[] ToBytes()
    {
        var bytes = new List<byte>(4 + 3 + Data.Length + 3) { Cla, Ins, P1, P2 };
        var extended = IsExtended && (Data.Length > 0 || Ne > 0);
        if (Data.Length > 0)
        {
            if (extended) bytes.AddRange([0x00, (byte)(Data.Length >> 8), (byte)Data.Length]);
            else bytes.Add((byte)Data.Length);
            bytes.AddRange(Data);
        }
        if (Ne > 0)
        {
            if (extended)
            {
                var le = Ne == 65536 ? 0 : Ne;
                if (Data.Length == 0) bytes.Add(0x00);
                bytes.AddRange([(byte)(le >> 8), (byte)le]);
            }
            else bytes.Add(Ne == 256 ? (byte)0 : (byte)Ne);
        }
        return [.. bytes];
    }

    /// <summary>Decodes a command APDU byte string (all seven cases of 7816-4 5.1).</summary>
    public static CommandApdu Parse(ReadOnlySpan<byte> apdu)
    {
        if (apdu.Length < 4) throw new FormatException("APDU kürzer als 4 Bytes.");
        byte cla = apdu[0], ins = apdu[1], p1 = apdu[2], p2 = apdu[3];
        var body = apdu[4..];
        if (body.Length == 0) return new CommandApdu(cla, ins, p1, p2);
        if (body.Length == 1) return new CommandApdu(cla, ins, p1, p2, null, body[0] == 0 ? 256 : body[0]);
        if (body[0] != 0)
        {
            var nc = body[0];
            if (body.Length == 1 + nc) return new CommandApdu(cla, ins, p1, p2, body.Slice(1, nc).ToArray());
            if (body.Length == 2 + nc) return new CommandApdu(cla, ins, p1, p2, body.Slice(1, nc).ToArray(), body[1 + nc] == 0 ? 256 : body[1 + nc]);
            throw new FormatException("Kurzes APDU: Länge passt nicht zu Lc.");
        }
        if (body.Length == 3)
        {
            var le = (body[1] << 8) | body[2];
            return new CommandApdu(cla, ins, p1, p2, null, le == 0 ? 65536 : le, true);
        }
        var ncExt = (body[1] << 8) | body[2];
        if (ncExt == 0) throw new FormatException("Erweitertes Lc = 0000 ist ungültig.");
        if (body.Length == 3 + ncExt) return new CommandApdu(cla, ins, p1, p2, body.Slice(3, ncExt).ToArray(), 0, true);
        if (body.Length == 5 + ncExt)
        {
            var le = (body[3 + ncExt] << 8) | body[4 + ncExt];
            return new CommandApdu(cla, ins, p1, p2, body.Slice(3, ncExt).ToArray(), le == 0 ? 65536 : le, true);
        }
        throw new FormatException("Erweitertes APDU: Länge passt nicht zu Lc.");
    }

    public CommandApdu WithNe(int ne) => new(Cla, Ins, P1, P2, Data, ne, ForceExtended);
    public CommandApdu WithCla(byte cla) => new(cla, Ins, P1, P2, Data, Ne, ForceExtended);

    public override string ToString() => Hex.Of(ToBytes());
}
