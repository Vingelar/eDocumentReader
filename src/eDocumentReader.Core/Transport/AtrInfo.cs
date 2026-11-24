using System.Text;
using eDocumentReader.Core.Util;

namespace eDocumentReader.Core.Transport;

public sealed record InterfaceByte(string Name, byte Value, string Meaning);

public sealed record CompactTlv(byte Tag, byte[] Value, string Meaning);

/// <summary>
/// Answer-to-Reset analysis according to ISO/IEC 7816-3:2006 clause 8 and historical bytes according to
/// ISO/IEC 7816-4:2005 clause 8.1.1. ATRs synthesized by PC/SC readers for contactless cards are recognised
/// according to PC/SC Part 3 v2.01.09, 3.1.3.2.3 (Tables 3-5 / 3-6).
/// </summary>
public sealed class AtrInfo
{
    private static readonly int?[] FiTable = [372, 372, 558, 744, 1116, 1488, 1860, null, null, 512, 768, 1024, 1536, 2048, null, null];
    private static readonly string?[] FmaxTable = ["4", "5", "6", "8", "12", "16", "20", null, null, "5", "7,5", "10", "15", "20", null, null];
    private static readonly int?[] DiTable = [null, 1, 2, 4, 8, 16, 32, 64, 12, 20, null, null, null, null, null, null];

    public byte[] Raw { get; }
    public byte Ts { get; }
    public byte T0 { get; }
    public List<InterfaceByte> InterfaceBytes { get; } = [];
    public List<int> Protocols { get; } = [];
    public byte[] HistoricalBytes { get; } = [];
    public byte? Tck { get; }
    public bool? TckValid { get; }
    public List<string> Findings { get; } = [];
    public List<CompactTlv> HistoricalObjects { get; } = [];

    /// <summary>True if the ATR has the PC/SC Part 3 structure for contactless ICCs (3B 8n 80 01 ...).</summary>
    public bool IsPcscContactless { get; }
    public bool IsPcscContactlessStorageCard { get; }
    /// <summary>From card capabilities (7816-4 Table 88), if announced in the historical bytes.</summary>
    public bool? ExtendedLengthSupported { get; private set; }
    public bool? CommandChainingSupported { get; private set; }

    public AtrInfo(byte[] atr)
    {
        Raw = atr;
        if (atr.Length < 2) { Findings.Add("ATR kürzer als 2 Bytes."); return; }
        Ts = atr[0];
        if (Ts is not (0x3B or 0x3F)) Findings.Add($"TS = {Ts:X2} ungültig (erwartet 3B direkte / 3F inverse Konvention).");
        T0 = atr[1];
        var k = T0 & 0x0F;
        var y = T0 >> 4;
        var pos = 2;
        var i = 1;
        var lastT = -1;
        var tckRequired = false;
        while (true)
        {
            var currentT = i <= 2 ? -1 : lastT;
            if ((y & 0x1) != 0) { if (!Read($"TA{i}", out var b)) break; InterfaceBytes.Add(new($"TA{i}", b, DescribeTa(i, currentT, b))); }
            if ((y & 0x2) != 0) { if (!Read($"TB{i}", out var b)) break; InterfaceBytes.Add(new($"TB{i}", b, DescribeTb(i, currentT, b))); }
            if ((y & 0x4) != 0) { if (!Read($"TC{i}", out var b)) break; InterfaceBytes.Add(new($"TC{i}", b, DescribeTc(i, currentT, b))); }
            if ((y & 0x8) == 0) break;
            if (!Read($"TD{i}", out var td)) break;
            var t = td & 0x0F;
            InterfaceBytes.Add(new($"TD{i}", td, $"Y{i + 1}={td >> 4:X1}h, T={t}"));
            if (t < lastT) Findings.Add($"TD{i}: Protokolltypen nicht aufsteigend (ISO/IEC 7816-3 8.2.3).");
            if (i == 1 && t == 15) Findings.Add("T=15 in TD1 ist ungültig (ISO/IEC 7816-3 8.2.3).");
            if (t != 15 && !Protocols.Contains(t)) Protocols.Add(t);
            if (t != 0) tckRequired = true;
            lastT = t;
            y = td >> 4;
            i++;
        }
        if (Protocols.Count == 0) Protocols.Add(0);

        if (pos + k > atr.Length) { Findings.Add($"ATR zu kurz für {k} historische Bytes."); k = Math.Max(0, atr.Length - pos); }
        HistoricalBytes = atr[pos..(pos + k)];
        pos += k;
        if (tckRequired)
        {
            if (pos < atr.Length)
            {
                Tck = atr[pos];
                byte x = 0;
                for (var j = 1; j <= pos; j++) x ^= atr[j];
                TckValid = x == 0;
                if (!TckValid.Value) Findings.Add($"TCK {Tck:X2} ungültig (XOR T0..TCK ≠ 00, ISO/IEC 7816-3 8.2.5).");
                pos++;
            }
            else Findings.Add("TCK fehlt, obwohl ein Protokoll ≠ T=0 angezeigt wird (ISO/IEC 7816-3 8.2.5).");
        }
        if (pos < atr.Length) Findings.Add($"{atr.Length - pos} überzählige Bytes nach dem ATR.");
        if (atr.Length > 33) Findings.Add("ATR länger als 33 Bytes (ISO/IEC 7816-3 8.2.1).");

        IsPcscContactless = atr.Length >= 5 && Ts == 0x3B && (T0 & 0xF0) == 0x80 && atr[2] == 0x80 && atr[3] == 0x01;
        IsPcscContactlessStorageCard = IsPcscContactless && HistoricalBytes.Length >= 2 && HistoricalBytes[0] == 0x80 && HistoricalBytes[1] == 0x4F;
        ParseHistoricalBytes();
        return;

        bool Read(string name, out byte value)
        {
            if (pos >= atr.Length) { Findings.Add($"ATR endet vor {name}."); value = 0; return false; }
            value = atr[pos++];
            return true;
        }
    }

    private static string DescribeTa(int i, int t, byte b) => (i, t) switch
    {
        (1, _) => $"Fi={FiTable[b >> 4]?.ToString() ?? "RFU"}, f(max)={FmaxTable[b >> 4] ?? "RFU"} MHz, Di={DiTable[b & 0x0F]?.ToString() ?? "RFU"}",
        (2, _) => $"Specific mode: {((b & 0x80) != 0 ? "nicht" : "")} änderbar, {((b & 0x10) != 0 ? "implizite" : "TA1-")}Parameter, T={b & 0x0F}",
        (_, 1) => $"IFSC = {b}",
        (_, 15) => $"Clock stop: {(b >> 6) switch { 0 => "nicht unterstützt", 1 => "Zustand L", 2 => "Zustand H", _ => "keine Präferenz" }}, Klassen: {ClassBits(b & 0x3F)}",
        _ => "spezifisch",
    };

    private static string DescribeTb(int i, int t, byte b) => (i, t) switch
    {
        (1 or 2, _) => "veraltet (ISO/IEC 7816-3 8.3), wird ignoriert",
        (_, 1) => $"BWI = {b >> 4}, CWI = {b & 0x0F}",
        (_, 15) => $"SPU: {b:X2}",
        _ => "spezifisch",
    };

    private static string DescribeTc(int i, int t, byte b) => (i, t) switch
    {
        (1, _) => $"Extra Guard Time N = {b}",
        (2, _) => $"WI = {b} (T=0)",
        (_, 1) => $"Fehlererkennung: {((b & 1) != 0 ? "CRC" : "LRC")}",
        _ => "spezifisch",
    };

    private static string ClassBits(int bits)
    {
        var classes = new List<string>();
        if ((bits & 1) != 0) classes.Add("A (5 V)");
        if ((bits & 2) != 0) classes.Add("B (3 V)");
        if ((bits & 4) != 0) classes.Add("C (1,8 V)");
        return classes.Count == 0 ? "-" : string.Join(", ", classes);
    }

    private void ParseHistoricalBytes()
    {
        var h = HistoricalBytes;
        if (h.Length == 0) return;
        if (IsPcscContactless && !IsPcscContactlessStorageCard && h[0] is not (0x00 or 0x80 or 0x10))
        {
            Findings.Add("Historische Bytes ohne ISO/IEC 7816-4-Kategorieindikator (bei kontaktlosen Karten: ATS-Hist.-Bytes bzw. ATQB-Daten, PC/SC Part 3 Tab. 3-5).");
            return;
        }
        switch (h[0])
        {
            case 0x00:
                if (h.Length < 4) { Findings.Add("Kategorie 00: Statusindikator (3 Bytes) fehlt."); return; }
                ParseCompact(h.AsSpan(1, h.Length - 4));
                HistoricalObjects.Add(new CompactTlv(0x00, h[^3..], $"Statusindikator: LCS={h[^3]:X2}, SW={h[^2]:X2}{h[^1]:X2}"));
                break;
            case 0x80:
                ParseCompact(h.AsSpan(1));
                break;
            case 0x10:
                HistoricalObjects.Add(new CompactTlv(0x10, h[1..], "DIR data reference"));
                break;
            default:
                Findings.Add($"Kategorieindikator {h[0]:X2} proprietär.");
                break;
        }
    }

    private void ParseCompact(ReadOnlySpan<byte> data)
    {
        var p = 0;
        while (p < data.Length)
        {
            var header = data[p++];
            var tag = (byte)(header >> 4);
            var len = header & 0x0F;
            if (p + len > data.Length) { Findings.Add($"COMPACT-TLV {header:X2}: Länge überschreitet historische Bytes."); return; }
            var value = data.Slice(p, len).ToArray();
            p += len;
            HistoricalObjects.Add(new CompactTlv(header, value, DescribeCompact(tag, value)));
        }
    }

    private string DescribeCompact(byte tag, byte[] v)
    {
        switch (tag)
        {
            case 0x1: return "Ländercode";
            case 0x2: return "Kartenherausgeber";
            case 0x3: return "Card service data";
            case 0x4: return "Initial access data";
            case 0x5: return "Card issuer's data";
            case 0x6: return "Pre-issuing data";
            case 0x7:
                var sb = new StringBuilder("Card capabilities");
                if (v.Length >= 3)
                {
                    CommandChainingSupported = (v[2] & 0x80) != 0;
                    ExtendedLengthSupported = (v[2] & 0x40) != 0;
                    sb.Append($": Chaining={(CommandChainingSupported.Value ? "ja" : "nein")}, Extended Lc/Le={(ExtendedLengthSupported.Value ? "ja" : "nein")}");
                }
                return sb.ToString();
            case 0x8: return "Statusindikator";
            case 0xF: return "Application identifier";
            default: return "RFU/unbekannt";
        }
    }

    public string Describe()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"ATR: {Hex.Of(Raw)}");
        sb.AppendLine($"TS = {Ts:X2} ({(Ts == 0x3B ? "direkte" : Ts == 0x3F ? "inverse" : "ungültige")} Konvention)");
        sb.AppendLine($"T0 = {T0:X2} (Y1={T0 >> 4:X1}h, K={T0 & 0xF})");
        foreach (var ib in InterfaceBytes) sb.AppendLine($"{ib.Name} = {ib.Value:X2}  {ib.Meaning}");
        sb.AppendLine($"Protokolle: {string.Join(", ", Protocols.Select(p => "T=" + p))}");
        sb.AppendLine($"Historische Bytes: {Hex.Of(HistoricalBytes)}");
        foreach (var o in HistoricalObjects) sb.AppendLine($"  {o.Tag:X2}: {Hex.Of(o.Value)}  {o.Meaning}");
        if (Tck.HasValue) sb.AppendLine($"TCK = {Tck:X2} ({(TckValid == true ? "gültig" : "UNGÜLTIG")})");
        if (IsPcscContactless) sb.AppendLine(IsPcscContactlessStorageCard ? "Kontaktlose Speicherkarte (PC/SC Part 3)" : "Kontaktlose ISO/IEC 14443-4-Karte (PC/SC Part 3 ATR-Abbildung)");
        foreach (var f in Findings) sb.AppendLine("⚠ " + f);
        return sb.ToString();
    }
}
