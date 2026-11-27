using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Util;

namespace eDocumentReader.Core.Documents;

/// <summary>
/// Common elementary files of the MF (ISO/IEC 7816-4 8.2.1.1, ICAO 9303-10 3.11): EF.ATR/INFO and EF.DIR. Both use the
/// interindustry tag allocation scheme (9303-10 3.11).
/// </summary>
public static class CardFiles
{
    public const byte SfiAtrInfo = 0x01;
    public const ushort FidAtrInfo = 0x2F01;
    public const byte SfiDir = 0x1E;
    public const ushort FidDir = 0x2F00;
    public const string AtrInfoName = "EF.ATR/INFO";
    public const string DirName = "EF.DIR";

    public static bool IsCardFile(string name) => name is AtrInfoName or DirName;

    /// <summary>Interindustry tag names (ISO/IEC 7816-4) for the file tree.</summary>
    public static string? TagName(uint tag) => tag switch
    {
        0x43 => T("Card service data", "Card service data"),
        0x46 => T("Pre-issuing data", "Pre-issuing data"),
        0x47 => T("Card capabilities", "Card capabilities"),
        0x7F66 => T("Extended length information", "Extended length information"),
        0x02 => T("Integer (Puffergröße)", "Integer (buffer size)"),
        0x61 => T("Application template", "Application template"),
        0x4F => T("Application identifier (AID)", "Application identifier (AID)"),
        0x50 => T("Application label", "Application label"),
        0x51 => T("Pfad", "Path"),
        0x73 => T("Discretionary data", "Discretionary data"),
        _ => null,
    };

    /// <summary>Strips the padding '00' / 'FF' that ISO/IEC 7816-4 allows before, between and after data objects.</summary>
    internal static List<BerTlv> ParseObjects(ReadOnlySpan<byte> data)
    {
        var list = new List<BerTlv>();
        var i = 0;
        while (i < data.Length)
        {
            if (data[i] is 0x00 or 0xFF) { i++; continue; }
            var tlv = BerTlv.ParseSingle(data[i..], i);
            list.Add(tlv);
            i += tlv.TotalLength;
        }
        return list;
    }
}

/// <summary>
/// EF.ATR/INFO (ICAO 9303-10 3.11.1 Table 29, ISO/IEC 7816-4 12.2.2 / 12.7.1): card service data '43', card capabilities
/// '47' and extended length information '7F66'. The terminal uses it to decide on command chaining and extended length
/// (9303-11 9.3.1.2, 9.3.2).
/// </summary>
public sealed class AtrInfoFile
{
    public byte? CardServiceData { get; }
    public byte[]? CardCapabilities { get; }
    public int? MaxCommandApdu { get; }
    public int? MaxResponseApdu { get; }
    public List<string> Findings { get; } = [];

    private byte Software(int index) => CardCapabilities is { } c && c.Length > index ? c[index] : (byte)0;

    /// <summary>Third software function b8 (ISO/IEC 7816-4 Table 88).</summary>
    public bool CommandChaining => (Software(2) & 0x80) != 0;
    /// <summary>Third software function b7.</summary>
    public bool ExtendedLength => (Software(2) & 0x40) != 0;
    /// <summary>Third software function b6: extended length information in EF.ATR/INFO.</summary>
    public bool ExtendedLengthInformation => (Software(2) & 0x20) != 0;
    /// <summary>Extended length with explicit buffer sizes: allowed beyond MSE:Set KAT / GENERAL AUTHENTICATE (9303-11 9.3.1.2).</summary>
    public bool BufferSizesStated => ExtendedLength && MaxCommandApdu.HasValue && MaxResponseApdu.HasValue;

    public AtrInfoFile(byte[] data)
    {
        foreach (var tlv in CardFiles.ParseObjects(data))
        {
            switch (tlv.Tag)
            {
                case 0x43 when tlv.Value.Length >= 1: CardServiceData = tlv.Value[0]; break;
                case 0x47: CardCapabilities = tlv.Value; break;
                case 0x7F66:
                    var ints = tlv.Children.Where(c => c.Tag == 0x02).ToList();
                    if (ints.Count >= 1) MaxCommandApdu = ToInt(ints[0].Value);
                    if (ints.Count >= 2) MaxResponseApdu = ToInt(ints[1].Value);
                    if (ints.Count != 2) Findings.Add(T($"'7F66' enthält {ints.Count} statt 2 Integer-DOs '02' (ISO/IEC 7816-4 12.7.1).", $"'7F66' contains {ints.Count} instead of 2 integer DOs '02' (ISO/IEC 7816-4 12.7.1)."));
                    break;
            }
        }
        if (CardCapabilities == null)
            Findings.Add(T("Card capabilities '47' fehlen (ICAO 9303-10 Table 29).", "Card capabilities '47' missing (ICAO 9303-10 Table 29)."));
        else if (CardCapabilities.Length != 3)
            Findings.Add(T($"Card capabilities '47' mit {CardCapabilities.Length} statt 3 Byte (ICAO 9303-10 Table 29).", $"Card capabilities '47' with {CardCapabilities.Length} instead of 3 bytes (ICAO 9303-10 Table 29)."));
        if (ExtendedLengthInformation && MaxCommandApdu == null)
            Findings.Add(T("Card capabilities kündigen Extended Length Information an, '7F66' fehlt.", "Card capabilities announce extended length information, '7F66' missing."));
        if (MaxCommandApdu != null && !ExtendedLengthInformation)
            Findings.Add(T("'7F66' vorhanden, aber Card capabilities Byte 3 b6 = 0.", "'7F66' present, but card capabilities byte 3 b6 = 0."));
        if (MaxCommandApdu != null && !ExtendedLength)
            Findings.Add(T("'7F66' vorhanden, aber Extended Lc/Le nicht angekündigt (Byte 3 b7 = 0).", "'7F66' present, but extended Lc/Le not announced (byte 3 b7 = 0)."));
    }

    private static int ToInt(byte[] v) => v.Aggregate(0, (a, b) => (a << 8) | b);

    public string Describe()
    {
        var lines = new List<string>();
        if (CardServiceData is { } s)
        {
            var b = new List<string>();
            if ((s & 0x80) != 0) b.Add(T("Anwendungsauswahl mit vollem DF-Namen", "application selection by full DF name"));
            if ((s & 0x40) != 0) b.Add(T("mit Teil-DF-Namen", "by partial DF name"));
            if ((s & 0x20) != 0) b.Add(T("BER-TLV in EF.DIR", "BER-TLV in EF.DIR"));
            if ((s & 0x10) != 0) b.Add(T("BER-TLV in EF.ATR", "BER-TLV in EF.ATR"));
            b.Add(((s >> 1) & 0x07) switch
            {
                0b100 => T("EF.DIR/EF.ATR per READ BINARY", "EF.DIR/EF.ATR by READ BINARY"),
                0b000 => T("EF.DIR/EF.ATR per READ RECORD", "EF.DIR/EF.ATR by READ RECORD"),
                0b010 => T("EF.DIR/EF.ATR per GET DATA", "EF.DIR/EF.ATR by GET DATA"),
                var x => T($"Zugriff EF.DIR/EF.ATR {x}", $"access EF.DIR/EF.ATR {x}"),
            });
            b.Add((s & 0x01) == 0 ? T("Karte mit MF", "card with MF") : T("Karte ohne MF", "card without MF"));
            lines.Add($"Card service data {s:X2}: {string.Join(", ", b)}");
        }
        if (CardCapabilities is { } c)
        {
            lines.Add($"Card capabilities {Hex.Of(c)}:");
            var s1 = Software(0);
            var sel = new List<string>();
            if ((s1 & 0x80) != 0) sel.Add(T("voller DF-Name", "full DF name"));
            if ((s1 & 0x40) != 0) sel.Add(T("Teil-DF-Name", "partial DF name"));
            if ((s1 & 0x20) != 0) sel.Add(T("Pfad", "path"));
            if ((s1 & 0x10) != 0) sel.Add("FID");
            lines.Add(T($"  DF-Auswahl: {(sel.Count > 0 ? string.Join(", ", sel) : "–")}; implizite DF-Auswahl: {((s1 & 0x08) != 0 ? "ja" : "nein")}", $"  DF selection: {(sel.Count > 0 ? string.Join(", ", sel) : "–")}; implicit DF selection: {((s1 & 0x08) != 0 ? "yes" : "no")}"));
            lines.Add(T($"  SFI: {Mark((s1 & 0x04) != 0)}, Record-Nummer: {Mark((s1 & 0x02) != 0)}, Record-ID: {Mark((s1 & 0x01) != 0)}", $"  SFI: {Mark((s1 & 0x04) != 0)}, record number: {Mark((s1 & 0x02) != 0)}, record identifier: {Mark((s1 & 0x01) != 0)}"));
            var unit = 1 << (Software(1) & 0x0F);
            lines.Add(T($"  Data unit: {(unit >= 2 ? $"{unit / 2} Byte" : "1 Quartett")}", $"  Data unit: {(unit >= 2 ? $"{unit / 2} byte(s)" : "1 quartet")}"));
            lines.Add(T($"  Command chaining: {Mark(CommandChaining)}, Extended Lc/Le: {Mark(ExtendedLength)}, Extended Length Info in EF.ATR/INFO: {Mark(ExtendedLengthInformation)}", $"  Command chaining: {Mark(CommandChaining)}, extended Lc/Le: {Mark(ExtendedLength)}, extended length info in EF.ATR/INFO: {Mark(ExtendedLengthInformation)}"));
            var s3 = Software(2);
            lines.Add(T($"  Logische Kanäle: {((s3 & 0x18) == 0 ? "nein" : $"ja, max. {((s3 & 0x07) == 7 ? "8 oder mehr" : ((s3 & 0x07) + 1).ToString())}")}", $"  Logical channels: {((s3 & 0x18) == 0 ? "no" : $"yes, max. {((s3 & 0x07) == 7 ? "8 or more" : ((s3 & 0x07) + 1).ToString())}")}"));
        }
        if (MaxCommandApdu is { } mc)
            lines.Add(T($"Extended length information: max. {mc} Byte pro Kommando-APDU, max. {MaxResponseApdu?.ToString() ?? "?"} Byte pro Antwort-APDU", $"Extended length information: max. {mc} bytes per command APDU, max. {MaxResponseApdu?.ToString() ?? "?"} bytes per response APDU"));
        lines.AddRange(Findings.Select(f => "⚠ " + f));
        return string.Join(Environment.NewLine, lines);
    }

    private static string Mark(bool on) => on ? T("ja", "yes") : T("nein", "no");
}

/// <summary>
/// EF.DIR (ICAO 9303-10 3.11.2, ISO/IEC 7816-4 8.2.1.1): application templates '61' with the AID '4F' of every
/// application. Its authenticity is checked with EFDIRInfo in EF.CardSecurity (9303-11 4.2, 9.2.10).
/// </summary>
public sealed class EfDirFile
{
    public sealed record Application(byte[] Aid, string? Label);
    public List<Application> Applications { get; } = [];
    public List<string> Findings { get; } = [];

    public EfDirFile(byte[] data)
    {
        foreach (var tlv in CardFiles.ParseObjects(data))
        {
            if (tlv.Tag != 0x61)
            {
                Findings.Add(T($"Datenobjekt '{tlv.TagHex}' außerhalb eines Application template '61' (ICAO 9303-10 3.11.2).", $"Data object '{tlv.TagHex}' outside an application template '61' (ICAO 9303-10 3.11.2)."));
                continue;
            }
            var aid = tlv.Find(0x4F)?.Value;
            if (aid == null)
            {
                Findings.Add(T("Application template '61' ohne AID '4F' (ICAO 9303-10 3.11.2).", "Application template '61' without AID '4F' (ICAO 9303-10 3.11.2)."));
                continue;
            }
            var label = tlv.Find(0x50)?.Value is { } l ? System.Text.Encoding.ASCII.GetString(l) : null;
            Applications.Add(new Application(aid, label));
        }
        if (Applications.Count == 0) Findings.Add(T("EF.DIR enthält keine Anwendung.", "EF.DIR contains no application."));
    }

    public bool Lists(ReadOnlySpan<byte> aid)
    {
        foreach (var a in Applications) if (a.Aid.AsSpan().SequenceEqual(aid)) return true;
        return false;
    }

    public string Describe() => string.Join(Environment.NewLine,
        Applications.Select(Describe).Concat(Findings.Select(f => "⚠ " + f)));

    /// <summary>One application: AID, known name and application label '50'.</summary>
    public static string Describe(Application a) => $"AID {Hex.Of(a.Aid)}{AidName(a.Aid)}{(a.Label != null ? $" \"{a.Label}\"" : "")}";

    /// <summary>LDS2 applications (ICAO 9303-10): Travel Records, Visa Records, Additional Biometrics = A0 00 00 02 47 20 01..03.</summary>
    public static bool IsLds2(ReadOnlySpan<byte> aid) => aid.Length == 7 && aid[..6].SequenceEqual(Lds2Prefix) && aid[6] is >= 1 and <= 3;

    private static readonly byte[] Lds2Prefix = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x20];

    private static string AidName(byte[] aid) =>
        aid.AsSpan().SequenceEqual(EmrtdReader.EmrtdAid) ? " (eMRTD, ICAO 9303-10)"
        : aid.AsSpan().SequenceEqual(EmrtdReader.IdlAid) ? " (IDL, ISO/IEC 18013-3)"
        : IsLds2(aid) ? aid[6] switch { 1 => " (LDS2 Travel Records)", 2 => " (LDS2 Visa Records)", _ => " (LDS2 Additional Biometrics)" }
        : Hex.Compact(aid) == "E80704007F00070302" ? " (eID, BSI TR-03110)"
        : Hex.Compact(aid) == "A000000167455349474E" ? " (eSign)"
        : Hex.Compact(aid).StartsWith("E828BD080F", StringComparison.Ordinal) ? " (CIA, ISO/IEC 7816-15)"
        : string.Empty;
}
