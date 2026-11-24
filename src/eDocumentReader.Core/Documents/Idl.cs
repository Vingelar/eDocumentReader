using System.Text;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Util;

namespace eDocumentReader.Core.Documents;

/// <summary>One displayed element of an IDL data group.</summary>
public sealed record IdlField(string Path, string TagHex, string Name, string Value, List<string> Findings)
{
    /// <summary>Language-independent identity of the DG1 fields (e.g. "familyName"); the name is display text.</summary>
    public string? Key { get; init; }
}

/// <summary>Driving privilege (category) entry, tag '87' inside '7F63'.</summary>
public sealed record IdlCategory(string Category, string IssueDate, string ExpiryDate, string Codes, string Sign, string Value, List<string> Findings);

/// <summary>Image of an IDL data group (DG4 portrait '5F40', DG5 signature '5F43').</summary>
public sealed record IdlImage(int DataGroup, string Name, byte[] Data, string Format, string? Captured, string? ImageType);

public sealed class IdlReadout
{
    public List<IdlField> Fields { get; } = [];
    public List<IdlCategory> Categories { get; } = [];
    public List<IdlImage> Images { get; } = [];
}

/// <summary>
/// Prepared display of the IDL data groups (ISO/IEC 18013-2 Annex C, ISO/IEC 18013-3 Table 12).
/// The encoding follows the Annex C layout as implemented by the open isodl reference (DG1 '5F1F' demographic
/// string with length-prefixed texts and BCD dates, '7F63' categories as ';'-separated '87' entries, DG2 tagged
/// attributes, DG4/DG5 images). The licensed 2020 edition was not available; deviating structures are displayed
/// generically (text or hex) with a finding instead of being rejected.
/// </summary>
public static class Idl
{
    /// <summary>EF.COM / data group tags of the IDL (differ from the eMRTD LDS).</summary>
    public static int DataGroupNumber(byte tag) => tag switch
    {
        0x61 => 1, 0x6B => 2, 0x6C => 3, 0x65 => 4, 0x67 => 5, 0x75 => 6, 0x63 => 7, 0x76 => 8, 0x70 => 9,
        0x6D => 11, 0x62 => 11, 0x71 => 12, 0x6F => 13, 0x6E => 14,
        _ => 0,
    };

    public static string DataGroupContent(int dg) => dg switch
    {
        1 => T("Pflichtdaten: Inhaber, Ausstellung, Fahrerlaubnisklassen", "Mandatory data: holder, issuance, driving privileges"),
        2 => T("Zusätzliche Inhaberdaten", "Additional holder data"),
        4 => T("Lichtbild", "Portrait"),
        5 => T("Unterschrift / Zeichen", "Signature / usual mark"),
        13 => T("Active Authentication (öffentlicher Schlüssel)", "Active Authentication (public key)"),
        14 => T("Sicherheitsinformationen (CA/TA/PACE)", "Security information (CA/TA/PACE)"),
        _ => $"DG{dg}",
    };

    public static string? TagName(uint tag) => tag switch
    {
        0x60 => "EF.COM",
        0x61 => T("DG1 – Pflichtdaten", "DG1 – mandatory data"),
        0x6B => T("DG2 – Zusätzliche Inhaberdaten", "DG2 – additional holder data"),
        0x65 => T("DG4 – Lichtbild", "DG4 – portrait"),
        0x67 => T("DG5 – Unterschrift", "DG5 – signature"),
        0x6F => T("DG13 – AA-Schlüssel", "DG13 – AA key"),
        0x6E => T("DG14 – Sicherheitsinformationen", "DG14 – security information"),
        0x77 => "EF.SOD",
        0x5F01 => T("LDS-Version", "LDS version"),
        0x5C => T("Tag-Liste", "Tag list"),
        0x5F1F => T("Demografische Daten", "Demographic data"),
        0x7F63 => T("Fahrerlaubnisklassen", "Driving privileges"),
        0x02 => T("Anzahl", "Number of entries"),
        0x87 => T("Fahrerlaubnisklasse", "Driving privilege"),
        0x5F35 => T("Geschlecht", "Sex"),
        0x5F64 => T("Größe", "Height"),
        0x5F65 => T("Gewicht", "Weight"),
        0x5F66 => T("Augenfarbe", "Eye colour"),
        0x5F67 => T("Haarfarbe", "Hair colour"),
        0x5F11 => T("Geburtsort", "Place of birth"),
        0x5F42 => T("Wohnort / Anschrift", "Residence / address"),
        0xA2 => T("Bildinstanz", "Image instance"),
        0x88 => T("Aufnahmezeitpunkt", "Capture time"),
        0x89 => T("Bildtyp", "Image type"),
        0x5F40 => T("Bilddaten (Lichtbild)", "Image data (portrait)"),
        0x5F43 => T("Bilddaten (Unterschrift)", "Image data (signature)"),
        0x53 => T("Freie Daten (ISO/IEC 7816-6 'discretionary data')", "Discretionary data (ISO/IEC 7816-6)"),
        _ => null,
    };

    /// <summary>Data groups that are shown here; DG13/DG14 belong to the security report.</summary>
    private static readonly int[] Displayed = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    public static IdlReadout Parse(IReadOnlyDictionary<int, byte[]> dataGroups)
    {
        var r = new IdlReadout();
        foreach (var dg in Displayed.Where(dataGroups.ContainsKey))
        {
            var path = $"DG{dg}";
            BerTlv outer;
            try { outer = BerTlv.ParseSingle(dataGroups[dg]); }
            catch (Exception ex)
            {
                r.Fields.Add(new IdlField(path, "", DataGroupContent(dg), Preview(dataGroups[dg]), [T($"Kein gültiges BER-TLV: {ex.Message}", $"Not a valid BER-TLV: {ex.Message}")]));
                continue;
            }
            var expectedTag = dg switch { 1 => 0x61u, 2 => 0x6Bu, 4 => 0x65u, 5 => 0x67u, _ => 0u };
            List<string> outerFindings = expectedTag != 0 && outer.Tag != expectedTag
                ? [T($"Äußeres Tag '{outer.TagHex}', erwartet '{expectedTag:X2}' (ISO/IEC 18013-3 Tabelle 12)", $"Outer tag '{outer.TagHex}', expected '{expectedTag:X2}' (ISO/IEC 18013-3 Table 12)")] : [];
            r.Fields.Add(new IdlField(path, outer.TagHex, DataGroupContent(dg), T($"{dataGroups[dg].Length} Byte", $"{dataGroups[dg].Length} bytes"), outerFindings));
            foreach (var child in outer.Children) Walk(child, outer, path, dg, r);
        }
        return r;
    }

    private static void Walk(BerTlv node, BerTlv parent, string path, int dg, IdlReadout r)
    {
        var name = TagName(node.Tag) ?? $"Tag '{node.TagHex}'";
        List<string> unknown = TagName(node.Tag) == null ? [T("Tag in ISO/IEC 18013-2 Anhang C nicht bekannt", "Tag not known in ISO/IEC 18013-2 Annex C")] : [];
        switch (node.Tag)
        {
            case 0x5F1F:
                ParseDemographics(node.Value, path, r);
                return;
            case 0x87:
                var cat = ParseCategory(node.Value);
                r.Categories.Add(cat);
                r.Fields.Add(new IdlField(path, node.TagHex, name, cat.Describe(), cat.Findings));
                return;
            case 0x5F40 or 0x5F43:
            {
                // Capture time '88' and image type '89' are siblings inside the same 'A2' instance (DG5: directly in '67').
                var format = ImageFormat(node.Value);
                var captured = parent.Find(0x88) is { } t ? (Bcd(t.Value) is { } digits ? FormatTimestamp(digits) : Hex.Of(t.Value)) : null;
                var type = parent.Find(0x89) is { } ty ? Hex.Of(ty.Value) : null;
                r.Images.Add(new IdlImage(dg, node.Tag == 0x5F40 ? T("Lichtbild", "Portrait") : T("Unterschrift", "Signature"), node.Value, format, captured, type));
                r.Fields.Add(new IdlField(path, node.TagHex, name, T($"{format}, {node.Value.Length} Byte", $"{format}, {node.Value.Length} bytes"),
                    !IsKnownImageFormat(format) ? [T("Bildformat nicht erkannt (erwartet JPEG oder JPEG 2000)", "Image format not recognized (expected JPEG or JPEG 2000)")] : []));
                return;
            }
            case 0x88:
                r.Fields.Add(new IdlField(path, node.TagHex, name, Bcd(node.Value) is { } ts ? FormatTimestamp(ts) : Hex.Of(node.Value),
                    Bcd(node.Value) == null ? [T("Keine BCD-Ziffern", "No BCD digits")] : []));
                return;
            case 0x89:
                r.Fields.Add(new IdlField(path, node.TagHex, name, Hex.Of(node.Value), []));
                return;
            case 0x5F35:
                r.Fields.Add(new IdlField(path, node.TagHex, name, Sex(node.Value), []));
                return;
            case 0x5F64 or 0x5F65:
            {
                var digits = Bcd(node.Value);
                var unit = node.Tag == 0x5F64 ? "cm" : "kg";
                r.Fields.Add(new IdlField(path, node.TagHex, name, digits != null ? $"{int.Parse(digits)} {unit}" : Hex.Of(node.Value),
                    digits == null ? [T("Keine BCD-Ziffern", "No BCD digits")] : []));
                return;
            }
            case 0x53:
                r.Fields.Add(new IdlField(path, node.TagHex, name, Text(node.Value),
                    [T("Freitext statt der Struktur nach ISO/IEC 18013-2 Anhang C (Platzhalter?)", "Free text instead of the ISO/IEC 18013-2 Annex C structure (placeholder?)")]));
                return;
        }
        if (node.IsConstructed)
        {
            r.Fields.Add(new IdlField(path, node.TagHex, name, T($"{node.Children.Count} Element(e)", $"{node.Children.Count} element(s)"), unknown));
            foreach (var c in node.Children) Walk(c, node, $"{path}/{node.TagHex}", dg, r);
            return;
        }
        r.Fields.Add(new IdlField(path, node.TagHex, name, node.Tag == 0x02 ? Hex.Of(node.Value) : Text(node.Value), unknown));
    }

    /// <summary>
    /// DG1 '5F1F': family name, given names (each length-prefixed), date of birth, date of issue, date of expiry
    /// (4 byte BCD each, YYYYMMDD), issuing country (3 characters), issuing authority and licence number (length-prefixed).
    /// </summary>
    public static void ParseDemographics(byte[] v, string path, IdlReadout r)
    {
        var p = $"{path}/5F1F";
        var pos = 0;
        var findings = new List<string>();
        string? LengthPrefixed()
        {
            if (pos >= v.Length) return null;
            int len = v[pos];
            if (pos + 1 + len > v.Length) return null;
            var s = Encoding.UTF8.GetString(v, pos + 1, len);
            pos += 1 + len;
            return s;
        }
        string? Date()
        {
            if (pos + 4 > v.Length) return null;
            var d = Bcd(v.AsSpan(pos, 4).ToArray());
            pos += 4;
            return d;
        }
        string? Fixed(int n)
        {
            if (pos + n > v.Length) return null;
            var s = Encoding.Latin1.GetString(v, pos, n);
            pos += n;
            return s;
        }
        var family = LengthPrefixed();
        var given = LengthPrefixed();
        var dob = Date();
        var doi = Date();
        var doe = Date();
        var country = Fixed(3);
        var authority = LengthPrefixed();
        var number = LengthPrefixed();
        if (number == null)
        {
            // Not the Annex C layout: show the content generically instead of guessing.
            r.Fields.Add(new IdlField(p, "5F1F", T("Demografische Daten", "Demographic data"), Text(v),
                [T("Aufbau entspricht nicht ISO/IEC 18013-2 Anhang C (Längenpräfixe / BCD-Daten); Rohinhalt angezeigt", "Structure does not match ISO/IEC 18013-2 Annex C (length prefixes / BCD dates); raw content shown")]));
            return;
        }
        if (pos != v.Length) findings.Add(T($"{v.Length - pos} Byte nach der Führerscheinnummer nicht ausgewertet", $"{v.Length - pos} bytes after the licence number not evaluated"));
        r.Fields.Add(new IdlField(p, "5F1F", T("Familienname", "Family name"), family!, []) { Key = "familyName" });
        r.Fields.Add(new IdlField(p, "5F1F", T("Vornamen", "Given names"), given!, []) { Key = "givenNames" });
        r.Fields.Add(new IdlField(p, "5F1F", T("Geburtsdatum", "Date of birth"), FormatDate(dob), DateFindings(dob)) { Key = "dateOfBirth" });
        r.Fields.Add(new IdlField(p, "5F1F", T("Ausstellungsdatum", "Date of issue"), FormatDate(doi), DateFindings(doi)) { Key = "dateOfIssue" });
        var expiryFindings = DateFindings(doe);
        if (doi != null && doe != null && string.CompareOrdinal(doi, doe) >= 0) expiryFindings.Add(T("Ablaufdatum liegt nicht nach dem Ausstellungsdatum", "Date of expiry is not after the date of issue"));
        r.Fields.Add(new IdlField(p, "5F1F", T("Ablaufdatum", "Date of expiry"), FormatDate(doe), expiryFindings) { Key = "dateOfExpiry" });
        r.Fields.Add(new IdlField(p, "5F1F", T("Ausstellerstaat", "Issuing country"), country!, country!.All(char.IsAsciiLetterUpper) ? [] : [T("Kein Ländercode aus 3 Großbuchstaben (ISO 3166-1 alpha-3)", "Not a country code of 3 capital letters (ISO 3166-1 alpha-3)")]) { Key = "issuingCountry" });
        r.Fields.Add(new IdlField(p, "5F1F", T("Ausstellende Behörde", "Issuing authority"), authority!, []) { Key = "issuingAuthority" });
        r.Fields.Add(new IdlField(p, "5F1F", T("Führerscheinnummer", "Licence number"), number, findings) { Key = "licenceNumber" });
    }

    /// <summary>Category entry: category;date of issue (BCD);date of expiry (BCD);codes ('+'-separated);sign;value.</summary>
    public static IdlCategory ParseCategory(byte[] v)
    {
        var parts = Split(v, (byte)';');
        var findings = new List<string>();
        string Part(int i) => i < parts.Count ? Encoding.Latin1.GetString(parts[i]) : "";
        string DatePart(int i)
        {
            if (i >= parts.Count || parts[i].Length == 0) return "";
            var d = Bcd(parts[i]);
            if (d == null || d.Length != 8) { findings.Add(T($"Datum {Hex.Of(parts[i])} ist kein 4-Byte-BCD-Datum", $"Date {Hex.Of(parts[i])} is not a 4-byte BCD date")); return Hex.Of(parts[i]); }
            return d;
        }
        if (parts.Count < 3) findings.Add(T("Weniger als 3 durch ';' getrennte Felder", "Fewer than 3 fields separated by ';'"));
        var category = Part(0);
        if (category.Length is 0 or > 3) findings.Add(T($"Klasse '{category}' muss 1–3 Zeichen haben", $"Category '{category}' must have 1–3 characters"));
        var doi = DatePart(1);
        var doe = DatePart(2);
        if (doi.Length == 8 && doe.Length == 8 && string.CompareOrdinal(doi, doe) >= 0) findings.Add(T("Ablaufdatum liegt nicht nach dem Ausstellungsdatum", "Date of expiry is not after the date of issue"));
        return new IdlCategory(category, doi, doe, Part(3), Part(4), Part(5), findings);
    }

    public static string Describe(this IdlCategory c)
    {
        var sb = new StringBuilder(c.Category);
        if (c.IssueDate.Length > 0) sb.Append(T($", erteilt {FormatDate(c.IssueDate)}", $", issued {FormatDate(c.IssueDate)}"));
        if (c.ExpiryDate.Length > 0) sb.Append(T($", gültig bis {FormatDate(c.ExpiryDate)}", $", valid until {FormatDate(c.ExpiryDate)}"));
        if (c.Codes.Length > 0) sb.Append($", Codes {c.Codes}");
        if (c.Sign.Length > 0 || c.Value.Length > 0) sb.Append($" {c.Sign}{c.Value}");
        return sb.ToString();
    }

    public static string ImageFormat(byte[] d) =>
        d.Length >= 3 && d[0] == 0xFF && d[1] == 0xD8 ? "JPEG"
        : d.Length >= 12 && d[4] == 0x6A && d[5] == 0x50 && d[6] == 0x20 && d[7] == 0x20 ? "JPEG 2000 (JP2)"
        : d.Length >= 4 && d[0] == 0xFF && d[1] == 0x4F && d[2] == 0xFF && d[3] == 0x51 ? "JPEG 2000 (Codestream)"
        : T("unbekannt", "unknown");

    public static bool IsKnownImageFormat(string format) => format.StartsWith("JPEG", StringComparison.Ordinal);

    private static List<byte[]> Split(byte[] v, byte separator)
    {
        // BCD dates never contain ';' (0x3B has a non-decimal nibble), so a plain split is unambiguous.
        var result = new List<byte[]>();
        var start = 0;
        for (var i = 0; i <= v.Length; i++)
            if (i == v.Length || v[i] == separator) { result.Add(v[start..i]); start = i + 1; }
        return result;
    }

    /// <summary>Packed BCD to digit string; null if a nibble is not decimal.</summary>
    public static string? Bcd(byte[] v)
    {
        var sb = new StringBuilder(v.Length * 2);
        foreach (var b in v)
        {
            if (b >> 4 > 9 || (b & 0x0F) > 9) return null;
            sb.Append((char)('0' + (b >> 4))).Append((char)('0' + (b & 0x0F)));
        }
        return sb.ToString();
    }

    private static string FormatDate(string? yyyymmdd) =>
        yyyymmdd is { Length: 8 } d ? $"{d[6..8]}.{d[4..6]}.{d[..4]}" : yyyymmdd ?? "–";

    private static string FormatTimestamp(string digits) => digits.Length switch
    {
        14 => $"{FormatDate(digits[..8])} {digits[8..10]}:{digits[10..12]}:{digits[12..14]}",
        8 => FormatDate(digits),
        _ => digits,
    };

    private static List<string> DateFindings(string? d)
    {
        if (d == null) return [T("Kein BCD-Datum", "No BCD date")];
        if (!DateOnly.TryParseExact(d, "yyyyMMdd", out _)) return [T($"Ungültiges Datum {d}", $"Invalid date {d}")];
        return [];
    }

    private static string Sex(byte[] v) => v.Length == 1
        ? v[0] switch { 0 => T("0 – unbekannt", "0 – not known"), 1 => T("1 – männlich", "1 – male"), 2 => T("2 – weiblich", "2 – female"), 9 => T("9 – nicht anwendbar", "9 – not applicable"), _ => Hex.Of(v) } + " (ISO/IEC 5218)"
        : Text(v);

    private static string Text(byte[] v) =>
        v.Length > 0 && v.All(b => b >= 0x20 && b != 0x7F) ? Encoding.UTF8.GetString(v) : Preview(v);

    private static string Preview(byte[] v) => v.Length <= 48 ? Hex.Of(v) : Hex.Of(v.AsSpan(0, 48)) + T($" … ({v.Length} Byte)", $" … ({v.Length} bytes)");
}
