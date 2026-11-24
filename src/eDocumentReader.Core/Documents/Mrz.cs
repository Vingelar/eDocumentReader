using System.Text;

namespace eDocumentReader.Core.Documents;

public enum MrzFormat { TD1, TD2, TD3 }

/// <param name="Key">Language-independent identity: documentNumber, dateOfBirth, dateOfExpiry, personalNumber, composite.</param>
public sealed record MrzField(string Name, string Value, char? CheckDigit, bool? Valid, string Key = "");

/// <summary>
/// Machine Readable Zone according to ICAO 9303-3 (check digits 4.9), 9303-4 (TD3), 9303-5 (TD1), 9303-6 (TD2).
/// Document numbers longer than 9 characters (TD1/TD2) are handled as described in 9303-5/-6 and 9303-11 Appendix D.2.
/// </summary>
public sealed class Mrz
{
    public MrzFormat Format { get; }
    public string[] Lines { get; }
    public string DocumentCode { get; private set; } = "";
    public string IssuingState { get; private set; } = "";
    public string DocumentNumber { get; private set; } = "";
    public char DocumentNumberCheckDigit { get; private set; }
    public string DateOfBirth { get; private set; } = "";
    public char DateOfBirthCheckDigit { get; private set; }
    public string Sex { get; private set; } = "";
    public string DateOfExpiry { get; private set; } = "";
    public char DateOfExpiryCheckDigit { get; private set; }
    public string Nationality { get; private set; } = "";
    public string PrimaryIdentifier { get; private set; } = "";
    public string SecondaryIdentifier { get; private set; } = "";
    public string OptionalData1 { get; private set; } = "";
    public string OptionalData2 { get; private set; } = "";
    public char? CompositeCheckDigit { get; private set; }
    public List<MrzField> Fields { get; } = [];
    public List<string> Findings { get; } = [];

    private Mrz(MrzFormat format, string[] lines)
    {
        Format = format;
        Lines = lines;
    }

    public static Mrz Parse(string text)
    {
        var lines = text.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => l.Replace(" ", "").ToUpperInvariant()).ToArray();
        var format = lines switch
        {
            [{ Length: 30 }, { Length: 30 }, { Length: 30 }] => MrzFormat.TD1,
            [{ Length: 36 }, { Length: 36 }] => MrzFormat.TD2,
            [{ Length: 44 }, { Length: 44 }] => MrzFormat.TD3,
            _ => throw new FormatException(T("MRZ muss aus 3×30 (TD1), 2×36 (TD2) oder 2×44 (TD3) Zeichen bestehen.", "The MRZ must consist of 3×30 (TD1), 2×36 (TD2) or 2×44 (TD3) characters.")),
        };
        foreach (var l in lines)
            if (l.Any(c => !(c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '<')))
                throw new FormatException(T("MRZ enthält Zeichen außerhalb des ICAO-OCR-B-Zeichensatzes (9303-3 4.2).", "The MRZ contains characters outside the ICAO OCR-B character set (9303-3 4.2)."));
        var mrz = new Mrz(format, lines);
        mrz.Decode();
        return mrz;
    }

    private void Decode()
    {
        string docNumberField, optional1;
        char docCd;
        string composite;
        switch (Format)
        {
            case MrzFormat.TD3:
            {
                var (l1, l2) = (Lines[0], Lines[1]);
                DocumentCode = l1[..2]; IssuingState = l1[2..5]; SplitName(l1[5..44]);
                docNumberField = l2[..9]; docCd = l2[9]; Nationality = l2[10..13];
                DateOfBirth = l2[13..19]; DateOfBirthCheckDigit = l2[19]; Sex = l2[20..21];
                DateOfExpiry = l2[21..27]; DateOfExpiryCheckDigit = l2[27];
                optional1 = l2[28..42];
                var personalCd = l2[42];
                Check("personalNumber", T("Persönliche Nummer", "Personal number"), optional1, personalCd, allowFillerCheckDigit: optional1.All(c => c == '<'));
                CompositeCheckDigit = l2[43];
                composite = l2[..10] + l2[13..20] + l2[21..43];
                OptionalData1 = optional1;
                DocumentNumber = docNumberField; DocumentNumberCheckDigit = docCd;
                break;
            }
            case MrzFormat.TD2:
            {
                var (l1, l2) = (Lines[0], Lines[1]);
                DocumentCode = l1[..2]; IssuingState = l1[2..5]; SplitName(l1[5..36]);
                docNumberField = l2[..9]; docCd = l2[9]; Nationality = l2[10..13];
                DateOfBirth = l2[13..19]; DateOfBirthCheckDigit = l2[19]; Sex = l2[20..21];
                DateOfExpiry = l2[21..27]; DateOfExpiryCheckDigit = l2[27];
                optional1 = l2[28..35];
                CompositeCheckDigit = l2[35];
                composite = l2[..10] + l2[13..20] + l2[21..35];
                ResolveLongDocumentNumber(docNumberField, docCd, optional1);
                break;
            }
            default:
            {
                var (l1, l2, l3) = (Lines[0], Lines[1], Lines[2]);
                DocumentCode = l1[..2]; IssuingState = l1[2..5];
                docNumberField = l1[5..14]; docCd = l1[14]; optional1 = l1[15..30];
                DateOfBirth = l2[..6]; DateOfBirthCheckDigit = l2[6]; Sex = l2[7..8];
                DateOfExpiry = l2[8..14]; DateOfExpiryCheckDigit = l2[14]; Nationality = l2[15..18];
                OptionalData2 = l2[18..29];
                CompositeCheckDigit = l2[29];
                composite = l1[5..30] + l2[..7] + l2[8..15] + l2[18..29];
                SplitName(l3);
                ResolveLongDocumentNumber(docNumberField, docCd, optional1);
                break;
            }
        }
        Check("documentNumber", T("Dokumentnummer", "Document number"), DocumentNumber, DocumentNumberCheckDigit);
        Check("dateOfBirth", T("Geburtsdatum", "Date of birth"), DateOfBirth, DateOfBirthCheckDigit);
        Check("dateOfExpiry", T("Ablaufdatum", "Date of expiry"), DateOfExpiry, DateOfExpiryCheckDigit);
        Check("composite", T("Gesamtprüfziffer", "Composite check digit"), composite, CompositeCheckDigit!.Value);
    }

    private void ResolveLongDocumentNumber(string field, char cd, string optional)
    {
        if (cd == '<')
        {
            // 9303-5 / 9303-6: number continues in the optional data, terminated by its check digit and a filler.
            var end = optional.IndexOf('<');
            var ext = end < 0 ? optional : optional[..end];
            if (ext.Length < 2) { Findings.Add(T("Verlängerte Dokumentnummer: Fortsetzung im optionalen Datenfeld fehlt.", "Extended document number: continuation in the optional data field missing.")); DocumentNumber = field; DocumentNumberCheckDigit = '<'; return; }
            DocumentNumber = field + ext[..^1];
            DocumentNumberCheckDigit = ext[^1];
            OptionalData1 = end < 0 ? "" : optional[(end + 1)..];
        }
        else
        {
            DocumentNumber = field;
            DocumentNumberCheckDigit = cd;
            OptionalData1 = optional;
        }
    }

    private void SplitName(string nameField)
    {
        var idx = nameField.IndexOf("<<", StringComparison.Ordinal);
        PrimaryIdentifier = (idx < 0 ? nameField : nameField[..idx]).Replace('<', ' ').Trim();
        SecondaryIdentifier = idx < 0 ? "" : nameField[(idx + 2)..].Replace('<', ' ').Trim();
    }

    private void Check(string key, string name, string value, char checkDigit, bool allowFillerCheckDigit = false)
    {
        bool? valid = allowFillerCheckDigit && checkDigit == '<' ? null : ComputeCheckDigit(value) == checkDigit;
        Fields.Add(new MrzField(name, value, checkDigit, valid, key));
        if (valid == false) Findings.Add(T($"Prüfziffer {name} falsch: '{checkDigit}', erwartet '{ComputeCheckDigit(value)}' (ICAO 9303-3 4.9).", $"Check digit {name} wrong: '{checkDigit}', expected '{ComputeCheckDigit(value)}' (ICAO 9303-3 4.9)."));
    }

    /// <summary>ICAO 9303-3 4.9: weights 7-3-1, A..Z = 10..35, '&lt;' = 0, result modulo 10.</summary>
    public static char ComputeCheckDigit(string value)
    {
        int[] weights = [7, 3, 1];
        var sum = 0;
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            var v = c switch
            {
                >= '0' and <= '9' => c - '0',
                >= 'A' and <= 'Z' => c - 'A' + 10,
                '<' => 0,
                _ => throw new FormatException(T($"Ungültiges MRZ-Zeichen '{c}'.", $"Invalid MRZ character '{c}'.")),
            };
            sum += v * weights[i % 3];
        }
        return (char)('0' + sum % 10);
    }

    /// <summary>'MRZ_information' for BAC/PACE key derivation (ICAO 9303-11 9.7.2, Appendix D.2).</summary>
    public string KeySeedInformation => BuildKeySeed(DocumentNumber, DocumentNumberCheckDigit, DateOfBirth, DateOfBirthCheckDigit, DateOfExpiry, DateOfExpiryCheckDigit);

    public static string BuildKeySeed(string documentNumber, char docCd, string dob, char dobCd, string doe, char doeCd)
    {
        var sb = new StringBuilder();
        // Document numbers shorter than 9 characters are padded with '<' to the full field length.
        sb.Append(documentNumber.PadRight(9, '<')).Append(docCd).Append(dob).Append(dobCd).Append(doe).Append(doeCd);
        return sb.ToString();
    }

    /// <summary>Builds the key seed from separately entered fields, computing check digits.</summary>
    public static string BuildKeySeed(string documentNumber, string dob, string doe)
    {
        var doc = documentNumber.ToUpperInvariant().PadRight(9, '<');
        return BuildKeySeed(doc, ComputeCheckDigit(doc), dob, ComputeCheckDigit(dob), doe, ComputeCheckDigit(doe));
    }
}
