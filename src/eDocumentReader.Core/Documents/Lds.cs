namespace eDocumentReader.Core.Documents;

/// <summary>Logical Data Structure constants of the eMRTD application (ICAO 9303-10 4.6/4.7, Table 34).</summary>
public static class Lds
{
    public const byte SfiCom = 0x1E;
    public const byte SfiSod = 0x1D;
    public const byte SfiCvca = 0x1C;
    public const byte SfiCardAccess = 0x1C;

    /// <summary>LDS tag to data group number (ICAO 9303-10 Table 34). 0 = unknown tag.</summary>
    public static int DataGroupNumber(byte tag) => tag switch
    {
        0x61 => 1, 0x75 => 2, 0x63 => 3, 0x76 => 4, 0x65 => 5, 0x66 => 6, 0x67 => 7, 0x68 => 8,
        0x69 => 9, 0x6A => 10, 0x6B => 11, 0x6C => 12, 0x6D => 13, 0x6E => 14, 0x6F => 15, 0x70 => 16,
        _ => 0,
    };

    /// <summary>The SFI of EF.DGn is n (ICAO 9303-10 Table 34).</summary>
    public static byte DataGroupSfi(int dg) => (byte)dg;

    /// <summary>DG3 and DG4 are protected by Extended Access Control (ICAO 9303-11 7, BSI TR-03110-1).</summary>
    public static bool IsEacProtected(int dg) => dg is 3 or 4;

    public static string DataGroupContent(int dg) => dg switch
    {
        1 => "MRZ",
        2 => T("Gesichtsbild", "Facial image"),
        3 => T("Fingerabdrücke", "Fingerprints"),
        4 => "Iris",
        5 => T("Porträt (angezeigt)", "Displayed portrait"),
        6 => T("reserviert", "reserved"),
        7 => T("Unterschrift/Handzeichen", "Signature/usual mark"),
        8 => T("Datenmerkmale", "Data features"),
        9 => T("Strukturmerkmale", "Structure features"),
        10 => T("Substanzmerkmale", "Substance features"),
        11 => T("Weitere Personendaten", "Additional personal details"),
        12 => T("Weitere Dokumentdaten", "Additional document details"),
        13 => T("Optionale Details", "Optional details"),
        14 => T("Sicherheitsoptionen (CA/PACE/TA)", "Security options (CA/PACE/TA)"),
        15 => T("AA-Public-Key", "AA public key"),
        16 => T("Notfallkontakte", "Persons to notify"),
        _ => "",
    };

    /// <summary>Display names of LDS data objects (ICAO 9303-10 4.6/4.7, ISO/IEC 7816-11 for the biometric templates).</summary>
    public static string? TagName(uint tag) => tag switch
    {
        0x60 => "EF.COM",
        0x5F01 => T("LDS-Version", "LDS version"),
        0x5F36 => T("Unicode-Version", "Unicode version"),
        0x5C => T("Tag-Liste", "Tag list"),
        0x61 => "EF.DG1",
        0x5F1F => "MRZ",
        0x75 => "EF.DG2",
        0x63 => "EF.DG3",
        0x76 => "EF.DG4",
        0x67 => "EF.DG7",
        0x6B => "EF.DG11",
        0x6C => "EF.DG12",
        0x6E => "EF.DG14",
        0x6F => "EF.DG15",
        0x77 => "EF.SOD",
        0x7F61 => "Biometric Information Group Template",
        0x7F60 => "Biometric Information Template",
        0xA1 => "Biometric Header Template",
        0x5F2E => "Biometric Data Block",
        0x7F2E => T("Biometric Data Block (konstruiert)", "Biometric Data Block (constructed)"),
        0x02 => T("Anzahl/Integer", "Number/integer"),
        0x80 => T("Version/Kontext 0", "Version/context 0"),
        0x81 => T("Biometrischer Typ/Kontext 1", "Biometric type/context 1"),
        0x82 => T("Biometrischer Subtyp/Kontext 2", "Biometric subtype/context 2"),
        0x83 => T("Erstellungsdatum/Kontext 3", "Creation date/context 3"),
        0x85 => T("Gültigkeit/Kontext 5", "Validity/context 5"),
        0x86 => T("Hersteller/Kontext 6", "Creator/context 6"),
        0x87 => "Format-Owner",
        0x88 => T("Format-Typ", "Format type"),
        0x5F0E => "Name",
        0x5F0F => T("Weitere Namen", "Other names"),
        0x5F10 => T("Persönliche Nummer", "Personal number"),
        0x5F11 => T("Geburtsort", "Place of birth"),
        0x5F42 => T("Anschrift", "Address"),
        0x5F12 => T("Telefon", "Telephone"),
        0x5F13 => T("Beruf", "Profession"),
        0x5F14 => T("Titel", "Title"),
        0x5F15 => T("Personalien", "Personal summary"),
        0x5F2B => T("Geburtsdatum (vollständig)", "Full date of birth"),
        0x5F19 => T("Ausstellende Behörde", "Issuing authority"),
        0x5F26 => T("Ausstellungsdatum", "Date of issue"),
        0x5F1A => T("Andere Personen", "Other persons"),
        0x5F1B => T("Bemerkungen", "Endorsements/observations"),
        0x5F1C => T("Steuer-/Ausreisevermerk", "Tax/exit requirements"),
        0x5F55 => T("Personalisierungszeitpunkt", "Date and time of personalization"),
        0x5F56 => T("Personalisierungsgerät", "Personalization system serial number"),
        0x5F43 => T("Unterschrift/Handzeichen-Bild", "Image of signature/usual mark"),
        0x30 => "SEQUENCE",
        0x31 => "SET",
        0x06 => "OBJECT IDENTIFIER",
        0x04 => "OCTET STRING",
        0x03 => "BIT STRING",
        0x42 => "CAR",
        _ => null,
    };

    /// <summary>Extracts the MRZ text from DG1: '61' → '5F1F' (ICAO 9303-10 4.7.1), split into its lines.</summary>
    public static Mrz? ParseDg1(byte[] dg1)
    {
        var mrzObject = Tlv.BerTlv.ParseSingle(dg1).Find(0x5F1F);
        if (mrzObject == null) return null;
        var text = System.Text.Encoding.ASCII.GetString(mrzObject.Value);
        var lineLength = text.Length switch { 90 => 30, 72 => 36, 88 => 44, _ => 0 };
        if (lineLength == 0) throw new FormatException(T($"DG1: MRZ-Länge {text.Length} entspricht keinem Format (90/72/88, ICAO 9303-10 4.7.1).", $"DG1: MRZ length {text.Length} matches no format (90/72/88, ICAO 9303-10 4.7.1)."));
        return Mrz.Parse(string.Join('\n', text.Chunk(lineLength).Select(c => new string(c))));
    }
}
