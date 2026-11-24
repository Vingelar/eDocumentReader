namespace eDocumentReader.Core.Apdu;

public enum StatusCategory { NormalProcessing, Warning, ExecutionError, CheckingError, Proprietary }

/// <summary>SW1-SW2 interpretation according to ISO/IEC 7816-4:2005, 5.1.3 (Tables 5 and 6).</summary>
public readonly record struct StatusWord(byte Sw1, byte Sw2)
{
    public static readonly StatusWord Success = new(0x90, 0x00);
    public static readonly StatusWord SecurityStatusNotSatisfied = new(0x69, 0x82);
    public static readonly StatusWord ConditionsOfUseNotSatisfied = new(0x69, 0x85);
    public static readonly StatusWord SmDataObjectsMissing = new(0x69, 0x87);
    public static readonly StatusWord SmDataObjectsIncorrect = new(0x69, 0x88);
    public static readonly StatusWord FileNotFound = new(0x6A, 0x82);
    public static readonly StatusWord EndOfFile = new(0x62, 0x82);

    public ushort Value => (ushort)((Sw1 << 8) | Sw2);
    public bool IsSuccess => Sw1 == 0x90 && Sw2 == 0x00;
    public bool IsNormal => IsSuccess || Sw1 == 0x61;
    public bool IsWarning => Sw1 is 0x62 or 0x63;
    /// <summary>Process completed (normal or warning), Table 5.</summary>
    public bool IsCompleted => IsNormal || IsWarning;
    /// <summary>7816-4 5.1.3: SW1 '63' or '65' indicates that the non-volatile memory has changed.</summary>
    public bool NonVolatileMemoryChanged => Sw1 is 0x63 or 0x65;

    public StatusCategory Category => Sw1 switch
    {
        0x90 when Sw2 == 0x00 => StatusCategory.NormalProcessing,
        0x61 => StatusCategory.NormalProcessing,
        0x62 or 0x63 => StatusCategory.Warning,
        0x64 or 0x65 or 0x66 => StatusCategory.ExecutionError,
        >= 0x67 and <= 0x6F => StatusCategory.CheckingError,
        _ => StatusCategory.Proprietary,
    };

    public static StatusWord Parse(ushort value) => new((byte)(value >> 8), (byte)value);

    public string Description => Describe(Sw1, Sw2);

    private static string Describe(byte sw1, byte sw2) => (sw1, sw2) switch
    {
        (0x90, 0x00) => "Normale Verarbeitung",
        (0x61, _) => $"Normale Verarbeitung, {(sw2 == 0 ? 256 : sw2)} Bytes verfügbar (GET RESPONSE)",
        (0x62, 0x00) => "Warnung: keine Information",
        (0x62, >= 0x02 and <= 0x80) => "Warnung: durch Karte ausgelöst (8.6.1)",
        (0x62, 0x81) => "Warnung: Teil der Antwortdaten evtl. verfälscht",
        (0x62, 0x82) => "Warnung: Datei-/Recordende vor Ne Bytes erreicht",
        (0x62, 0x83) => "Warnung: ausgewählte Datei deaktiviert",
        (0x62, 0x84) => "Warnung: FCI nicht nach 5.3.3 formatiert",
        (0x62, 0x85) => "Warnung: ausgewählte Datei im Termination-Zustand",
        (0x62, 0x86) => "Warnung: keine Sensordaten verfügbar",
        (0x62, _) => "Warnung: NV-Speicher unverändert",
        (0x63, 0x00) => "Warnung: keine Information (NV-Speicher geändert)",
        (0x63, 0x81) => "Warnung: Datei durch letzten Schreibvorgang gefüllt",
        (0x63, >= 0xC0 and <= 0xCF) => $"Warnung: Zähler = {sw2 & 0x0F}",
        (0x63, _) => "Warnung: NV-Speicher geändert",
        (0x64, 0x00) => "Ausführungsfehler",
        (0x64, 0x01) => "Ausführungsfehler: sofortige Antwort erforderlich",
        (0x64, >= 0x02 and <= 0x80) => "Ausführungsfehler: durch Karte ausgelöst (8.6.1)",
        (0x64, _) => "Ausführungsfehler: NV-Speicher unverändert",
        (0x65, 0x00) => "Ausführungsfehler: keine Information (NV-Speicher geändert)",
        (0x65, 0x81) => "Ausführungsfehler: Speicherfehler",
        (0x65, _) => "Ausführungsfehler: NV-Speicher geändert",
        (0x66, _) => "Ausführungsfehler: sicherheitsrelevant",
        (0x67, 0x00) => "Falsche Länge",
        (0x67, _) => "Falsche Länge (SW2 nicht definiert)",
        (0x68, 0x00) => "Funktion in CLA nicht unterstützt",
        (0x68, 0x81) => "Logischer Kanal nicht unterstützt",
        (0x68, 0x82) => "Secure Messaging nicht unterstützt",
        (0x68, 0x83) => "Letztes Kommando der Kette erwartet",
        (0x68, 0x84) => "Command Chaining nicht unterstützt",
        (0x69, 0x00) => "Kommando nicht erlaubt",
        (0x69, 0x81) => "Kommando inkompatibel mit Dateistruktur",
        (0x69, 0x82) => "Sicherheitszustand nicht erfüllt",
        (0x69, 0x83) => "Authentisierungsmethode blockiert",
        (0x69, 0x84) => "Referenzdaten nicht verwendbar",
        (0x69, 0x85) => "Benutzungsbedingungen nicht erfüllt",
        (0x69, 0x86) => "Kommando nicht erlaubt (kein aktuelles EF)",
        (0x69, 0x87) => "Erwartete SM-Datenobjekte fehlen",
        (0x69, 0x88) => "SM-Datenobjekte fehlerhaft",
        (0x6A, 0x00) => "Falsche Parameter: keine Information",
        (0x6A, 0x80) => "Falsche Parameter im Datenfeld",
        (0x6A, 0x81) => "Funktion nicht unterstützt",
        (0x6A, 0x82) => "Datei oder Anwendung nicht gefunden",
        (0x6A, 0x83) => "Record nicht gefunden",
        (0x6A, 0x84) => "Nicht genug Speicher in der Datei",
        (0x6A, 0x85) => "Nc inkonsistent mit TLV-Struktur",
        (0x6A, 0x86) => "Falsche Parameter P1-P2",
        (0x6A, 0x87) => "Nc inkonsistent mit P1-P2",
        (0x6A, 0x88) => "Referenzierte Daten nicht gefunden",
        (0x6A, 0x89) => "Datei existiert bereits",
        (0x6A, 0x8A) => "DF-Name existiert bereits",
        (0x6B, 0x00) => "Falsche Parameter P1-P2",
        (0x6C, _) => $"Falsches Le; exakt verfügbar: {(sw2 == 0 ? 256 : sw2)}",
        (0x6D, 0x00) => "INS nicht unterstützt oder ungültig",
        (0x6E, 0x00) => "Klasse nicht unterstützt",
        (0x6F, 0x00) => "Keine genaue Diagnose",
        (>= 0x67 and <= 0x6F, _) => "Prüffehler (SW2 RFU)",
        _ => "Proprietär / nicht in ISO/IEC 7816-4 definiert",
    };

    public override string ToString() => $"{Sw1:X2}{Sw2:X2}";
}
