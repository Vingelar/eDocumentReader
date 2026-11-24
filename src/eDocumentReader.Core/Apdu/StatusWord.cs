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
        (0x90, 0x00) => T("Normale Verarbeitung", "Normal processing"),
        (0x61, _) => T($"Normale Verarbeitung, {(sw2 == 0 ? 256 : sw2)} Bytes verfügbar (GET RESPONSE)", $"Normal processing, {(sw2 == 0 ? 256 : sw2)} bytes available (GET RESPONSE)"),
        (0x62, 0x00) => T("Warnung: keine Information", "Warning: no information"),
        (0x62, >= 0x02 and <= 0x80) => T("Warnung: durch Karte ausgelöst (8.6.1)", "Warning: triggered by the card (8.6.1)"),
        (0x62, 0x81) => T("Warnung: Teil der Antwortdaten evtl. verfälscht", "Warning: part of the returned data may be corrupted"),
        (0x62, 0x82) => T("Warnung: Datei-/Recordende vor Ne Bytes erreicht", "Warning: end of file/record reached before reading Ne bytes"),
        (0x62, 0x83) => T("Warnung: ausgewählte Datei deaktiviert", "Warning: selected file deactivated"),
        (0x62, 0x84) => T("Warnung: FCI nicht nach 5.3.3 formatiert", "Warning: FCI not formatted according to 5.3.3"),
        (0x62, 0x85) => T("Warnung: ausgewählte Datei im Termination-Zustand", "Warning: selected file in termination state"),
        (0x62, 0x86) => T("Warnung: keine Sensordaten verfügbar", "Warning: no input data available from a sensor"),
        (0x62, _) => T("Warnung: NV-Speicher unverändert", "Warning: non-volatile memory unchanged"),
        (0x63, 0x00) => T("Warnung: keine Information (NV-Speicher geändert)", "Warning: no information (non-volatile memory changed)"),
        (0x63, 0x81) => T("Warnung: Datei durch letzten Schreibvorgang gefüllt", "Warning: file filled up by the last write"),
        (0x63, >= 0xC0 and <= 0xCF) => T($"Warnung: Zähler = {sw2 & 0x0F}", $"Warning: counter = {sw2 & 0x0F}"),
        (0x63, _) => T("Warnung: NV-Speicher geändert", "Warning: non-volatile memory changed"),
        (0x64, 0x00) => T("Ausführungsfehler", "Execution error"),
        (0x64, 0x01) => T("Ausführungsfehler: sofortige Antwort erforderlich", "Execution error: immediate response required"),
        (0x64, >= 0x02 and <= 0x80) => T("Ausführungsfehler: durch Karte ausgelöst (8.6.1)", "Execution error: triggered by the card (8.6.1)"),
        (0x64, _) => T("Ausführungsfehler: NV-Speicher unverändert", "Execution error: non-volatile memory unchanged"),
        (0x65, 0x00) => T("Ausführungsfehler: keine Information (NV-Speicher geändert)", "Execution error: no information (non-volatile memory changed)"),
        (0x65, 0x81) => T("Ausführungsfehler: Speicherfehler", "Execution error: memory failure"),
        (0x65, _) => T("Ausführungsfehler: NV-Speicher geändert", "Execution error: non-volatile memory changed"),
        (0x66, _) => T("Ausführungsfehler: sicherheitsrelevant", "Execution error: security-related issue"),
        (0x67, 0x00) => T("Falsche Länge", "Wrong length"),
        (0x67, _) => T("Falsche Länge (SW2 nicht definiert)", "Wrong length (SW2 not defined)"),
        (0x68, 0x00) => T("Funktion in CLA nicht unterstützt", "Functions in CLA not supported"),
        (0x68, 0x81) => T("Logischer Kanal nicht unterstützt", "Logical channel not supported"),
        (0x68, 0x82) => T("Secure Messaging nicht unterstützt", "Secure messaging not supported"),
        (0x68, 0x83) => T("Letztes Kommando der Kette erwartet", "Last command of the chain expected"),
        (0x68, 0x84) => T("Command Chaining nicht unterstützt", "Command chaining not supported"),
        (0x69, 0x00) => T("Kommando nicht erlaubt", "Command not allowed"),
        (0x69, 0x81) => T("Kommando inkompatibel mit Dateistruktur", "Command incompatible with file structure"),
        (0x69, 0x82) => T("Sicherheitszustand nicht erfüllt", "Security status not satisfied"),
        (0x69, 0x83) => T("Authentisierungsmethode blockiert", "Authentication method blocked"),
        (0x69, 0x84) => T("Referenzdaten nicht verwendbar", "Reference data not usable"),
        (0x69, 0x85) => T("Benutzungsbedingungen nicht erfüllt", "Conditions of use not satisfied"),
        (0x69, 0x86) => T("Kommando nicht erlaubt (kein aktuelles EF)", "Command not allowed (no current EF)"),
        (0x69, 0x87) => T("Erwartete SM-Datenobjekte fehlen", "Expected SM data objects missing"),
        (0x69, 0x88) => T("SM-Datenobjekte fehlerhaft", "Incorrect SM data objects"),
        (0x6A, 0x00) => T("Falsche Parameter: keine Information", "Wrong parameters: no information"),
        (0x6A, 0x80) => T("Falsche Parameter im Datenfeld", "Incorrect parameters in the command data field"),
        (0x6A, 0x81) => T("Funktion nicht unterstützt", "Function not supported"),
        (0x6A, 0x82) => T("Datei oder Anwendung nicht gefunden", "File or application not found"),
        (0x6A, 0x83) => T("Record nicht gefunden", "Record not found"),
        (0x6A, 0x84) => T("Nicht genug Speicher in der Datei", "Not enough memory space in the file"),
        (0x6A, 0x85) => T("Nc inkonsistent mit TLV-Struktur", "Nc inconsistent with TLV structure"),
        (0x6A, 0x86) => T("Falsche Parameter P1-P2", "Incorrect parameters P1-P2"),
        (0x6A, 0x87) => T("Nc inkonsistent mit P1-P2", "Nc inconsistent with parameters P1-P2"),
        (0x6A, 0x88) => T("Referenzierte Daten nicht gefunden", "Referenced data not found"),
        (0x6A, 0x89) => T("Datei existiert bereits", "File already exists"),
        (0x6A, 0x8A) => T("DF-Name existiert bereits", "DF name already exists"),
        (0x6B, 0x00) => T("Falsche Parameter P1-P2", "Incorrect parameters P1-P2"),
        (0x6C, _) => T($"Falsches Le; exakt verfügbar: {(sw2 == 0 ? 256 : sw2)}", $"Wrong Le; exact number available: {(sw2 == 0 ? 256 : sw2)}"),
        (0x6D, 0x00) => T("INS nicht unterstützt oder ungültig", "Instruction code not supported or invalid"),
        (0x6E, 0x00) => T("Klasse nicht unterstützt", "Class not supported"),
        (0x6F, 0x00) => T("Keine genaue Diagnose", "No precise diagnosis"),
        (>= 0x67 and <= 0x6F, _) => T("Prüffehler (SW2 RFU)", "Checking error (SW2 RFU)"),
        _ => T("Proprietär / nicht in ISO/IEC 7816-4 definiert", "Proprietary / not defined in ISO/IEC 7816-4"),
    };

    public override string ToString() => $"{Sw1:X2}{Sw2:X2}";
}
