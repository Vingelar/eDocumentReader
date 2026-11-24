using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Transport;
using eDocumentReader.Core.Transport.Pcsc;
using eDocumentReader.Core.Util;

// Diagnostic CLI:
//   eDocumentReader.Probe [reader-substring]                      – card/application survey
//   eDocumentReader.Probe read <reader-substring> <MRZ line 2|MRZ_information> [output-dir]
//   Key: MRZ line 2 (44), MRZ_information, IDL MRZ (raw string, used as-is), or CAN:<digits>; option --idl selects the IDL application.
if (args.Length >= 3 && args[0] == "read")
{
    var idlMode = args.Contains("--idl");
    var noPace = args.Contains("--bap") || args.Contains("--bac");
    bool? chaining = args.Contains("--nochain") ? false : args.Contains("--chain") ? true : null;
    args = args.Where(a => a is not ("--idl" or "--bap" or "--bac" or "--nochain" or "--chain")).ToArray();
    var readerName = PcscTransport.ListReaders().First(r => r.Contains(args[1], StringComparison.OrdinalIgnoreCase));
    var mrzArg = args[2];
    var mrzInformation = mrzArg.Length == 44
        ? eDocumentReader.Core.Documents.Mrz.Parse("P<XXX" + new string('<', 39) + "\n" + mrzArg).KeySeedInformation
        : mrzArg;
    var output = args.Length > 3 ? args[3] : Path.Combine(Path.GetTempPath(), "opencode", "edoc_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"));
    var readLogger = new Logger(Environment.GetEnvironmentVariable("EDOC_LOG") == "detail" ? LogLevel.Detail : LogLevel.Info);
    readLogger.AddSink(new ConsoleSink());
    using var readTransport = new PcscTransport(readerName, ShareMode.Shared);
    readTransport.Reset(cold: true); // RF off/on: drop SM state of an earlier session
    eDocumentReader.Core.Documents.AccessKey key = mrzArg.StartsWith("CAN:", StringComparison.OrdinalIgnoreCase)
        ? new eDocumentReader.Core.Documents.AccessKey.CanKey(mrzArg[4..])
        : new eDocumentReader.Core.Documents.AccessKey.MrzKey(mrzInformation);
    var readOptions = new eDocumentReader.Core.Documents.EmrtdReadOptions
    {
        Key = key,
        PreferPace = !noPace,
        CommandChaining = chaining,
        Aid = idlMode ? eDocumentReader.Core.Documents.EmrtdReader.IdlAid : eDocumentReader.Core.Documents.EmrtdReader.EmrtdAid,
        ApplicationName = idlMode ? "IDL" : "eMRTD",
    };
    return ReadDocument.Run(new CardChannel(readTransport, readLogger), readOptions, output, new eDocumentReader.Core.Pki.PkiStore(Environment.GetEnvironmentVariable("EDOC_PKI_ROOT")));
}

//   eDocumentReader.Probe apdu <reader-substring> <hex APDU> [<hex APDU> …]   – raw APDUs in one card session
if (args.Length >= 3 && args[0] == "apdu")
{
    var readerName = PcscTransport.ListReaders().First(r => r.Contains(args[1], StringComparison.OrdinalIgnoreCase));
    var apduLogger = new Logger(LogLevel.Info);
    apduLogger.AddSink(new ConsoleSink());
    using var apduTransport = new PcscTransport(readerName, ShareMode.Shared);
    var apduChannel = new CardChannel(apduTransport, apduLogger);
    foreach (var a in args.Skip(2)) apduChannel.Transmit(CommandApdu.Parse(Hex.Parse(a)));
    return 0;
}

//   eDocumentReader.Probe evrc <reader-substring> [output-dir]
if (args.Length >= 2 && args[0] == "evrc")
{
    var readerName = PcscTransport.ListReaders().First(r => r.Contains(args[1], StringComparison.OrdinalIgnoreCase));
    var output = args.Length > 2 ? args[2] : Path.Combine(Path.GetTempPath(), "opencode", "evrc_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"));
    Directory.CreateDirectory(output);
    var evrcLogger = new Logger(LogLevel.Info);
    evrcLogger.AddSink(new ConsoleSink());
    using var evrcTransport = new PcscTransport(readerName, ShareMode.Shared);
    var evrc = new eDocumentReader.Core.Documents.EvrcReader(new CardChannel(evrcTransport, evrcLogger)).Read();
    foreach (var f in evrc.Files) File.WriteAllBytes(Path.Combine(output, f.Name + ".bin"), f.Data);
    Console.WriteLine();
    Console.WriteLine("=== Ablauf ===");
    foreach (var s in evrc.Steps) Console.WriteLine($"{s.Name}: {s.Outcome} – {s.Detail}");
    Console.WriteLine("=== Daten ===");
    foreach (var f in evrc.Fields)
    {
        Console.WriteLine($"{f.Path,-24} {f.TagHex,-5} {f.Name,-50} {f.Value}");
        foreach (var x in f.Findings) Console.WriteLine("    ⚠ " + x);
    }
    foreach (var sig in evrc.Signatures.Where(s => s.Certificate != null))
        Console.WriteLine($"Zertifikat Teil {sig.Part}:{Environment.NewLine}{eDocumentReader.Core.Documents.SecurityObject.Describe(sig.Certificate!)}");
    Console.WriteLine($"Dateien gespeichert in: {output}");
    if (Environment.GetEnvironmentVariable("EDOC_SET_DIR") is { Length: > 0 } setDir)
        Console.WriteLine("Set gespeichert in: " + eDocumentReader.Core.Documents.DocumentSet.Write(eDocumentReader.Core.Documents.DocumentSet.FromEvrc(evrc), setDir));
    return 0;
}

if (args.Length >= 2 && args[0] == "analyze")
{
    var analyzeLogger = new Logger(LogLevel.Warning);
    analyzeLogger.AddSink(new ConsoleSink());
    ReadDocument.Analyze(args[1], analyzeLogger, new eDocumentReader.Core.Pki.PkiStore(Environment.GetEnvironmentVariable("EDOC_PKI_ROOT")));
    return 0;
}

//   eDocumentReader.Probe pki import <files...> | pki list
if (args.Length >= 2 && args[0] == "pki")
{
    var store = new eDocumentReader.Core.Pki.PkiStore(Environment.GetEnvironmentVariable("EDOC_PKI_ROOT"));
    if (args[1] == "import")
        foreach (var f in args.Skip(2))
            try { foreach (var r in store.Import(f)) Console.WriteLine($"{r.Kind}: {r.Description}"); }
            catch (Exception ex) { Console.WriteLine($"{f}: FEHLER {ex.Message}"); }
    store.Reload();
    Console.WriteLine($"PKI-Speicher {store.Root}: {store.Cscas.Count} CSCA, {store.DocumentSigners.Count} DS, {store.Crls.Count} CRL, {store.CvCertificates.Count} CVC, {store.PrivateKeys.Count} Schlüssel, {store.TerminalCredentials().Count} Terminal-Credentials");
    foreach (var e in store.Errors) Console.WriteLine("Fehler: " + e);
    foreach (var c in store.CvCertificates) Console.WriteLine("  " + c.Describe());
    foreach (var t in store.TerminalCredentials())
    {
        Console.WriteLine($"Kettenprüfung Terminal {t.Certificate.Chr}:");
        foreach (var line in store.VerifyCvChain(t.Certificate)) Console.WriteLine("    " + line);
    }
    return 0;
}

var readers = PcscTransport.ListReaders();
Console.WriteLine("Leser:");
foreach (var r in readers) Console.WriteLine("  " + r);
var filter = args.Length > 0 ? args[0] : "EMV";
var name = readers.FirstOrDefault(r => r.Contains(filter, StringComparison.OrdinalIgnoreCase));
if (name == null) { Console.WriteLine($"Kein Leser mit '{filter}' gefunden."); return 1; }

var logger = new Logger(LogLevel.Info);
logger.AddSink(new ConsoleSink());
using var transport = new PcscTransport(name, ShareMode.Shared);
var channel = new CardChannel(transport, logger);
Console.WriteLine();
Console.WriteLine($"Verbunden: {name} ({transport.Protocol}, {transport.Interface})");
Console.WriteLine(new AtrInfo(transport.Atr).Describe());

if (transport.Interface == CardInterface.Contactless)
{
    channel.GetContactlessData(false);
    channel.GetContactlessData(true);
}

var features = ReaderFeatures.Query(transport);
Console.WriteLine("Part-10-Features: " + (features.ControlCodes.Count == 0 ? "keine" : string.Join(", ", features.ControlCodes.Keys.Select(ReaderFeatures.FeatureName))));
if (features.MaxApduDataSize is { } max) Console.WriteLine($"dwMaxAPDUDataSize: {max}");
Console.WriteLine();

// Unprotected files in the MF (ICAO 9303-10 4.7 / 9303-11 / TR-03110-3): EF.CardAccess (SFI 1C), EF.ATR/INFO (2F01), EF.DIR (2F00)
Console.WriteLine("--- MF-Dateien ---");
channel.Transmit(new CommandApdu(0x00, 0xB0, 0x9C, 0x00, null, 256), "READ BINARY EF.CardAccess (SFI 1C)");
channel.Transmit(new CommandApdu(0x00, 0xB0, 0x81, 0x00, null, 256), "READ BINARY EF.ATR/INFO (SFI 01)");
channel.Transmit(new CommandApdu(0x00, 0xB0, 0x9E, 0x00, null, 256), "READ BINARY EF.DIR (SFI 1E)");

Console.WriteLine("--- Anwendungen ---");
var aids = new (string Name, string Aid)[]
{
    ("eMRTD (ICAO 9303-10)", "A0000002471001"),
    ("eID (TR-03110-4)", "E80704007F00070302"),
    ("IDL (ISO/IEC 18013-3)", "A0000002480200"),
    ("IDL kompakt (ISO/IEC 18013-2)", "A0000002480300"),
    ("EU-Führerschein (VO 383/2012, 'EDL-01')", "A0000004564544 4C2D3031"),
    ("eVRC (EU, de-facto AID 'EVR-01')", "A000000456455652 2D3031"),
};
foreach (var (appName, aid) in aids)
{
    var r = channel.Transmit(new CommandApdu(0x00, 0xA4, 0x04, 0x0C, Hex.Parse(aid)), $"SELECT {appName}");
    Console.WriteLine($"  => {appName}: {(r.Status.IsSuccess ? "VORHANDEN" : r.Status + " " + r.Status.Description)}");
}

// Unauthenticated read attempts inside the IDL application (ISO/IEC 18013-3 Table 12, 18013-2 Annex C SFIs).
// Expected for BAP/BAC protected files: 6982 (security status not satisfied).
Console.WriteLine("--- IDL: Lesen ohne Authentisierung ---");
var idl = channel.Transmit(new CommandApdu(0x00, 0xA4, 0x04, 0x0C, Hex.Parse("A0000002480200")), "SELECT IDL");
if (idl.Status.IsSuccess)
{
    foreach (var (sfi, label) in new (byte, string)[] { (0x1E, "EF.COM"), (0x1D, "EF.SOD"), (0x01, "EF.DG1"), (0x0D, "EF.DG13"), (0x0E, "EF.DG14"), (0x1C, "EF.CardAccess") })
        channel.Transmit(new CommandApdu(0x00, 0xB0, (byte)(0x80 | sfi), 0x00, null, 4), $"READ BINARY {label} (SFI {sfi:X2}), 4 Bytes");
    channel.Transmit(new CommandApdu(0x00, 0xA4, 0x02, 0x0C, Hex.Parse("001E")), "SELECT EF.COM (FID 001E)");
    channel.Transmit(new CommandApdu(0x00, 0xB0, 0x00, 0x00, null, 4), "READ BINARY (aktuelles EF), 4 Bytes");
    channel.Transmit(new CommandApdu(0x00, 0x84, 0x00, 0x00, null, 8), "GET CHALLENGE (8 Bytes)");
}
return 0;

sealed class ConsoleSink : ILogSink
{
    public void Write(LogEntry entry) => Console.WriteLine(entry.Format());
}

