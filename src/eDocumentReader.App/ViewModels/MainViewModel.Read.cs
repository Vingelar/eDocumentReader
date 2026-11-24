using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Windows.Media.Imaging;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using eDocumentReader.App.Imaging;
using eDocumentReader.Core.Documents;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Pki;
using eDocumentReader.Core.Protocols;
using eDocumentReader.Core.Tlv;

namespace eDocumentReader.App.ViewModels;

public sealed record MrzRow(string Name, string Value, string Check);

/// <summary>Document readout: access key input, inspection procedure, prepared display of the result.</summary>
public sealed partial class MainViewModel
{
    private CancellationTokenSource? readCancellation;
    private PkiStore? pki;
    private List<EmrtdFile> lastFiles = [];
    private List<FaceImage> faces = [];
    private Mrz? pastedMrz;
    private IdlMrz? pastedIdlMrz;

    // Access key. Personal data stays in memory only and is never written to settings or logs.
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(ReadDocumentCommand))] private bool useCan;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(ReadDocumentCommand))] private string documentNumber = string.Empty;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(ReadDocumentCommand))] private string dateOfBirth = string.Empty;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(ReadDocumentCommand))] private string dateOfExpiry = string.Empty;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(ReadDocumentCommand))] private string can = string.Empty;
    [ObservableProperty] private string mrzInput = string.Empty;
    [ObservableProperty] private string accessKeyHint = string.Empty;

    /// <summary>0 = automatic (IDL application present?), 1 = eMRTD (ICAO 9303), 2 = IDL (ISO/IEC 18013-3).</summary>
    [ObservableProperty] private int applicationChoice;
    [ObservableProperty] private bool preferPace = true;
    [ObservableProperty] private bool runChipAuthentication = true;
    [ObservableProperty] private bool runTerminalAuthentication = true;
    [ObservableProperty] private bool runActiveAuthentication = true;

    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(ReadDocumentCommand), nameof(CancelReadCommand), nameof(ConnectCommand), nameof(DisconnectCommand), nameof(ReadEvrcCommand))] private bool isReading;
    [ObservableProperty] private double readProgress;
    [ObservableProperty] private string readStage = string.Empty;

    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(SaveSetCommand))] private bool hasResult;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(SaveFaceImageCommand))] private BitmapSource? faceBitmap;
    [ObservableProperty] private string faceInfo = string.Empty;
    [ObservableProperty] private string mrzText = string.Empty;
    [ObservableProperty] private string mrzFindings = string.Empty;
    [ObservableProperty] private string securityReport = string.Empty;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(SaveSelectedFileCommand))] private FileNode? selectedFileNode;

    public ObservableCollection<ReadStep> ReadSteps { get; } = [];
    public ObservableCollection<MrzRow> MrzRows { get; } = [];
    public ObservableCollection<FileNode> FileNodes { get; } = [];

    /// <summary>Accepts a complete MRZ (TD1/TD2/TD3) or the second TD3 line and fills the three key fields.</summary>
    partial void OnMrzInputChanged(string value)
    {
        var text = value.Trim();
        pastedMrz = null;
        pastedIdlMrz = null;
        if (text.Length == 0) { AccessKeyHint = string.Empty; ReadDocumentCommand.NotifyCanExecuteChanged(); return; }
        if (IdlMrz.LooksLikeIdlMrz(text))
        {
            pastedIdlMrz = IdlMrz.Parse(text);
            ReadDocumentCommand.NotifyCanExecuteChanged();
            AccessKeyHint = $"Führerschein-MRZ (ISO/IEC 18013) übernommen, BAP-Konfiguration {pastedIdlMrz.Configuration}, " +
                (pastedIdlMrz.CheckDigitValid ? "Prüfziffer korrekt." : "Prüfziffer FALSCH – MRZ bitte kontrollieren.");
            return;
        }
        try
        {
            var compact = text.Replace(" ", "").Replace("\r", "");
            var mrz = compact.Length == 44 && !compact.Contains('\n')
                ? Mrz.Parse("P<XXX" + new string('<', 39) + "\n" + compact)
                : Mrz.Parse(text);
            pastedMrz = mrz;
            DocumentNumber = mrz.DocumentNumber.TrimEnd('<');
            DateOfBirth = mrz.DateOfBirth;
            DateOfExpiry = mrz.DateOfExpiry;
            ReadDocumentCommand.NotifyCanExecuteChanged();
            var bad = mrz.Fields.Where(f => f.Valid == false && f.Name is not "Gesamtprüfziffer").Select(f => f.Name).ToList();
            AccessKeyHint = bad.Count == 0 ? $"MRZ ({mrz.Format}) übernommen, Prüfziffern korrekt." : $"Prüfziffer falsch: {string.Join(", ", bad)} – MRZ bitte kontrollieren.";
        }
        catch (FormatException ex)
        {
            AccessKeyHint = ex.Message;
        }
    }

    private AccessKey? BuildAccessKey(out string? error)
    {
        error = null;
        if (UseCan)
        {
            // CAN: 6 digits (ICAO 9303-11 9.7.3 / BSI TR-03110).
            if (Can.Length == 6 && Can.All(char.IsAsciiDigit)) return new AccessKey.CanKey(Can);
            error = "CAN muss aus 6 Ziffern bestehen.";
            return null;
        }
        // IDL: BAP key seed from characters 2–29 of the single-line MRZ (ISO/IEC 18013-3 8.2.3).
        if (pastedIdlMrz != null) return new AccessKey.MrzKey(pastedIdlMrz.BapKeySeedInformation);
        var doc = DocumentNumber.Trim().ToUpperInvariant();
        // A pasted MRZ supplies its own check digits and the extended document number (9303-3 4.2.4, 9303-11 9.7.2).
        if (pastedMrz != null && pastedMrz.DocumentNumber.TrimEnd('<') == doc && pastedMrz.DateOfBirth == DateOfBirth && pastedMrz.DateOfExpiry == DateOfExpiry)
            return new AccessKey.MrzKey(pastedMrz.KeySeedInformation);
        if (doc.Length == 0 || doc.Any(c => !(char.IsAsciiLetterUpper(c) || char.IsAsciiDigit(c) || c == '<'))) error = "Dokumentnummer: nur A–Z, 0–9.";
        else if (!IsYyMmDd(DateOfBirth)) error = "Geburtsdatum im Format JJMMTT.";
        else if (!IsYyMmDd(DateOfExpiry)) error = "Ablaufdatum im Format JJMMTT.";
        // Document numbers longer than 9 characters are handled by the MRZ parser (9303-3 4.2.4); manual entry covers up to 9.
        else if (doc.Length > 9) error = "Dokumentnummern über 9 Zeichen bitte als vollständige MRZ einfügen.";
        return error == null ? new AccessKey.MrzKey(Mrz.BuildKeySeed(doc, DateOfBirth, DateOfExpiry)) : null;
    }

    private static bool IsYyMmDd(string s) => s.Length == 6 && s.All(char.IsAsciiDigit) && int.Parse(s.AsSpan(2, 2)) is >= 1 and <= 12 && int.Parse(s.AsSpan(4, 2)) is >= 1 and <= 31;

    private bool CanReadDocument() => !IsReading && SelectedReader != null && BuildAccessKey(out _) != null;

    [RelayCommand(CanExecute = nameof(CanReadDocument))]
    private async Task ReadDocument()
    {
        var key = BuildAccessKey(out var error);
        if (key == null) { StatusText = error ?? "Zugangsdaten unvollständig"; return; }
        if (!IsConnected) Connect();
        if (Channel == null) return;

        IsReading = true;
        ClearResult();
        readCancellation = new CancellationTokenSource();
        var ct = readCancellation.Token;
        var channel = Channel;
        var started = DateTime.Now;
        try
        {
            var application = ApplicationChoice switch
            {
                1 => EmrtdReader.DocumentApplication.Emrtd,
                2 => EmrtdReader.DocumentApplication.Idl,
                _ => await Task.Run(() => EmrtdReader.DetectApplication(channel), ct),
            };
            var isIdl = application == EmrtdReader.DocumentApplication.Idl;
            if (!isIdl && pastedIdlMrz != null && !UseCan)
                throw new ProtocolException("Führerschein-MRZ eingegeben, auf der Karte ist aber keine IDL-Anwendung (ISO/IEC 18013-3) auswählbar.");
            var options = new EmrtdReadOptions
            {
                Key = key,
                Aid = isIdl ? EmrtdReader.IdlAid : EmrtdReader.EmrtdAid,
                ApplicationName = isIdl ? "IDL" : "eMRTD",
                PreferPace = PreferPace,
                ChipAuthentication = RunChipAuthentication,
                TerminalAuthentication = RunTerminalAuthentication,
                ActiveAuthentication = RunActiveAuthentication,
            };
            ReadStage = "PKI-Speicher laden";
            pki ??= await Task.Run(() => new PkiStore());
            var reader = new EmrtdReader(channel, pki)
            {
                Progress = p => dispatcher.BeginInvoke(() =>
                {
                    ReadStage = p.File == null ? p.Stage : p.Total > 0 ? $"{p.Stage} {p.File}: {p.Done} / {p.Total} Bytes" : $"{p.Stage} {p.File}";
                    ReadProgress = p.Total > 0 ? 100.0 * p.Done / p.Total : 0;
                }),
            };
            var result = await Task.Run(() => reader.Read(options, ct), ct);
            ShowResult(result, isIdl);
            var failed = result.Steps.Count(s => s.Outcome == StepOutcome.Failed);
            StatusText = $"{(isIdl ? "Führerschein (IDL)" : "Dokument")} gelesen in {(DateTime.Now - started).TotalSeconds:F1} s – {result.AccessControl}{(failed > 0 ? $", {failed} Schritt(e) fehlgeschlagen" : "")}";
        }
        catch (OperationCanceledException)
        {
            StatusText = "Lesen abgebrochen";
            Logger.Warning(LogCategory.Application, "Lesen durch Benutzer abgebrochen");
        }
        catch (Exception ex)
        {
            var sw = ex is ProtocolException { Status: { } s } ? $" ({s})" : "";
            StatusText = $"Lesen fehlgeschlagen: {ex.Message}";
            ReadSteps.Add(new ReadStep("Lesen", StepOutcome.Failed, ex.Message + sw));
            Logger.Error(LogCategory.Application, $"Lesen fehlgeschlagen: {ex.Message}");
        }
        finally
        {
            IsReading = false;
            ReadStage = string.Empty;
            ReadProgress = 0;
            readCancellation.Dispose();
            readCancellation = null;
        }
    }

    [RelayCommand(CanExecute = nameof(IsReading))]
    private void CancelRead() => readCancellation?.Cancel();

    private void ClearResult()
    {
        lastFiles = [];
        faces = [];
        EvrcFields.Clear();
        HasResult = false;
        ReadSteps.Clear();
        MrzRows.Clear();
        FileNodes.Clear();
        FaceBitmap = null;
        FaceInfo = MrzText = MrzFindings = SecurityReport = string.Empty;
        IdlFields.Clear();
        SignatureBitmap = null;
        idlPortrait = null;
        DataPanelTitle = "DG1 – MRZ";
        ImagePanelTitle = "DG2 – Gesichtsbild";
    }

    private void ShowResult(EmrtdReadResult result, bool isIdl)
    {
        lastFiles = result.Files;
        HasResult = true;
        RememberSetSource(() => DocumentSet.FromEmrtd(result, isIdl, UseCan ? Can : null), isIdl ? SetDocumentType.Idl : SetDocumentType.Icao,
            result.PassiveAuthentication?.Sod);
        foreach (var s in result.Steps) ReadSteps.Add(s);
        foreach (var f in result.Files) FileNodes.Add(FileNode.FromFile(f, isIdl ? Idl.TagName : null));
        if (isIdl) { ShowIdlResult(result); SecurityReport = BuildSecurityReport(result); return; }
        DataPanelTitle = "DG1 – MRZ";
        ImagePanelTitle = "DG2 – Gesichtsbild";

        // IDL data groups have their own structure (ISO/IEC 18013-2 Annex C); here they are shown in the file tree only.
        if (!isIdl && result.DataGroups.TryGetValue(1, out var dg1))
        {
            try
            {
                var mrz = Lds.ParseDg1(dg1);
                if (mrz != null)
                {
                    MrzText = string.Join(Environment.NewLine, mrz.Lines);
                    foreach (var row in BuildMrzRows(mrz)) MrzRows.Add(row);
                    MrzFindings = string.Join(Environment.NewLine, mrz.Findings.Select(f => "⚠ " + f));
                }
            }
            catch (Exception ex) { MrzFindings = "⚠ DG1: " + ex.Message; }
        }

        if (!isIdl && result.DataGroups.TryGetValue(2, out var dg2))
        {
            try
            {
                faces = FaceImageParser.ParseDg2(dg2);
                var first = faces.FirstOrDefault(f => f.ImageData.Length > 0);
                if (first != null) FaceBitmap = FaceImageDecoder.Decode(first);
                FaceInfo = string.Join(Environment.NewLine, faces.Select(f => f.Describe()).Concat(faces.SelectMany(f => f.Findings).Select(f => "⚠ " + f)));
            }
            catch (Exception ex) { FaceInfo = "⚠ DG2: " + ex.Message; }
        }
        SecurityReport = BuildSecurityReport(result);
    }

    private static IEnumerable<MrzRow> BuildMrzRows(Mrz mrz)
    {
        string Check(string field)
        {
            var f = mrz.Fields.FirstOrDefault(x => x.Name == field);
            return f == null ? "" : $"{f.CheckDigit} {(f.Valid switch { true => "✔", false => "✘ falsch", null => "–" })}";
        }
        yield return new MrzRow("Format", mrz.Format.ToString(), "");
        yield return new MrzRow("Dokumenttyp", mrz.DocumentCode.TrimEnd('<'), "");
        yield return new MrzRow("Ausstellerstaat", mrz.IssuingState, "");
        yield return new MrzRow("Name", mrz.PrimaryIdentifier, "");
        yield return new MrzRow("Vornamen", mrz.SecondaryIdentifier, "");
        yield return new MrzRow("Dokumentnummer", mrz.DocumentNumber.TrimEnd('<'), Check("Dokumentnummer"));
        yield return new MrzRow("Staatsangehörigkeit", mrz.Nationality, "");
        yield return new MrzRow("Geburtsdatum (JJMMTT)", mrz.DateOfBirth, Check("Geburtsdatum"));
        yield return new MrzRow("Geschlecht", mrz.Sex, "");
        yield return new MrzRow("Ablaufdatum (JJMMTT)", mrz.DateOfExpiry, Check("Ablaufdatum"));
        if (mrz.OptionalData1.Trim('<').Length > 0 || mrz.Format == MrzFormat.TD3) yield return new MrzRow("Optionale Daten", mrz.OptionalData1, Check("Persönliche Nummer"));
        if (mrz.OptionalData2.Trim('<').Length > 0) yield return new MrzRow("Optionale Daten 2", mrz.OptionalData2, "");
        yield return new MrzRow("Gesamtprüfziffer", "", Check("Gesamtprüfziffer"));
    }

    private static string BuildSecurityReport(EmrtdReadResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Protokolle ===");
        foreach (var s in result.Steps) sb.AppendLine($"{Symbol(s.Outcome)} {s.Name}: {s.Detail}");
        sb.AppendLine();
        if (result.PassiveAuthentication is { } pa)
        {
            sb.AppendLine("=== Passive Authentication (ICAO 9303-11 5.1) ===");
            foreach (var f in pa.Sod.Findings) sb.AppendLine("⚠ " + f);
            sb.AppendLine($"EF.SOD: LDSSecurityObject v{pa.Sod.Version}, Hash {pa.Sod.HashName.Name}, LDS {pa.Sod.LdsVersion ?? "-"}");
            foreach (var h in pa.Hashes)
                sb.AppendLine($"  DG{h.DataGroup,-2} {(h.Match switch { true => "✔ Hash stimmt", false => "✘ Hash FALSCH", null => "– nicht gelesen" })}");
            sb.AppendLine($"SOD-Signatur: {(pa.SignatureValid ? "✔ " : "✘ ")}{pa.SignatureDetail}");
            if (pa.Signer != null) sb.AppendLine("Document Signer:").AppendLine(Indent(SecurityObject.Describe(pa.Signer)));
            if (pa.Chain != null)
            {
                sb.AppendLine($"Kette DS → CSCA: {(pa.Chain.Valid ? "✔ gültig" : "✘ nicht gültig")}");
                foreach (var s in pa.Chain.Steps) sb.AppendLine("  " + s);
            }
            sb.AppendLine();
        }
        if (result.DataGroups.TryGetValue(14, out var dg14))
        {
            sb.AppendLine("=== DG14 SecurityInfos (ICAO 9303-11 9.2) ===");
            try { foreach (var si in SecurityInfos.Parse(BerTlv.ParseSingle(dg14).Value)) sb.AppendLine("  " + si.Description); }
            catch (Exception ex) { sb.AppendLine("⚠ " + ex.Message); }
            sb.AppendLine();
        }
        if (result.File("EF.CardAccess") is { } cardAccess)
        {
            sb.AppendLine("=== EF.CardAccess ===");
            try { foreach (var si in SecurityInfos.Parse(cardAccess)) sb.AppendLine("  " + si.Description); }
            catch (Exception ex) { sb.AppendLine("⚠ " + ex.Message); }
        }
        return sb.ToString();
    }

    private static string Indent(string s) => "  " + s.Replace(Environment.NewLine, Environment.NewLine + "  ");

    public static string Symbol(StepOutcome o) => o switch
    {
        StepOutcome.Success => "✔",
        StepOutcome.Failed => "✘",
        StepOutcome.Skipped => "–",
        StepOutcome.Warning => "⚠",
        _ => "○",
    };


    private bool CanSaveFaceImage() => FaceBitmap != null;

    [RelayCommand(CanExecute = nameof(CanSaveFaceImage))]
    private void SaveFaceImage()
    {
        if (idlPortrait != null) { SaveIdlPortrait(idlPortrait); return; }
        var face = faces.FirstOrDefault(f => f.ImageData.Length > 0);
        if (face == null) return;
        var ext = face.DataType == FaceImageDataType.Jpeg ? "jpg" : "jp2";
        var dlg = new Microsoft.Win32.SaveFileDialog { Filter = $"Originalbild (*.{ext})|*.{ext}|PNG (*.png)|*.png", FileName = $"DG2_Gesicht.{ext}" };
        if (dlg.ShowDialog() != true) return;
        if (dlg.FilterIndex == 2 && FaceBitmap != null)
        {
            using var fs = File.Create(dlg.FileName);
            var enc = new PngBitmapEncoder();
            enc.Frames.Add(BitmapFrame.Create(FaceBitmap));
            enc.Save(fs);
        }
        else File.WriteAllBytes(dlg.FileName, face.ImageData);
    }
}
