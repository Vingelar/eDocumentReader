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

    public ObservableCollection<StepItem> ReadSteps { get; } = [];
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
            AccessKeyHint = T($"Führerschein-MRZ (ISO/IEC 18013) übernommen, BAP-Konfiguration {pastedIdlMrz.Configuration}, ", $"Driving licence MRZ (ISO/IEC 18013) accepted, BAP configuration {pastedIdlMrz.Configuration}, ") +
                (pastedIdlMrz.CheckDigitValid ? T("Prüfziffer korrekt.", "check digit correct.") : T("Prüfziffer FALSCH – MRZ bitte kontrollieren.", "check digit WRONG – please check the MRZ."));
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
            var bad = mrz.Fields.Where(f => f.Valid == false && f.Key != "composite").Select(f => f.Name).ToList();
            AccessKeyHint = bad.Count == 0 ? T($"MRZ ({mrz.Format}) übernommen, Prüfziffern korrekt.", $"MRZ ({mrz.Format}) accepted, check digits correct.") : T($"Prüfziffer falsch: {string.Join(", ", bad)} – MRZ bitte kontrollieren.", $"Check digit wrong: {string.Join(", ", bad)} – please check the MRZ.");
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
            error = T("CAN muss aus 6 Ziffern bestehen.", "The CAN must consist of 6 digits.");
            return null;
        }
        // IDL: BAP key seed from characters 2–29 of the single-line MRZ (ISO/IEC 18013-3 8.2.3).
        if (pastedIdlMrz != null) return new AccessKey.MrzKey(pastedIdlMrz.BapKeySeedInformation) { IsIdlInputString = true };
        var doc = DocumentNumber.Trim().ToUpperInvariant();
        // A pasted MRZ supplies its own check digits and the extended document number (9303-3 4.2.4, 9303-11 9.7.2).
        if (pastedMrz != null && pastedMrz.DocumentNumber.TrimEnd('<') == doc && pastedMrz.DateOfBirth == DateOfBirth && pastedMrz.DateOfExpiry == DateOfExpiry)
            return new AccessKey.MrzKey(pastedMrz.KeySeedInformation);
        if (doc.Length == 0 || doc.Any(c => !(char.IsAsciiLetterUpper(c) || char.IsAsciiDigit(c) || c == '<'))) error = T("Dokumentnummer: nur A–Z, 0–9.", "Document number: A–Z, 0–9 only.");
        else if (!IsYyMmDd(DateOfBirth)) error = T("Geburtsdatum im Format JJMMTT.", "Date of birth in the format YYMMDD.");
        else if (!IsYyMmDd(DateOfExpiry)) error = T("Ablaufdatum im Format JJMMTT.", "Date of expiry in the format YYMMDD.");
        // Document numbers longer than 9 characters are handled by the MRZ parser (9303-3 4.2.4); manual entry covers up to 9.
        else if (doc.Length > 9) error = T("Dokumentnummern über 9 Zeichen bitte als vollständige MRZ einfügen.", "Please paste document numbers longer than 9 characters as the complete MRZ.");
        return error == null ? new AccessKey.MrzKey(Mrz.BuildKeySeed(doc, DateOfBirth, DateOfExpiry)) : null;
    }

    private static bool IsYyMmDd(string s) => s.Length == 6 && s.All(char.IsAsciiDigit) && int.Parse(s.AsSpan(2, 2)) is >= 1 and <= 12 && int.Parse(s.AsSpan(4, 2)) is >= 1 and <= 31;

    private bool CanReadDocument() => !IsReading && SelectedReader != null && BuildAccessKey(out _) != null;

    [RelayCommand(CanExecute = nameof(CanReadDocument))]
    private async Task ReadDocument()
    {
        var key = BuildAccessKey(out var error);
        if (key == null) { StatusText = error ?? T("Zugangsdaten unvollständig", "Access data incomplete"); return; }
        if (!IsConnected) Connect();
        if (Channel == null) return;

        IsReading = true;
        ClearResult();
        ResetOverallProgress();
        readCancellation = new CancellationTokenSource();
        var ct = readCancellation.Token;
        var channel = Channel;
        var started = DateTime.Now;
        try
        {
            // Automatic: the reader finds the application by SELECT where the standards put it (after PACE under SM,
            // or before BAC/BAP). An IDL input string only fits the IDL; an MRZ or CAN is tried with eMRTD first.
            IReadOnlyList<EmrtdReader.DocumentApplication> candidates = ApplicationChoice switch
            {
                1 => [EmrtdReader.DocumentApplication.Emrtd],
                2 => [EmrtdReader.DocumentApplication.Idl],
                _ when pastedIdlMrz != null && !UseCan => [EmrtdReader.DocumentApplication.Idl],
                _ => [EmrtdReader.DocumentApplication.Emrtd, EmrtdReader.DocumentApplication.Idl],
            };
            ReadStage = T("PKI-Speicher laden", "Loading the PKI store");
            pki ??= await Task.Run(() => new PkiStore());
            // Warm reset: afterwards the MF is the current DF (ISO/IEC 7816-4 7.1) and no SM session of an earlier
            // read is open, so EF.CardAccess is read first and without SELECT (ICAO 9303-11 4.2 step 1).
            var resetAnchor = LogSink.Count;
            var reset = await Task.Run(ResetCard);
            AddFinishedStep(new ReadStep(T("Reset der Karte", "Card reset"), reset == null ? StepOutcome.Success : StepOutcome.Warning,
                reset == null ? T("Warm-Reset, MF ist aktuelles DF (ISO/IEC 7816-4 7.1)", "warm reset, MF is the current DF (ISO/IEC 7816-4 7.1)") : T($"Reset fehlgeschlagen ({reset}) – Lesen ohne Reset", $"reset failed ({reset}) – reading without reset")), resetAnchor);
            var options = new EmrtdReadOptions
            {
                Key = key,
                PreferPace = PreferPace,
                ChipAuthentication = RunChipAuthentication,
                TerminalAuthentication = RunTerminalAuthentication,
                ActiveAuthentication = RunActiveAuthentication,
                Candidates = candidates,
            };
            var reader = new EmrtdReader(channel, pki)
            {
                Progress = p => dispatcher.BeginInvoke(() =>
                    ReadStage = p.File == null ? p.Stage : p.Total > 0 ? T($"{p.Stage} {p.File}: {p.Done} / {p.Total} Bytes", $"{p.Stage} {p.File}: {p.Done} / {p.Total} bytes") : $"{p.Stage} {p.File}"),
                StepChanged = e =>
                {
                    // Captured on the reading thread: the log entries of this step follow this index.
                    var anchor = LogSink.Count;
                    dispatcher.BeginInvoke(() => ApplyStep(e, anchor));
                },
            };
            var result = await Task.Run(() => reader.Read(options, ct), ct);
            await FlushStepEvents();
            FinishOpenSteps(cancelled: false, null);
            ReadProgress = 100;
            var isIdl = result.IsIdl;
            ShowResult(result, isIdl);
            var failed = result.Steps.Count(s => s.Outcome == StepOutcome.Failed);
            StatusText = T($"{(isIdl ? "Führerschein (IDL)" : "Dokument")} gelesen in {(DateTime.Now - started).TotalSeconds:F1} s – {result.AccessControl}{(failed > 0 ? $", {failed} Schritt(e) fehlgeschlagen" : "")}", $"{(isIdl ? "Driving licence (IDL)" : "Document")} read in {(DateTime.Now - started).TotalSeconds:F1} s – {result.AccessControl}{(failed > 0 ? $", {failed} step(s) failed" : "")}");
        }
        catch (OperationCanceledException)
        {
            await FlushStepEvents();
            FinishOpenSteps(cancelled: true, T("abgebrochen", "cancelled"));
            StatusText = T("Lesen abgebrochen", "Reading cancelled");
            Logger.Warning(LogCategory.Application, T("Lesen durch Benutzer abgebrochen", "Reading cancelled by the user"));
        }
        catch (Exception ex)
        {
            var sw = ex switch { ProtocolException { Status: { } s } => $" ({s})", AccessControlException { Status: { } a } => $" ({a})", _ => "" };
            StatusText = T($"Lesen fehlgeschlagen: {ex.Message}", $"Reading failed: {ex.Message}");
            Logger.Error(LogCategory.Application, T($"Lesen fehlgeschlagen: {ex.Message}", $"Reading failed: {ex.Message}"));
            await FlushStepEvents();
            // The reader already marked a failed access control; otherwise the running entry gets the error.
            if (!FinishOpenSteps(cancelled: false, ex.Message + sw) && ex is not AccessControlException)
                AddFinishedStep(new ReadStep(T("Lesen", "Read"), StepOutcome.Failed, ex.Message + sw), lastStepAnchor);
        }
        finally
        {
            IsReading = false;
            ReadStage = string.Empty;
            readCancellation.Dispose();
            readCancellation = null;
        }
    }

    private int lastStepAnchor = -1;

    /// <summary>Lets the step events queued by the reading thread reach the list before an attempt is closed.</summary>
    private Task FlushStepEvents() => dispatcher.InvokeAsync(() => { }, System.Windows.Threading.DispatcherPriority.Background).Task;

    /// <summary>Applies a live step event of the reader to the result list and advances the overall progress.</summary>
    private void ApplyStep(StepEvent e, int anchor)
    {
        // The entry an event refers to: the latest one with this Id that is not final yet (a provisional result may be replaced).
        var open = ReadSteps.LastOrDefault(s => s.Id == e.Id && (s.State != StepState.Done || (e.State == StepState.Done && s.Provisional)));
        switch (e.State)
        {
            case StepState.Pending:
                if (open != null) break;
                var before = e.Before == null ? null : ReadSteps.FirstOrDefault(s => s.Id == e.Before && s.State == StepState.Pending);
                if (before != null) ReadSteps.Insert(ReadSteps.IndexOf(before), new StepItem(e.Id, e.Name));
                else ReadSteps.Add(new StepItem(e.Id, e.Name));
                break;
            case StepState.Running:
                if (open == null) { open = new StepItem(e.Id, e.Name); InsertBeforeTodo(open); }
                if (open.State != StepState.Running)
                {
                    open.State = StepState.Running;
                    open.LogAnchor = anchor;
                    lastStepAnchor = anchor;
                }
                if (e.Detail != null) open.Detail = e.Detail;
                if (e.Total > 0)
                {
                    open.ShowProgress = true;
                    open.Progress = 100.0 * e.Done / e.Total;
                    open.Detail = T($"{e.Done} / {e.Total} Byte", $"{e.Done} / {e.Total} bytes");
                }
                break;
            case StepState.Done when e.Step != null:
                if (open == null) { open = new StepItem(e.Id, e.Name) { LogAnchor = lastStepAnchor }; InsertBeforeTodo(open); }
                else if (open.LogAnchor < 0) open.LogAnchor = lastStepAnchor;
                open.Finish(e.Step, e.Provisional);
                break;
            case StepState.Removed:
                var gone = ReadSteps.LastOrDefault(s => s.Id == e.Id);
                if (gone != null) ReadSteps.Remove(gone);
                break;
        }
        UpdateOverallProgress();
    }

    // Overall progress: every finished entry advances the bar by its share of what was still open when the
    // list last changed its length (new todo entries, data groups that do not exist), so it never moves backwards.
    private double progressBase;
    private double openAtBase;
    private int countAtBase;

    private void ResetOverallProgress()
    {
        ReadProgress = progressBase = openAtBase = 0;
        countAtBase = 0;
    }

    private void UpdateOverallProgress()
    {
        var open = ReadSteps.Sum(s => 1 - s.Fraction);
        if (ReadSteps.Count != countAtBase)
        {
            progressBase = ReadProgress;
            openAtBase = open;
            countAtBase = ReadSteps.Count;
        }
        if (openAtBase <= 0) return;
        var value = progressBase + (100 - progressBase) * (1 - open / openAtBase);
        if (value > ReadProgress) ReadProgress = Math.Min(value, 100);
    }

    /// <summary>Finished and running entries go before the todo entries, in the order they happen.</summary>
    private void InsertBeforeTodo(StepItem item)
    {
        var todo = ReadSteps.FirstOrDefault(s => s.State == StepState.Pending);
        if (todo != null) ReadSteps.Insert(ReadSteps.IndexOf(todo), item);
        else ReadSteps.Add(item);
    }

    /// <summary>A step of the view model itself (detection, fallback, error): result list and separator line in the log.</summary>
    private void AddFinishedStep(ReadStep step, int anchor)
    {
        InsertBeforeTodo(StepItem.From(step, anchor));
        Logger.Info(LogCategory.Application, EmrtdReader.SeparatorText(step));
        UpdateOverallProgress();
    }

    /// <summary>
    /// End of an attempt: planned entries that were not needed disappear, a running one gets the error (or is closed
    /// without result). Returns true if a running entry was marked as failed.
    /// </summary>
    private bool FinishOpenSteps(bool cancelled, string? error)
    {
        foreach (var p in ReadSteps.Where(s => s.State == StepState.Pending).ToList()) ReadSteps.Remove(p);
        var marked = false;
        foreach (var r in ReadSteps.Where(s => s.State == StepState.Running).ToList())
        {
            var outcome = cancelled ? StepOutcome.Skipped : error != null ? StepOutcome.Failed : StepOutcome.Warning;
            var step = new ReadStep(r.Name, outcome, error ?? T("ohne Ergebnis beendet", "ended without result"));
            r.Finish(step, provisional: false);
            Logger.Info(LogCategory.Application, EmrtdReader.SeparatorText(step));
            marked |= outcome == StepOutcome.Failed;
        }
        UpdateOverallProgress();
        return marked;
    }

    /// <summary>Warm reset before reading: MF current, no open SM session. Returns null or the error message.</summary>
    private string? ResetCard()
    {
        try
        {
            transport?.Reset(cold: false);
            Logger.Info(LogCategory.Reader, T("Warm-Reset vor dem Lesen", "Warm reset before reading"), transport?.Atr);
            return null;
        }
        catch (Exception ex)
        {
            Logger.Warning(LogCategory.Reader, T($"Reset fehlgeschlagen: {ex.Message}", $"Reset failed: {ex.Message}"));
            return ex.Message;
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
        ImagePanelTitle = T("DG2 – Gesichtsbild", "DG2 – facial image");
    }

    private void ShowResult(EmrtdReadResult result, bool isIdl)
    {
        lastFiles = result.Files;
        HasResult = true;
        RememberSetSource(() => DocumentSet.FromEmrtd(result, isIdl, UseCan ? Can : null), isIdl ? SetDocumentType.Idl : SetDocumentType.Icao,
            result.PassiveAuthentication?.Sod);
        foreach (var f in result.Files) FileNodes.Add(FileNode.FromFile(f, CardFiles.IsCardFile(f.Name) ? CardFiles.TagName : isIdl ? Idl.TagName : null));
        if (isIdl) { ShowIdlResult(result); SecurityReport = BuildSecurityReport(result); return; }
        DataPanelTitle = "DG1 – MRZ";
        ImagePanelTitle = T("DG2 – Gesichtsbild", "DG2 – facial image");

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
        string Check(string key)
        {
            var f = mrz.Fields.FirstOrDefault(x => x.Key == key);
            return f == null ? "" : $"{f.CheckDigit} {(f.Valid switch { true => "✔", false => T("✘ falsch", "✘ wrong"), null => "–" })}";
        }
        yield return new MrzRow("Format", mrz.Format.ToString(), "");
        yield return new MrzRow(T("Dokumenttyp", "Document type"), mrz.DocumentCode.TrimEnd('<'), "");
        yield return new MrzRow(T("Ausstellerstaat", "Issuing state"), mrz.IssuingState, "");
        yield return new MrzRow("Name", mrz.PrimaryIdentifier, "");
        yield return new MrzRow(T("Vornamen", "Given names"), mrz.SecondaryIdentifier, "");
        yield return new MrzRow(T("Dokumentnummer", "Document number"), mrz.DocumentNumber.TrimEnd('<'), Check("documentNumber"));
        yield return new MrzRow(T("Staatsangehörigkeit", "Nationality"), mrz.Nationality, "");
        yield return new MrzRow(T("Geburtsdatum (JJMMTT)", "Date of birth (YYMMDD)"), mrz.DateOfBirth, Check("dateOfBirth"));
        yield return new MrzRow(T("Geschlecht", "Sex"), mrz.Sex, "");
        yield return new MrzRow(T("Ablaufdatum (JJMMTT)", "Date of expiry (YYMMDD)"), mrz.DateOfExpiry, Check("dateOfExpiry"));
        if (mrz.OptionalData1.Trim('<').Length > 0 || mrz.Format == MrzFormat.TD3) yield return new MrzRow(T("Optionale Daten", "Optional data"), mrz.OptionalData1, Check("personalNumber"));
        if (mrz.OptionalData2.Trim('<').Length > 0) yield return new MrzRow(T("Optionale Daten 2", "Optional data 2"), mrz.OptionalData2, "");
        yield return new MrzRow(T("Gesamtprüfziffer", "Composite check digit"), "", Check("composite"));
    }

    private static string BuildSecurityReport(EmrtdReadResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine(T("=== Protokolle ===", "=== Protocols ==="));
        foreach (var s in result.Steps) sb.AppendLine($"{Symbol(s.Outcome)} {s.Name}: {s.Detail}");
        sb.AppendLine();
        if (result.PassiveAuthentication is { } pa)
        {
            sb.AppendLine("=== Passive Authentication (ICAO 9303-11 5.1) ===");
            foreach (var f in pa.Sod.Findings) sb.AppendLine("⚠ " + f);
            sb.AppendLine(T($"EF.SOD: LDSSecurityObject v{pa.Sod.Version}, Hash {pa.Sod.HashName.Name}, LDS {pa.Sod.LdsVersion ?? "-"}", $"EF.SOD: LDSSecurityObject v{pa.Sod.Version}, hash {pa.Sod.HashName.Name}, LDS {pa.Sod.LdsVersion ?? "-"}"));
            foreach (var h in pa.Hashes)
                sb.AppendLine(T($"  DG{h.DataGroup,-2} {(h.Match switch { true => "✔ Hash stimmt", false => "✘ Hash FALSCH", null => "– nicht gelesen" })}", $"  DG{h.DataGroup,-2} {(h.Match switch { true => "✔ hash matches", false => "✘ hash WRONG", null => "– not read" })}"));
            sb.AppendLine(T($"SOD-Signatur: {(pa.SignatureValid ? "✔ " : "✘ ")}{pa.SignatureDetail}", $"SOD signature: {(pa.SignatureValid ? "✔ " : "✘ ")}{pa.SignatureDetail}"));
            if (pa.Signer != null) sb.AppendLine("Document Signer:").AppendLine(Indent(SecurityObject.Describe(pa.Signer)));
            if (pa.Chain != null)
            {
                sb.AppendLine(T($"Kette DS → CSCA: {(pa.Chain.Valid ? "✔ gültig" : "✘ nicht gültig")}", $"Chain DS → CSCA: {(pa.Chain.Valid ? "✔ valid" : "✘ not valid")}"));
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
            sb.AppendLine();
        }
        if (result.File("EF.CardSecurity") is { } cardSecurity)
        {
            sb.AppendLine("=== EF.CardSecurity ===");
            try { foreach (var si in new CardSecurity(cardSecurity).Infos) sb.AppendLine("  " + si.Description); }
            catch (Exception ex) { sb.AppendLine("⚠ " + ex.Message); }
            sb.AppendLine();
        }
        sb.AppendLine("=== EF.ATR/INFO (ICAO 9303-10 3.11.1) ===");
        sb.AppendLine(result.AtrInfo != null ? Indent(result.AtrInfo.Describe())
            : T("  – nicht vorhanden (für LDS1 optional); Chaining/Extended Length nach Voreinstellung", "  – not present (optional for LDS1); chaining/extended length by default setting"));
        sb.AppendLine();
        sb.AppendLine("=== EF.DIR (ICAO 9303-10 3.11.2) ===");
        sb.AppendLine(result.Dir != null ? Indent(result.Dir.Describe())
            : T("  – nicht vorhanden (empfohlen; Pflicht, wenn mehr als LDS1 auf dem Chip ist)", "  – not present (recommended; required if more than LDS1 is on the chip)"));
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
        var dlg = new Microsoft.Win32.SaveFileDialog { Filter = T($"Originalbild (*.{ext})|*.{ext}|PNG (*.png)|*.png", $"Original image (*.{ext})|*.{ext}|PNG (*.png)|*.png"), FileName = T($"DG2_Gesicht.{ext}", $"DG2_face.{ext}") };
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
