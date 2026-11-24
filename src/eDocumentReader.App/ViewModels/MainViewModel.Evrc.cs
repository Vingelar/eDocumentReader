using System.Collections.ObjectModel;
using System.Text;
using CommunityToolkit.Mvvm.Input;
using eDocumentReader.Core.Documents;
using eDocumentReader.Core.Logging;

namespace eDocumentReader.App.ViewModels;

/// <summary>Electronic vehicle registration certificate (Directive 2003/127/EC): freely readable, no access key.</summary>
public sealed partial class MainViewModel
{
    public ObservableCollection<EvrcField> EvrcFields { get; } = [];

    private bool CanReadEvrc() => !IsReading && SelectedReader != null;

    [RelayCommand(CanExecute = nameof(CanReadEvrc))]
    private async Task ReadEvrc()
    {
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
            var reader = new EvrcReader(channel)
            {
                Progress = p => dispatcher.BeginInvoke(() =>
                {
                    ReadStage = p.File == null ? p.Stage : p.Total > 0 ? T($"{p.Stage} {p.File}: {p.Done} / {p.Total} Bytes", $"{p.Stage} {p.File}: {p.Done} / {p.Total} bytes") : $"{p.Stage} {p.File}";
                    ReadProgress = p.Total > 0 ? 100.0 * p.Done / p.Total : 0;
                }),
            };
            var result = await Task.Run(() => reader.Read(ct), ct);
            ShowEvrcResult(result);
            var failed = result.Steps.Count(s => s.Outcome == StepOutcome.Failed);
            StatusText = T($"Zulassungsbescheinigung gelesen in {(DateTime.Now - started).TotalSeconds:F1} s – {result.Findings.Count} Befund(e){(failed > 0 ? $", {failed} Schritt(e) fehlgeschlagen" : "")}", $"Registration certificate read in {(DateTime.Now - started).TotalSeconds:F1} s – {result.Findings.Count} finding(s){(failed > 0 ? $", {failed} step(s) failed" : "")}");
        }
        catch (OperationCanceledException)
        {
            StatusText = T("Lesen abgebrochen", "Reading cancelled");
        }
        catch (Exception ex)
        {
            StatusText = T($"Lesen fehlgeschlagen: {ex.Message}", $"Reading failed: {ex.Message}");
            ReadSteps.Add(new ReadStep(T("Lesen", "Read"), StepOutcome.Failed, ex.Message));
            Logger.Error(LogCategory.Application, T($"eVRC lesen fehlgeschlagen: {ex.Message}", $"Reading the eVRC failed: {ex.Message}"));
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

    private void ShowEvrcResult(EvrcReadResult result)
    {
        lastFiles = result.Files;
        HasResult = true;
        RememberSetSource(() => DocumentSet.FromEvrc(result), SetDocumentType.Evrc, null);
        foreach (var s in result.Steps) ReadSteps.Add(s);
        if (result.Findings.Count > 0)
            ReadSteps.Add(new ReadStep(T("Normkonformität", "Conformance"), StepOutcome.Warning, T($"{result.Findings.Count} Abweichung(en), siehe Tab „Sicherheit“", $"{result.Findings.Count} deviation(s), see tab 'Security'")));
        foreach (var f in result.Files) FileNodes.Add(FileNode.FromFile(f, Evrc.TagName));
        foreach (var f in result.Fields) EvrcFields.Add(f);
        SecurityReport = BuildEvrcReport(result);
    }

    private static string BuildEvrcReport(EvrcReadResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine(T("=== Zulassungsbescheinigung Teil I (RL 2003/127/EG) ===", "=== Registration certificate Part I (Directive 2003/127/EC) ==="));
        foreach (var s in result.Steps) sb.AppendLine($"{Symbol(s.Outcome)} {s.Name}: {s.Detail}");
        sb.AppendLine();
        sb.AppendLine(T("=== Signaturen (Anhang III.2 D / III.12 C) ===", "=== Signatures (Annex III.2 D / III.12 C) ==="));
        foreach (var sig in result.Signatures)
        {
            sb.AppendLine(T($"Teil {sig.Part}: {(sig.Valid switch { true => "✔", false => "✘", null => "–" })} {sig.Detail}", $"Part {sig.Part}: {(sig.Valid switch { true => "✔", false => "✘", null => "–" })} {sig.Detail}"));
            if (sig.Certificate != null) sb.AppendLine(Indent(SecurityObject.Describe(sig.Certificate)));
        }
        // The directive leaves trust anchors for the issuing authority certificates to the Member States (III.12 C).
        sb.AppendLine(T("Hinweis: Die Ausstellerzertifikate werden nicht gegen einen Vertrauensanker geprüft; die Richtlinie überlässt das den Mitgliedstaaten (III.12 C).", "Note: the issuer certificates are not checked against a trust anchor; the directive leaves this to the Member States (III.12 C)."));
        sb.AppendLine();
        sb.AppendLine(T($"=== Befunde ({result.Findings.Count}) ===", $"=== Findings ({result.Findings.Count}) ==="));
        foreach (var f in result.Findings) sb.AppendLine("⚠ " + f);
        return sb.ToString();
    }
}
