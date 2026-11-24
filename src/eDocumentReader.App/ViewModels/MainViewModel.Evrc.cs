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
                    ReadStage = p.File == null ? p.Stage : p.Total > 0 ? $"{p.Stage} {p.File}: {p.Done} / {p.Total} Bytes" : $"{p.Stage} {p.File}";
                    ReadProgress = p.Total > 0 ? 100.0 * p.Done / p.Total : 0;
                }),
            };
            var result = await Task.Run(() => reader.Read(ct), ct);
            ShowEvrcResult(result);
            var failed = result.Steps.Count(s => s.Outcome == StepOutcome.Failed);
            StatusText = $"Zulassungsbescheinigung gelesen in {(DateTime.Now - started).TotalSeconds:F1} s – {result.Findings.Count} Befund(e){(failed > 0 ? $", {failed} Schritt(e) fehlgeschlagen" : "")}";
        }
        catch (OperationCanceledException)
        {
            StatusText = "Lesen abgebrochen";
        }
        catch (Exception ex)
        {
            StatusText = $"Lesen fehlgeschlagen: {ex.Message}";
            ReadSteps.Add(new ReadStep("Lesen", StepOutcome.Failed, ex.Message));
            Logger.Error(LogCategory.Application, $"eVRC lesen fehlgeschlagen: {ex.Message}");
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
            ReadSteps.Add(new ReadStep("Normkonformität", StepOutcome.Warning, $"{result.Findings.Count} Abweichung(en), siehe Tab „Sicherheit“"));
        foreach (var f in result.Files) FileNodes.Add(FileNode.FromFile(f, Evrc.TagName));
        foreach (var f in result.Fields) EvrcFields.Add(f);
        SecurityReport = BuildEvrcReport(result);
    }

    private static string BuildEvrcReport(EvrcReadResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Zulassungsbescheinigung Teil I (RL 2003/127/EG) ===");
        foreach (var s in result.Steps) sb.AppendLine($"{Symbol(s.Outcome)} {s.Name}: {s.Detail}");
        sb.AppendLine();
        sb.AppendLine("=== Signaturen (Anhang III.2 D / III.12 C) ===");
        foreach (var sig in result.Signatures)
        {
            sb.AppendLine($"Teil {sig.Part}: {(sig.Valid switch { true => "✔", false => "✘", null => "–" })} {sig.Detail}");
            if (sig.Certificate != null) sb.AppendLine(Indent(SecurityObject.Describe(sig.Certificate)));
        }
        // The directive leaves trust anchors for the issuing authority certificates to the Member States (III.12 C).
        sb.AppendLine("Hinweis: Die Ausstellerzertifikate werden nicht gegen einen Vertrauensanker geprüft; die Richtlinie überlässt das den Mitgliedstaaten (III.12 C).");
        sb.AppendLine();
        sb.AppendLine($"=== Befunde ({result.Findings.Count}) ===");
        foreach (var f in result.Findings) sb.AppendLine("⚠ " + f);
        return sb.ToString();
    }
}
