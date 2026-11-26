using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using eDocumentReader.Core.Documents;

namespace eDocumentReader.App.ViewModels;

/// <summary>One entry of the result list: planned, running (with a byte progress bar for files) or finished.</summary>
public sealed partial class StepItem(string id, string name) : ObservableObject
{
    public string Id { get; } = id;

    [ObservableProperty] private string name = name;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(Symbol), nameof(SymbolBrush), nameof(IsPending))] private StepState state = StepState.Pending;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(Symbol), nameof(SymbolBrush))] private StepOutcome? outcome;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(DetailText))] private string detail = string.Empty;
    [ObservableProperty] private double progress;
    [ObservableProperty] private bool showProgress;

    /// <summary>Live-only result (e.g. a file read without error); a later step with the same Id replaces it.</summary>
    public bool Provisional { get; set; }

    /// <summary>Index into the log sink where this step started (-1: unknown).</summary>
    public int LogAnchor { get; set; } = -1;

    /// <summary>Byte progress of a running file read, 0..1 (for the overall progress).</summary>
    public double Fraction => State == StepState.Done ? 1 : ShowProgress ? Progress / 100 : 0;

    public bool IsPending => State == StepState.Pending;

    public string DetailText => Detail.Length > 0 ? ": " + Detail : string.Empty;

    public string Symbol => State switch
    {
        StepState.Pending => "○",
        StepState.Running => "▶",
        _ => Outcome is { } o ? MainViewModel.Symbol(o) : "○",
    };

    public Brush SymbolBrush => State switch
    {
        StepState.Pending => Brushes.Gray,
        StepState.Running => Brushes.RoyalBlue,
        _ => Outcome switch
        {
            StepOutcome.Success => Brushes.Green,
            StepOutcome.Failed => Brushes.Red,
            StepOutcome.Skipped or StepOutcome.Warning => Brushes.DarkOrange,
            _ => Brushes.Gray,
        },
    };

    public void Finish(ReadStep step, bool provisional)
    {
        Name = step.Name;
        Detail = step.Detail;
        Outcome = step.Outcome;
        ShowProgress = false;
        Provisional = provisional;
        State = StepState.Done;
    }

    public static StepItem From(ReadStep step, int anchor)
    {
        var item = new StepItem(step.Id, step.Name) { LogAnchor = anchor };
        item.Finish(step, provisional: false);
        return item;
    }
}
