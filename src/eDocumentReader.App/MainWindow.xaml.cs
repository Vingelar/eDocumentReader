using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using eDocumentReader.App.ViewModels;

namespace eDocumentReader.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel viewModel = new();
    private INotifyCollectionChanged? logCollection;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = viewModel;
        HookLog();
        // The log view is rebuilt when a display level changes.
        viewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(MainViewModel.LogEntries)) HookLog();
            else if (e.PropertyName == nameof(MainViewModel.SecurityReport)) ShowColored(SecurityBox, viewModel.SecurityReport);
            else if (e.PropertyName == nameof(MainViewModel.CardInfo)) ShowColored(CardInfoBox, viewModel.CardInfo);
        };
        Closed += (_, _) => viewModel.Dispose();
    }

    private void HookLog()
    {
        if (logCollection != null) logCollection.CollectionChanged -= LogEntries_CollectionChanged;
        logCollection = viewModel.LogEntries;
        logCollection.CollectionChanged += LogEntries_CollectionChanged;
        ScrollLogToEnd();
    }

    private void LogEntries_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        // Follow new entries, unless the user has jumped to a step's entry after reading.
        if (e.Action != NotifyCollectionChangedAction.Add || (LogList.SelectedItem != null && !viewModel.IsReading)) return;
        ScrollLogToEnd();
    }

    private void ScrollLogToEnd() => Dispatcher.BeginInvoke(DispatcherPriority.Background, () =>
    {
        if (LogList.Items.Count > 0) LogList.ScrollIntoView(LogList.Items[^1]);
    });

    /// <summary>Click on a result entry: select its first log entry and show it at the top of the log.</summary>
    private void StepList_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (StepList.SelectedItem is not StepItem step || viewModel.FindLogEntry(step.LogAnchor) is not { } entry) return;
        LogList.SelectedItem = entry;
        // Scrolling to the end first makes the target appear at the top instead of the bottom.
        LogList.ScrollIntoView(LogList.Items[^1]);
        LogList.UpdateLayout();
        LogList.ScrollIntoView(entry);
    }

    private static readonly Brush Good = Brushes.Green, Bad = Brushes.Red, Doubtful = new SolidColorBrush(Color.FromRgb(0xC8, 0x8A, 0x00));

    /// <summary>
    /// Security and reader/card tabs: one line per paragraph, green for ✔, red for ✘, yellow for ⚠ and – (skipped /
    /// not read), headings bold. Text stays selectable and copyable.
    /// </summary>
    private static void ShowColored(RichTextBox box, string report)
    {
        // A wide page keeps the lines unwrapped; the box scrolls horizontally like the former text box.
        var doc = new FlowDocument { PageWidth = 3000, PagePadding = new Thickness(4), FontFamily = box.FontFamily, FontSize = box.FontSize };
        foreach (var line in report.Replace("\r\n", "\n").Split('\n'))
        {
            var paragraph = new Paragraph(new Run(line)) { Margin = new Thickness(0) };
            var brush = LineBrush(line);
            if (brush != null) paragraph.Foreground = brush;
            if (line.StartsWith("===") || (line.EndsWith(':') && !line.StartsWith(' '))) paragraph.FontWeight = FontWeights.Bold;
            doc.Blocks.Add(paragraph);
        }
        box.Document = doc;
    }

    private static Brush? LineBrush(string line)
    {
        if (line.Contains('✘')) return Bad;
        if (line.Contains('⚠')) return Doubtful;
        if (line.Contains('✔')) return Good;
        var t = line.TrimStart();
        // "– skipped" at the start of a step line, or a data group that was not read ("DG3  – not read").
        return t.StartsWith("– ") || System.Text.RegularExpressions.Regex.IsMatch(t, @"^DG\d+\s+– ") ? Doubtful : null;
    }

    // TreeView.SelectedItem is read-only and cannot be bound two-way.
    private void FileTree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e) =>
        viewModel.SelectedFileNode = e.NewValue as FileNode;
}
