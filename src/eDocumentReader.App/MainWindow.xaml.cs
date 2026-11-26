using System.Collections.Specialized;
using System.Windows;
using System.Windows.Input;
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
        viewModel.PropertyChanged += (_, e) => { if (e.PropertyName == nameof(MainViewModel.LogEntries)) HookLog(); };
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

    // TreeView.SelectedItem is read-only and cannot be bound two-way.
    private void FileTree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e) =>
        viewModel.SelectedFileNode = e.NewValue as FileNode;
}
