using System.Collections.Specialized;
using System.Windows;
using System.Windows.Threading;
using eDocumentReader.App.ViewModels;

namespace eDocumentReader.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel viewModel = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = viewModel;
        ((INotifyCollectionChanged)viewModel.LogEntries).CollectionChanged += (_, e) =>
        {
            if (e.Action != NotifyCollectionChangedAction.Add) return;
            Dispatcher.BeginInvoke(DispatcherPriority.Background, () =>
            {
                if (LogList.Items.Count > 0) LogList.ScrollIntoView(LogList.Items[^1]);
            });
        };
        Closed += (_, _) => viewModel.Dispose();
    }

    // TreeView.SelectedItem is read-only and cannot be bound two-way.
    private void FileTree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e) =>
        viewModel.SelectedFileNode = e.NewValue as FileNode;
}
