using System.Globalization;
using System.Windows.Data;
using eDocumentReader.Core.Logging;

namespace eDocumentReader.App.ViewModels;

public sealed class LogEntryFormatter : IValueConverter
{
    public static LogEntryFormatter Instance { get; } = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value is LogEntry e ? e.Format() : string.Empty;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
