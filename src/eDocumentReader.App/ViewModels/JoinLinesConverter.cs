using System.Globalization;
using System.Windows.Data;

namespace eDocumentReader.App.ViewModels;

/// <summary>Joins a list of strings into one text block, one entry per line.</summary>
public sealed class JoinLinesConverter : IValueConverter
{
    public static JoinLinesConverter Instance { get; } = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is IEnumerable<string> lines ? string.Join(Environment.NewLine, lines) : string.Empty;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
