using System.Globalization;
using System.Windows.Data;

namespace eDocumentReader.App.ViewModels;

public sealed class InverseBoolConverter : IValueConverter
{
    public static InverseBoolConverter Instance { get; } = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value is bool b ? !b : value;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => value is bool b ? !b : value;
}
