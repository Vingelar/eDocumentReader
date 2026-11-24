using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using eDocumentReader.Core.Documents;

namespace eDocumentReader.App.ViewModels;

/// <summary>StepOutcome → symbol (default) or brush (ConverterParameter "brush").</summary>
public sealed class StepOutcomeConverter : IValueConverter
{
    public static StepOutcomeConverter Instance { get; } = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not StepOutcome o) return string.Empty;
        if (parameter as string != "brush") return MainViewModel.Symbol(o);
        return o switch
        {
            StepOutcome.Success => Brushes.Green,
            StepOutcome.Failed => Brushes.Red,
            StepOutcome.Skipped or StepOutcome.Warning => Brushes.DarkOrange,
            _ => Brushes.Gray,
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
