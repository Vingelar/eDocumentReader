using System.ComponentModel;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Markup;
using eDocumentReader.Core.Localization;

namespace eDocumentReader.App.Localization;

/// <summary>Bindable source that announces language changes so XAML texts switch immediately.</summary>
public sealed class UiText : INotifyPropertyChanged
{
    public static UiText Instance { get; } = new();

    private UiText() => Loc.LanguageChanged += () => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Language)));

    public UiLanguage Language => Loc.Language;

    public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>
/// Bilingual XAML text: <c>Content="{l:Tr 'Lesen', En='Read'}"</c>.
/// Produces a binding to <see cref="UiText.Language"/>, so the text follows the language setting at run time.
/// </summary>
[MarkupExtensionReturnType(typeof(string))]
public sealed class TrExtension : MarkupExtension
{
    public TrExtension() { }
    public TrExtension(string de) => De = de;

    [ConstructorArgument("de")]
    public string De { get; set; } = string.Empty;
    public string En { get; set; } = string.Empty;

    public override object ProvideValue(IServiceProvider serviceProvider)
    {
        var binding = new Binding(nameof(UiText.Language))
        {
            Source = UiText.Instance,
            Mode = BindingMode.OneWay,
            Converter = TrConverter.Instance,
            ConverterParameter = (De, En),
        };
        return binding.ProvideValue(serviceProvider);
    }
}

internal sealed class TrConverter : IValueConverter
{
    public static TrConverter Instance { get; } = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        parameter is (string de, string en) ? (value is UiLanguage.English ? en : de) : string.Empty;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
