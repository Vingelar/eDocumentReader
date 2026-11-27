using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using eDocumentReader.Core.Documents;
using eDocumentReader.Core.Protocols;

namespace eDocumentReader.App;

/// <summary>
/// Choice of the PACE variant when EF.CardAccess offers several PACEInfos (ICAO 9303-11 9.2.1): one radio button per
/// entry in card order, unsupported entries disabled, optionally BAC/BAP instead of PACE.
/// </summary>
public sealed class PaceChoiceWindow : Window
{
    /// <summary>Result: <see cref="Cancelled"/>, or the chosen PACEInfo (null = BAC/BAP).</summary>
    public sealed record Choice(bool Cancelled, PaceInfo? Info);

    private readonly List<(RadioButton Button, PaceInfo? Info)> buttons = [];
    private Choice choice = new(true, null);

    private PaceChoiceWindow(PaceChoiceRequest request)
    {
        Title = T("PACE-Verfahren wählen", "Choose the PACE variant");
        SizeToContent = SizeToContent.WidthAndHeight;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;

        var panel = new StackPanel { Margin = new Thickness(14) };
        panel.Children.Add(new TextBlock
        {
            Text = T("Die Karte bietet in EF.CardAccess mehrere PACE-Verfahren an (ICAO 9303-11 9.2.1).\nMit welchem soll gelesen werden?",
                     "The card offers several PACE variants in EF.CardAccess (ICAO 9303-11 9.2.1).\nWhich one shall be used?"),
            Margin = new Thickness(0, 0, 0, 10),
        });
        var index = 0;
        foreach (var option in request.Options)
        {
            index++;
            var text = $"{index}. {option.Description}" + (option.Supported ? "" : T(" – vom Reader nicht unterstützt", " – not supported by the reader"));
            var button = new RadioButton
            {
                Content = text, GroupName = "pace", IsEnabled = option.Supported, Margin = new Thickness(0, 3, 0, 3),
                IsChecked = ReferenceEquals(option.Info, request.Preselected) && option.Supported,
                FontFamily = new FontFamily("Consolas"),
            };
            buttons.Add((button, option.Info));
            panel.Children.Add(button);
        }
        if (request.Fallback is { } fallback)
        {
            var bac = new RadioButton
            {
                Content = T($"{fallback} statt PACE (mit der MRZ)", $"{fallback} instead of PACE (with the MRZ)"),
                GroupName = "pace", Margin = new Thickness(0, 9, 0, 3),
            };
            buttons.Add((bac, null));
            panel.Children.Add(bac);
        }
        if (!buttons.Any(b => b.Button.IsChecked == true) && buttons.FirstOrDefault(b => b.Button.IsEnabled) is { Button: { } first }) first.IsChecked = true;

        var ok = new Button { Content = "OK", IsDefault = true, MinWidth = 90, Margin = new Thickness(0, 0, 8, 0) };
        ok.Click += (_, _) =>
        {
            var selected = buttons.FirstOrDefault(b => b.Button.IsChecked == true);
            if (selected.Button == null) return;
            choice = new Choice(false, selected.Info);
            DialogResult = true;
        };
        var cancel = new Button { Content = T("Lesen abbrechen", "Cancel reading"), IsCancel = true, MinWidth = 90 };
        var row = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 14, 0, 0) };
        row.Children.Add(ok);
        row.Children.Add(cancel);
        panel.Children.Add(row);
        Content = panel;
    }

    /// <summary>Shows the dialog modally on the UI thread.</summary>
    public static Choice Ask(Window? owner, PaceChoiceRequest request)
    {
        var window = new PaceChoiceWindow(request);
        if (owner is { IsLoaded: true }) window.Owner = owner;
        else window.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        window.ShowDialog();
        return window.choice;
    }
}
