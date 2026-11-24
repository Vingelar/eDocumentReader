using System.Windows;
using CommunityToolkit.Mvvm.Input;
using eDocumentReader.App.Localization;
using eDocumentReader.Core.Localization;

namespace eDocumentReader.App.ViewModels;

/// <summary>Menu: language switch (German/English) and the About dialog.</summary>
public sealed partial class MainViewModel
{
    public bool IsGerman => Loc.Language == UiLanguage.German;
    public bool IsEnglish => Loc.Language == UiLanguage.English;

    [RelayCommand]
    private void SetLanguage(string code)
    {
        var language = code == "en" ? UiLanguage.English : UiLanguage.German;
        var settings = AppSettings.Load();
        settings.Language = AppSettings.Code(language);
        settings.Save();
        if (Loc.Language == language) return;
        Loc.Language = language;
        OnPropertyChanged(nameof(IsGerman));
        OnPropertyChanged(nameof(IsEnglish));
        RefreshLanguageDependentTexts();
    }

    /// <summary>
    /// Texts the view model builds itself are rebuilt in the new language. Results of a read that is already displayed
    /// keep the language they were produced in; the next read uses the new one.
    /// </summary>
    private void RefreshLanguageDependentTexts()
    {
        StatusText = T("Sprache: Deutsch", "Language: English");
        if (!HasResult)
        {
            DataPanelTitle = "DG1 – MRZ";
            ImagePanelTitle = T("DG2 – Gesichtsbild", "DG2 – facial image");
        }
        PkiSummary = pki != null ? BuildPkiSummary(pki) : T("PKI-Speicher noch nicht geladen – „Aktualisieren“ oder „Importieren…“.", "PKI store not loaded yet – 'Refresh' or 'Import…'.");
        if (transport != null && Channel != null)
        {
            try { CardInfo = BuildCardInfo(transport, Channel); }
            catch (Exception ex) { CardInfo = ex.Message; }
        }
        OnMrzInputChanged(MrzInput);
    }

    [RelayCommand]
    private void ShowAbout() => new AboutWindow { Owner = Application.Current.MainWindow }.ShowDialog();
}
