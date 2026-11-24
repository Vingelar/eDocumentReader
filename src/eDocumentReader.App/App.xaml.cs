using System.Windows;
using eDocumentReader.App.Localization;
using eDocumentReader.Core.Localization;

namespace eDocumentReader.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // Before the main window exists, so every text is created in the chosen language.
        Loc.Language = AppSettings.Load().EffectiveLanguage;
        base.OnStartup(e);
    }
}
