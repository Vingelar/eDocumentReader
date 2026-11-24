using System.Globalization;
using System.IO;
using System.Text.Json;
using eDocumentReader.Core.Localization;

namespace eDocumentReader.App.Localization;

/// <summary>User settings in %APPDATA%\eDocumentReader\settings.json. Holds the language only; no personal data.</summary>
public sealed class AppSettings
{
    public string Language { get; set; } = "";

    private static string FilePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "eDocumentReader", "settings.json");

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath)) return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new AppSettings();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException) { /* defaults */ }
        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* setting is a convenience only */ }
    }

    /// <summary>Saved choice, otherwise German on a German Windows and English everywhere else.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public UiLanguage EffectiveLanguage => Language switch
    {
        "de" => UiLanguage.German,
        "en" => UiLanguage.English,
        _ => CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "de" ? UiLanguage.German : UiLanguage.English,
    };

    public static string Code(UiLanguage language) => language == UiLanguage.English ? "en" : "de";
}
