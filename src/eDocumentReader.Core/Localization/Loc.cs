namespace eDocumentReader.Core.Localization;

public enum UiLanguage { German, English }

/// <summary>
/// Language of all texts the library produces (steps, findings, reports, log messages).
/// Each text is written in both languages at the place it is produced: <c>T("Datei", "File")</c>.
/// Identifiers that program logic compares (file names, step keys, tag values) are never translated.
/// </summary>
public static class Loc
{
    private static volatile UiLanguage language = UiLanguage.German;

    public static UiLanguage Language
    {
        get => language;
        set
        {
            if (language == value) return;
            language = value;
            LanguageChanged?.Invoke();
        }
    }

    public static bool IsEnglish => language == UiLanguage.English;

    public static event Action? LanguageChanged;

    /// <summary>German or English text, depending on <see cref="Language"/>.</summary>
    public static string T(string german, string english) => language == UiLanguage.English ? english : german;
}
