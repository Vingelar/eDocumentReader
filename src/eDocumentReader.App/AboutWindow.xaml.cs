using System.Reflection;
using System.Windows;
using eDocumentReader.Core.Localization;

namespace eDocumentReader.App;

public sealed record AboutParagraph(string Title, string Text);

/// <summary>About dialog: purpose, standards, disclaimer, AI notice and licence (same wording as README.md).</summary>
public partial class AboutWindow : Window
{
    public AboutWindow()
    {
        InitializeComponent();
        Fill();
        Loc.LanguageChanged += Fill;
        Closed += (_, _) => Loc.LanguageChanged -= Fill;
    }

    private void Fill()
    {
        Heading.Text = "eDocumentReader";
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "?";
        Version.Text = T($"Version {version} · Testsoftware", $"Version {version} · test software");
        Paragraphs.ItemsSource = Texts();
    }

    public static IReadOnlyList<AboutParagraph> Texts() =>
    [
        new(T("Testsoftware", "Test software"),
            T("eDocumentReader ist eine Testsoftware zum Lesen und Prüfen elektronischer Dokumente über PC/SC-Leser: " +
              "Reisepässe und ID-Karten (eMRTD), Führerscheine (IDL) und Zulassungsbescheinigungen (eVRC). " +
              "Sie dient Entwicklung, Test und Analyse und ist kein zertifiziertes Prüf- oder Kontrollsystem.",
              "eDocumentReader is test software for reading and checking electronic documents with PC/SC readers: " +
              "passports and ID cards (eMRTD), driving licences (IDL) and vehicle registration certificates (eVRC). " +
              "It is meant for development, testing and analysis and is not a certified inspection system.")),
        new(T("Standards", "Standards"),
            T("Die Software wurde nach den relevanten Standards geschrieben, insbesondere ICAO Doc 9303 (Teile 3, 10, 11), " +
              "BSI TR-03110 und TR-03111, ISO/IEC 7816-3/-4, ISO/IEC 14443, ISO/IEC 18013-2/-3, ISO/IEC 19794-5, PC/SC und " +
              "Richtlinie 2003/127/EG. Abweichungen von den Standards und Fehler in der Auswertung sind dennoch möglich.",
              "The software was written according to the relevant standards, in particular ICAO Doc 9303 (Parts 3, 10, 11), " +
              "BSI TR-03110 and TR-03111, ISO/IEC 7816-3/-4, ISO/IEC 14443, ISO/IEC 18013-2/-3, ISO/IEC 19794-5, PC/SC and " +
              "Directive 2003/127/EC. Deviations from the standards and errors in the evaluation are nevertheless possible.")),
        new(T("Gewährleistungs- und Haftungsausschluss", "Disclaimer of warranty and liability"),
            T("Die Software wird ohne jegliche Gewährleistung bereitgestellt, weder ausdrücklich noch stillschweigend, " +
              "einschließlich der Gewährleistung der Marktgängigkeit, der Eignung für einen bestimmten Zweck und der Fehlerfreiheit. " +
              "Die Nutzung erfolgt auf eigenes Risiko. Schäden an Karten, Chips oder Lesegeräten – etwa durch blockierte Zugangsdaten, " +
              "verbrauchte Fehlbedienungszähler, unterbrochene Kommunikation oder unerwartetes Verhalten des Chips – können nicht " +
              "ausgeschlossen werden. Eine Haftung für Schäden jeder Art ist ausgeschlossen, soweit das Gesetz dies zulässt.",
              "The software is provided without any warranty, express or implied, including the warranties of merchantability, " +
              "fitness for a particular purpose and freedom from errors. Use it at your own risk. Damage to cards, chips or readers – " +
              "for example through blocked access credentials, exhausted retry counters, interrupted communication or unexpected chip " +
              "behaviour – cannot be ruled out. Liability for damage of any kind is excluded to the extent permitted by law.")),
        new(T("Künstliche Intelligenz", "Artificial intelligence"),
            T("Die Software wurde mit Hilfe künstlicher Intelligenz (Claude von Anthropic) geschrieben.",
              "The software was written with the help of artificial intelligence (Claude by Anthropic).")),
        new(T("Lizenz", "Licence"),
            T("MIT-Lizenz – freie Nutzung, Änderung und Weitergabe, auch kommerziell, solange der Copyright- und Lizenzhinweis erhalten bleibt " +
              "(Datei LICENSE). Verwendete Bibliotheken: BouncyCastle (MIT), CommunityToolkit.Mvvm (MIT), CoreJ2K (BSD-3-Clause).",
              "MIT License – free use, modification and distribution, also commercially, as long as the copyright and licence notice is kept " +
              "(file LICENSE). Libraries used: BouncyCastle (MIT), CommunityToolkit.Mvvm (MIT), CoreJ2K (BSD-3-Clause).")),
    ];

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
