using System.Diagnostics;
using System.IO;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Pki;

namespace eDocumentReader.App.ViewModels;

/// <summary>PKI tab: import of CSCA/DS/CRL/Master Lists, CV certificates and terminal keys; overview of the store.</summary>
public sealed partial class MainViewModel
{
    [ObservableProperty] private string pkiSummary = T("PKI-Speicher noch nicht geladen – „Aktualisieren“ oder „Importieren…“.", "PKI store not loaded yet – 'Refresh' or 'Import…'.");
    [ObservableProperty] private string pkiImportLog = string.Empty;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(ImportPkiCommand), nameof(RefreshPkiCommand))] private bool isPkiBusy;

    private bool CanUsePki() => !IsPkiBusy;

    [RelayCommand(CanExecute = nameof(CanUsePki))]
    private async Task ImportPki()
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = T("PKI-Dateien importieren", "Import PKI files"),
            Multiselect = true,
            Filter = T("Alle unterstützten Dateien|*.cvcert;*.cvc;*.bin;*.der;*.cer;*.crt;*.pem;*.pkcs8;*.p8;*.key;*.ml;*.crl|" +
                     "CV-Zertifikate (*.cvcert;*.cvc;*.bin)|*.cvcert;*.cvc;*.bin|" +
                     "Private Schlüssel (*.pkcs8;*.p8;*.key;*.pem;*.der)|*.pkcs8;*.p8;*.key;*.pem;*.der|" +
                     "X.509 / Master List / CRL (*.cer;*.crt;*.der;*.pem;*.ml;*.crl)|*.cer;*.crt;*.der;*.pem;*.ml;*.crl|" +
                     "Alle Dateien (*.*)|*.*", "All supported files|*.cvcert;*.cvc;*.bin;*.der;*.cer;*.crt;*.pem;*.pkcs8;*.p8;*.key;*.ml;*.crl|" +
                     "CV certificates (*.cvcert;*.cvc;*.bin)|*.cvcert;*.cvc;*.bin|" +
                     "Private keys (*.pkcs8;*.p8;*.key;*.pem;*.der)|*.pkcs8;*.p8;*.key;*.pem;*.der|" +
                     "X.509 / Master List / CRL (*.cer;*.crt;*.der;*.pem;*.ml;*.crl)|*.cer;*.crt;*.der;*.pem;*.ml;*.crl|" +
                     "All files (*.*)|*.*"),
        };
        if (dlg.ShowDialog() != true) return;
        IsPkiBusy = true;
        try
        {
            var files = dlg.FileNames;
            var lines = await Task.Run(() =>
            {
                pki ??= new PkiStore();
                var log = new List<string>();
                foreach (var f in files)
                {
                    try
                    {
                        var results = pki.Import(f);
                        if (results.Count == 0) log.Add(T($"✘ {Path.GetFileName(f)}: Dateityp nicht erkannt", $"✘ {Path.GetFileName(f)}: file type not recognized"));
                        foreach (var r in results) log.Add($"✔ {Path.GetFileName(f)} → {r.Kind}: {r.Description}");
                    }
                    catch (Exception ex) { log.Add($"✘ {Path.GetFileName(f)}: {ex.Message}"); }
                }
                // Reload so that keys imported before their certificate are matched as well.
                pki.Reload();
                return log;
            });
            PkiImportLog = string.Join(Environment.NewLine, lines);
            foreach (var l in lines) Logger.Info(LogCategory.Application, T("PKI-Import: ", "PKI import: ") + l);
            PkiSummary = BuildPkiSummary(pki!);
            StatusText = T($"PKI-Import: {lines.Count(l => l.StartsWith('✔'))} von {files.Length} Datei(en) übernommen", $"PKI import: {lines.Count(l => l.StartsWith('✔'))} of {files.Length} file(s) imported");
        }
        finally { IsPkiBusy = false; }
    }

    [RelayCommand(CanExecute = nameof(CanUsePki))]
    private async Task RefreshPki()
    {
        IsPkiBusy = true;
        try
        {
            await Task.Run(() => { if (pki == null) pki = new PkiStore(); else pki.Reload(); });
            PkiSummary = BuildPkiSummary(pki!);
        }
        finally { IsPkiBusy = false; }
    }

    [RelayCommand]
    private void OpenPkiFolder() => Process.Start(new ProcessStartInfo("explorer.exe", $"\"{pki?.Root ?? PkiStore.DefaultRoot}\"") { UseShellExecute = true });

    private static string BuildPkiSummary(PkiStore store)
    {
        var sb = new StringBuilder();
        sb.AppendLine(T($"Speicherort: {store.Root}", $"Location: {store.Root}"));
        sb.AppendLine(T($"{store.Cscas.Count} CSCA, {store.DocumentSigners.Count} DS, {store.Crls.Count} CRL, {store.CvCertificates.Count} CV-Zertifikate, {store.PrivateKeys.Count} private Schlüssel", $"{store.Cscas.Count} CSCA, {store.DocumentSigners.Count} DS, {store.Crls.Count} CRL, {store.CvCertificates.Count} CV certificates, {store.PrivateKeys.Count} private keys"));
        sb.AppendLine();

        sb.AppendLine(T("=== Terminal Authentication: Ketten (TR-03110-3, ISO/IEC 18013-3 EAP) ===", "=== Terminal Authentication: chains (TR-03110-3, ISO/IEC 18013-3 EAP) ==="));
        var terminals = store.TerminalCredentials();
        if (terminals.Count == 0) sb.AppendLine(T("  keine Terminal-Credentials (Terminalzertifikat + passender privater Schlüssel)", "  no terminal credentials (terminal certificate + matching private key)"));
        foreach (var t in terminals)
        {
            sb.AppendLine(T($"  Terminal {t.Certificate.Chr} ({t.Certificate.TerminalType}), gültig bis {t.Certificate.ExpirationDate:yyyy-MM-dd}", $"  Terminal {t.Certificate.Chr} ({t.Certificate.TerminalType}), valid until {t.Certificate.ExpirationDate:yyyy-MM-dd}"));
            foreach (var line in store.VerifyCvChain(t.Certificate)) sb.AppendLine("    " + line);
        }
        var keysWithoutCert = store.PrivateKeys.Count - terminals.Count;
        if (keysWithoutCert > 0) sb.AppendLine(T($"  ⚠ {keysWithoutCert} privater Schlüssel ohne passendes Terminalzertifikat", $"  ⚠ {keysWithoutCert} private key(s) without matching terminal certificate"));
        var anchors = store.CandidateTrustPoints();
        sb.AppendLine(T($"  Vertrauensanker (CVCA) für Chips ohne EF.CVCA: {(anchors.Count > 0 ? string.Join(", ", anchors) : "keine")}", $"  Trust points (CVCA) for chips without EF.CVCA: {(anchors.Count > 0 ? string.Join(", ", anchors) : "none")}"));
        sb.AppendLine();

        sb.AppendLine(T("=== CV-Zertifikate ===", "=== CV certificates ==="));
        foreach (var c in store.CvCertificates.OrderBy(c => c.Role == CvRole.Cvca ? 0 : c.Role == CvRole.InspectionSystemOrTerminal ? 2 : 1).ThenBy(c => c.Chr))
            sb.AppendLine("  " + c.Describe());
        if (store.Errors.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine(T("=== Fehler beim Laden ===", "=== Errors while loading ==="));
            foreach (var e in store.Errors) sb.AppendLine("  ✘ " + e);
        }
        return sb.ToString();
    }
}
