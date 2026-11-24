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
    [ObservableProperty] private string pkiSummary = "PKI-Speicher noch nicht geladen – „Aktualisieren“ oder „Importieren…“.";
    [ObservableProperty] private string pkiImportLog = string.Empty;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(ImportPkiCommand), nameof(RefreshPkiCommand))] private bool isPkiBusy;

    private bool CanUsePki() => !IsPkiBusy;

    [RelayCommand(CanExecute = nameof(CanUsePki))]
    private async Task ImportPki()
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "PKI-Dateien importieren",
            Multiselect = true,
            Filter = "Alle unterstützten Dateien|*.cvcert;*.cvc;*.bin;*.der;*.cer;*.crt;*.pem;*.pkcs8;*.p8;*.key;*.ml;*.crl|" +
                     "CV-Zertifikate (*.cvcert;*.cvc;*.bin)|*.cvcert;*.cvc;*.bin|" +
                     "Private Schlüssel (*.pkcs8;*.p8;*.key;*.pem;*.der)|*.pkcs8;*.p8;*.key;*.pem;*.der|" +
                     "X.509 / Master List / CRL (*.cer;*.crt;*.der;*.pem;*.ml;*.crl)|*.cer;*.crt;*.der;*.pem;*.ml;*.crl|" +
                     "Alle Dateien (*.*)|*.*",
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
                        if (results.Count == 0) log.Add($"✘ {Path.GetFileName(f)}: Dateityp nicht erkannt");
                        foreach (var r in results) log.Add($"✔ {Path.GetFileName(f)} → {r.Kind}: {r.Description}");
                    }
                    catch (Exception ex) { log.Add($"✘ {Path.GetFileName(f)}: {ex.Message}"); }
                }
                // Reload so that keys imported before their certificate are matched as well.
                pki.Reload();
                return log;
            });
            PkiImportLog = string.Join(Environment.NewLine, lines);
            foreach (var l in lines) Logger.Info(LogCategory.Application, "PKI-Import: " + l);
            PkiSummary = BuildPkiSummary(pki!);
            StatusText = $"PKI-Import: {lines.Count(l => l.StartsWith('✔'))} von {files.Length} Datei(en) übernommen";
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
        sb.AppendLine($"Speicherort: {store.Root}");
        sb.AppendLine($"{store.Cscas.Count} CSCA, {store.DocumentSigners.Count} DS, {store.Crls.Count} CRL, {store.CvCertificates.Count} CV-Zertifikate, {store.PrivateKeys.Count} private Schlüssel");
        sb.AppendLine();

        sb.AppendLine("=== Terminal Authentication: Ketten (TR-03110-3, ISO/IEC 18013-3 EAP) ===");
        var terminals = store.TerminalCredentials();
        if (terminals.Count == 0) sb.AppendLine("  keine Terminal-Credentials (Terminalzertifikat + passender privater Schlüssel)");
        foreach (var t in terminals)
        {
            sb.AppendLine($"  Terminal {t.Certificate.Chr} ({t.Certificate.TerminalType}), gültig bis {t.Certificate.ExpirationDate:yyyy-MM-dd}");
            foreach (var line in store.VerifyCvChain(t.Certificate)) sb.AppendLine("    " + line);
        }
        var keysWithoutCert = store.PrivateKeys.Count - terminals.Count;
        if (keysWithoutCert > 0) sb.AppendLine($"  ⚠ {keysWithoutCert} privater Schlüssel ohne passendes Terminalzertifikat");
        var anchors = store.CandidateTrustPoints();
        sb.AppendLine($"  Vertrauensanker (CVCA) für Chips ohne EF.CVCA: {(anchors.Count > 0 ? string.Join(", ", anchors) : "keine")}");
        sb.AppendLine();

        sb.AppendLine("=== CV-Zertifikate ===");
        foreach (var c in store.CvCertificates.OrderBy(c => c.Role == CvRole.Cvca ? 0 : c.Role == CvRole.InspectionSystemOrTerminal ? 2 : 1).ThenBy(c => c.Chr))
            sb.AppendLine("  " + c.Describe());
        if (store.Errors.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("=== Fehler beim Laden ===");
            foreach (var e in store.Errors) sb.AppendLine("  ✘ " + e);
        }
        return sb.ToString();
    }
}
