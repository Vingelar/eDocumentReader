using System.IO;
using System.Reflection;
using CommunityToolkit.Mvvm.Input;
using eDocumentReader.Core.Documents;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Util;

namespace eDocumentReader.App.ViewModels;

/// <summary>
/// Export of single EF files and complete data sets in the exchange format of PaceSetupGen
/// (H:\JOB\ICAO\ICAO_perso\docs\SET-FORMAT.md). Personal data is written only where the user chooses.
/// </summary>
public sealed partial class MainViewModel
{
    private Func<SetExport>? setSource;
    private SetDocumentType lastDocumentType;
    private SecurityObject? lastSod;
    private DateTimeOffset lastReadAt;
    private string? lastReaderName;
    private byte[]? lastAtr;

    /// <summary>Called after each successful read; the set itself is built only when it is saved.</summary>
    private void RememberSetSource(Func<SetExport> source, SetDocumentType type, SecurityObject? sod)
    {
        setSource = source;
        lastDocumentType = type;
        lastSod = sod;
        lastReadAt = DateTimeOffset.Now;
        lastReaderName = transport?.Name;
        lastAtr = transport?.Atr;
    }

    [RelayCommand(CanExecute = nameof(HasResult))]
    private void SaveSet()
    {
        if (setSource == null) return;
        var dlg = new Microsoft.Win32.OpenFolderDialog { Title = "Übergeordneten Ordner für den Datensatz wählen" };
        if (dlg.ShowDialog() != true) return;
        try
        {
            var export = setSource();
            export.Origin.SoftwareVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3);
            export.Origin.ReadAt = DocumentSet.Iso(lastReadAt);
            export.Origin.ReaderDevice = lastReaderName;
            if (lastAtr is { Length: > 0 }) export.Origin.Atr = Hex.Compact(lastAtr);
            var dir = DocumentSet.Write(export, dlg.FolderName);
            var notRead = export.Origin.NotRead.Count > 0 ? $", nicht gelesen: {string.Join(", ", export.Origin.NotRead.Keys)}" : "";
            StatusText = $"Datensatz ({export.DocumentType.ToString().ToUpperInvariant()}, {export.Files.Count} Dateien{notRead}) gespeichert in {dir}";
            Logger.Info(LogCategory.Application, $"Datensatz gespeichert: {export.Files.Count} EF-Dateien, project.json (Schema {DocumentSet.SchemaVersion})");
        }
        catch (Exception ex)
        {
            StatusText = $"Datensatz nicht gespeichert: {ex.Message}";
            Logger.Error(LogCategory.Application, StatusText);
        }
    }

    private bool CanSaveSelectedFile() => SelectedFileNode?.File != null;

    /// <summary>Saves the selected EF as DG&lt;n&gt;.bin / EF.xxx.bin; ICAO/IDL files are cut to the outer TLV (SET-FORMAT.md 1.2).</summary>
    [RelayCommand(CanExecute = nameof(CanSaveSelectedFile))]
    private void SaveSelectedFile()
    {
        if (SelectedFileNode?.File is not { } file) return;
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = "EF-Datei speichern",
            FileName = DocumentSet.SingleFileName(file),
            Filter = "Binärdatei (*.bin)|*.bin|Alle Dateien (*.*)|*.*",
        };
        if (dlg.ShowDialog() != true) return;
        var data = file.Data;
        string? note = null;
        if (lastDocumentType != SetDocumentType.Evrc)
            (data, note) = DocumentSet.TrimToTlv(DocumentSet.ExportName(file) ?? file.Name, file.Data, lastSod, file.DataGroup);
        File.WriteAllBytes(dlg.FileName, data);
        StatusText = $"{Path.GetFileName(dlg.FileName)} gespeichert ({data.Length} Byte){(note != null ? " – " + note : "")}";
    }
}
