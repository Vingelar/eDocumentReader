using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Media.Imaging;
using CommunityToolkit.Mvvm.ComponentModel;
using eDocumentReader.App.Imaging;
using eDocumentReader.Core.Documents;

namespace eDocumentReader.App.ViewModels;

/// <summary>Prepared display of the IDL data groups (ISO/IEC 18013-2 Annex C).</summary>
public sealed partial class MainViewModel
{
    private IdlImage? idlPortrait;

    [ObservableProperty] private string dataPanelTitle = "DG1 – MRZ";
    [ObservableProperty] private string imagePanelTitle = "DG2 – Gesichtsbild";
    [ObservableProperty] private BitmapSource? signatureBitmap;

    public ObservableCollection<IdlField> IdlFields { get; } = [];

    private void ShowIdlResult(EmrtdReadResult result)
    {
        DataPanelTitle = "Führerschein – DG1 Pflichtdaten";
        ImagePanelTitle = "DG4 – Lichtbild";
        IdlReadout idl;
        try { idl = Idl.Parse(result.DataGroups); }
        catch (Exception ex) { MrzFindings = "⚠ IDL-Datengruppen: " + ex.Message; return; }
        foreach (var f in idl.Fields) IdlFields.Add(f);

        // Overview panel: the DG1 fields, then the driving privileges.
        foreach (var f in idl.Fields.Where(f => f.Path.StartsWith("DG1/5F1F") || f.TagHex == "53" && f.Path.StartsWith("DG1")))
            MrzRows.Add(new MrzRow(f.Name, f.Value, f.Findings.Count == 0 ? "✔" : "⚠"));
        foreach (var c in idl.Categories)
            MrzRows.Add(new MrzRow($"Klasse {c.Category}", c.Describe(), c.Findings.Count == 0 ? "✔" : "⚠"));
        var missing = new[] { 1, 2, 4, 5 }.Where(d => !result.DataGroups.ContainsKey(d)).Select(d => $"DG{d}").ToList();
        var findings = idl.Fields.Where(f => f.Path.StartsWith("DG1")).SelectMany(f => f.Findings).Concat(idl.Categories.SelectMany(c => c.Findings)).Distinct()
            .Select(x => "⚠ " + x).ToList();
        if (missing.Count > 0) findings.Insert(0, $"Nicht gelesen: {string.Join(", ", missing)} (geschützt – Terminal Authentication nötig?)");
        MrzFindings = string.Join(Environment.NewLine, findings);
        MrzText = string.Join("  ·  ", idl.Fields.Where(f => f.Name is "Familienname" or "Vornamen" or "Führerscheinnummer").Select(f => f.Value));

        idlPortrait = idl.Images.FirstOrDefault(i => i.DataGroup == 4);
        if (idlPortrait != null)
        {
            try { FaceBitmap = FaceImageDecoder.DecodeAny(idlPortrait.Data); }
            catch (Exception ex) { FaceInfo = "⚠ DG4: " + ex.Message; }
            FaceInfo = $"{idlPortrait.Format}, {idlPortrait.Data.Length} Byte" +
                (idlPortrait.Captured != null ? $", aufgenommen {idlPortrait.Captured}" : "") +
                (idlPortrait.ImageType != null ? $", Bildtyp {idlPortrait.ImageType}" : "") +
                (FaceInfo.StartsWith('⚠') ? Environment.NewLine + FaceInfo : "");
        }
        else FaceInfo = result.DataGroups.ContainsKey(4) ? "DG4 enthält kein Bild (5F40)." : "DG4 nicht gelesen.";

        if (idl.Images.FirstOrDefault(i => i.DataGroup == 5) is { } signature)
        {
            try { SignatureBitmap = FaceImageDecoder.DecodeAny(signature.Data); }
            catch (Exception ex) { FaceInfo += Environment.NewLine + "⚠ DG5 Unterschrift: " + ex.Message; }
        }
        else if (idl.Fields.FirstOrDefault(f => f.Path.StartsWith("DG5") && f.TagHex == "53") is { } text)
            FaceInfo += Environment.NewLine + $"DG5: „{text.Value}“ (kein Bild)";
    }

    private void SaveIdlPortrait(IdlImage image)
    {
        var ext = image.Format == "JPEG" ? "jpg" : "jp2";
        var dlg = new Microsoft.Win32.SaveFileDialog { Filter = $"Originalbild (*.{ext})|*.{ext}|PNG (*.png)|*.png", FileName = $"DG4_Lichtbild.{ext}" };
        if (dlg.ShowDialog() != true) return;
        if (dlg.FilterIndex == 2 && FaceBitmap != null)
        {
            using var fs = File.Create(dlg.FileName);
            var enc = new PngBitmapEncoder();
            enc.Frames.Add(BitmapFrame.Create(FaceBitmap));
            enc.Save(fs);
        }
        else File.WriteAllBytes(dlg.FileName, image.Data);
    }
}
