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
    [ObservableProperty] private string imagePanelTitle = T("DG2 – Gesichtsbild", "DG2 – facial image");
    [ObservableProperty] private BitmapSource? signatureBitmap;

    public ObservableCollection<IdlField> IdlFields { get; } = [];

    private void ShowIdlResult(EmrtdReadResult result)
    {
        DataPanelTitle = T("Führerschein – DG1 Pflichtdaten", "Driving licence – DG1 mandatory data");
        ImagePanelTitle = T("DG4 – Lichtbild", "DG4 – portrait");
        IdlReadout idl;
        try { idl = Idl.Parse(result.DataGroups); }
        catch (Exception ex) { MrzFindings = T("⚠ IDL-Datengruppen: ", "⚠ IDL data groups: ") + ex.Message; return; }
        foreach (var f in idl.Fields) IdlFields.Add(f);

        // Overview panel: the DG1 fields, then the driving privileges.
        foreach (var f in idl.Fields.Where(f => f.Path.StartsWith("DG1/5F1F") || f.TagHex == "53" && Idl.IsDg1(f.Path)))
            MrzRows.Add(new MrzRow(f.Name, f.Value, f.Findings.Count == 0 ? "✔" : "⚠"));
        foreach (var c in idl.Categories)
            MrzRows.Add(new MrzRow(T($"Klasse {c.Category}", $"Category {c.Category}"), c.Describe(), c.Findings.Count == 0 ? "✔" : "⚠"));
        // Only DG1 is mandatory (ISO/IEC 18013-2 clause 8); further DGs are expected only when EF.COM lists them.
        var expected = result.DataGroupsListed.Append(1).Distinct().Order();
        var notRead = expected.Where(d => !result.DataGroups.ContainsKey(d)).ToList();
        bool Refused(int d) => result.Steps.Any(s => s.Id == $"read:EF.DG{d}" && s.Outcome == StepOutcome.Failed && s.Detail.Contains("6982"));
        var protectedDgs = notRead.Where(Refused).Select(d => $"DG{d}").ToList();
        var missing = notRead.Where(d => !Refused(d)).Select(d => $"DG{d}").ToList();
        var findings = idl.Fields.Where(f => Idl.IsDg1(f.Path)).SelectMany(f => f.Findings).Concat(idl.Categories.SelectMany(c => c.Findings)).Distinct()
            .Select(x => "⚠ " + x).ToList();
        if (missing.Count > 0) findings.Insert(0, T($"In EF.COM aufgeführt, aber nicht gelesen: {string.Join(", ", missing)}", $"Listed in EF.COM but not read: {string.Join(", ", missing)}"));
        if (protectedDgs.Count > 0) findings.Insert(0, T($"Nicht gelesen: {string.Join(", ", protectedDgs)} (geschützt – Terminal Authentication nötig)", $"Not read: {string.Join(", ", protectedDgs)} (protected – Terminal Authentication required)"));
        MrzFindings = string.Join(Environment.NewLine, findings);
        MrzText = string.Join("  ·  ", idl.Fields.Where(f => f.Key is "familyName" or "givenNames" or "licenceNumber").Select(f => f.Value));

        idlPortrait = idl.Images.FirstOrDefault(i => i.DataGroup == 4);
        if (idlPortrait != null)
        {
            try { FaceBitmap = FaceImageDecoder.DecodeAny(idlPortrait.Data); }
            catch (Exception ex) { FaceInfo = "⚠ DG4: " + ex.Message; }
            FaceInfo = $"{idlPortrait.Format}, {idlPortrait.Data.Length} Byte" +
                (idlPortrait.Captured != null ? T($", aufgenommen {idlPortrait.Captured}", $", captured {idlPortrait.Captured}") : "") +
                (idlPortrait.ImageType != null ? T($", Bildtyp {idlPortrait.ImageType}", $", image type {idlPortrait.ImageType}") : "") +
                (FaceInfo.StartsWith('⚠') ? Environment.NewLine + FaceInfo : "");
        }
        else FaceInfo = result.DataGroups.ContainsKey(4) ? T("DG4 enthält kein Bild (5F40).", "DG4 contains no image (5F40).") : T("DG4 nicht gelesen.", "DG4 not read.");

        if (idl.Images.FirstOrDefault(i => i.DataGroup == 5) is { } signature)
        {
            try { SignatureBitmap = FaceImageDecoder.DecodeAny(signature.Data); }
            catch (Exception ex) { FaceInfo += Environment.NewLine + T("⚠ DG5 Unterschrift: ", "⚠ DG5 signature: ") + ex.Message; }
        }
        else if (idl.Fields.FirstOrDefault(f => f.Path.StartsWith("DG5") && f.TagHex == "53") is { } text)
            FaceInfo += Environment.NewLine + T($"DG5: „{text.Value}“ (kein Bild)", $"DG5: \"{text.Value}\" (no image)");
    }

    private void SaveIdlPortrait(IdlImage image)
    {
        var ext = image.Format == "JPEG" ? "jpg" : "jp2";
        var dlg = new Microsoft.Win32.SaveFileDialog { Filter = T($"Originalbild (*.{ext})|*.{ext}|PNG (*.png)|*.png", $"Original image (*.{ext})|*.{ext}|PNG (*.png)|*.png"), FileName = T($"DG4_Lichtbild.{ext}", $"DG4_portrait.{ext}") };
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
