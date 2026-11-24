using eDocumentReader.Core.Documents;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Pki;
using eDocumentReader.Core.Protocols;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Transport;

/// <summary>Console front end for <see cref="EmrtdReader"/>: reads, saves raw files, prints the outcome.</summary>
static class ReadDocument
{
    public static int Run(CardChannel channel, EmrtdReadOptions options, string outputDirectory, PkiStore pki)
    {
        Directory.CreateDirectory(outputDirectory);
        var result = new EmrtdReader(channel, pki).Read(options);
        foreach (var f in result.Files) File.WriteAllBytes(Path.Combine(outputDirectory, f.Name + ".bin"), f.Data);
        // EDOC_SET_DIR: additionally write a set in the PaceSetupGen exchange format (SET-FORMAT.md).
        if (Environment.GetEnvironmentVariable("EDOC_SET_DIR") is { Length: > 0 } setDir)
        {
            var can = options.Key is AccessKey.CanKey c ? c.Can : null;
            Console.WriteLine("Set gespeichert in: " + DocumentSet.Write(DocumentSet.FromEmrtd(result, options.IsIdl, can), setDir));
        }

        Console.WriteLine();
        Console.WriteLine("=== Ablauf ===");
        foreach (var s in result.Steps) Console.WriteLine($"{s.Name}: {s.Outcome} – {s.Detail}");
        Console.WriteLine($"Dateien gespeichert in: {outputDirectory}");
        Analyze(outputDirectory, channel.Logger, pki);
        return 0;
    }

    public static void Analyze(string directory, Logger log, PkiStore? pki = null)
    {
        Console.WriteLine();
        Console.WriteLine("=== Passive Authentication ===");
        var dataGroups = new Dictionary<int, byte[]>();
        for (var dg = 1; dg <= 16; dg++)
        {
            var file = Path.Combine(directory, $"EF.DG{dg}.bin");
            if (File.Exists(file)) dataGroups[dg] = File.ReadAllBytes(file);
        }
        var pa = PassiveAuthentication.Verify(File.ReadAllBytes(Path.Combine(directory, "EF.SOD.bin")), dataGroups, pki);
        foreach (var f in pa.Sod.Findings) Console.WriteLine("⚠ " + f);
        Console.WriteLine($"SOD: LDSSecurityObject v{pa.Sod.Version}, {pa.Sod.HashName.Name}, LDS {pa.Sod.LdsVersion ?? "-"}");
        foreach (var h in pa.Hashes)
            Console.WriteLine($"  DG{h.DataGroup,-2} Hash: {(h.Match switch { true => "OK", false => "FALSCH", null => "nicht gelesen" })}");
        Console.WriteLine($"SOD-Signatur: {pa.SignatureDetail}");
        if (pa.Signer != null) Console.WriteLine(SecurityObject.Describe(pa.Signer));
        if (pa.Chain != null)
        {
            foreach (var s in pa.Chain.Steps) Console.WriteLine("  " + s);
            Console.WriteLine($"Zertifikatskette DS → CSCA: {(pa.Chain.Valid ? "GÜLTIG" : "NICHT GÜLTIG")}");
        }
        if (dataGroups.TryGetValue(14, out var dg14))
        {
            Console.WriteLine("DG14 SecurityInfos:");
            foreach (var si in SecurityInfos.Parse(BerTlv.ParseSingle(dg14).Value)) Console.WriteLine("  " + si.Description);
        }
        // eMRTD interpretation of DG1/DG2; IDL data groups (ISO/IEC 18013-2 Annex C) have a different structure.
        try
        {
            if (dataGroups.TryGetValue(1, out var dg1) && Lds.ParseDg1(dg1) is { } mrz)
                Console.WriteLine($"DG1 MRZ: {mrz.Format}, {mrz.Fields.Count} Felder, Prüfziffern {(mrz.Fields.All(f => f.Valid != false) ? "OK" : "FEHLER")}");
            if (dataGroups.TryGetValue(2, out var dg2))
                foreach (var face in FaceImageParser.ParseDg2(dg2))
                {
                    Console.WriteLine("DG2 " + face.Describe());
                    foreach (var f in face.Findings) Console.WriteLine("  ⚠ " + f);
                }
        }
        catch (FormatException ex) { Console.WriteLine($"DG1/DG2 nicht als eMRTD-Struktur lesbar (IDL?): {ex.Message}"); }
    }
}
