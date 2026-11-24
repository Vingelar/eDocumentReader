using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using eDocumentReader.Core.Protocols;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Util;

namespace eDocumentReader.Core.Documents;

public enum SetDocumentType { Icao, Idl, Evrc }

/// <summary>Reading circumstances, <c>origin</c> object of project.json (SET-FORMAT.md 5.3).</summary>
public sealed class SetOrigin
{
    public string? Software { get; set; } = "eDocumentReader";
    public string? SoftwareVersion { get; set; }
    public string? ReadAt { get; set; }
    public string? ReaderDevice { get; set; }
    public string? AccessProtocol { get; set; }
    public string? PassiveAuthentication { get; set; }
    public string? ChipAuthentication { get; set; }
    public string? ActiveAuthentication { get; set; }
    public string? TerminalAuthentication { get; set; }
    public string? Atr { get; set; }
    public Dictionary<string, string> NotRead { get; set; } = [];
    public List<string> Notes { get; set; } = [];
}

/// <summary>One EF of a set as written to <c>ef/</c>.</summary>
public sealed record SetFile(string Name, int? DataGroup, string FileId, byte[] Data);

/// <summary>Everything needed to write a set; built by <see cref="DocumentSet.FromEmrtd"/> or <see cref="DocumentSet.FromEvrc"/>.</summary>
public sealed class SetExport
{
    public required SetDocumentType DocumentType { get; init; }
    public List<SetFile> Files { get; } = [];
    public string? DocumentNumber { get; set; }
    public string? Holder { get; set; }
    public string? Authentication { get; set; }
    public string? Can { get; set; }
    public string? MrzFormat { get; set; }
    public int? PaceParamId { get; set; }
    public string? LdsVersion { get; set; }
    public string? HashAlgorithm { get; set; }
    /// <summary>CSCA certificate (DER), written to <c>reader/CSCA.der</c>.</summary>
    public byte[]? Csca { get; set; }
    public SetOrigin Origin { get; } = new();
    public DateTimeOffset Created { get; set; } = DateTimeOffset.Now;
}

/// <summary>
/// Exchange format for single EF files and complete data sets ("sets") as specified by
/// PaceSetupGen, H:\JOB\ICAO\ICAO_perso\docs\SET-FORMAT.md, schema version 1, <c>"source": "reader"</c>.
/// </summary>
public static class DocumentSet
{
    public const int SchemaVersion = 1;

    /// <summary>Export name of an EF read by <see cref="EmrtdReader"/> (e.g. "EF.DG1" → "DG1"); null for EFs not part of the format (EF.CVCA).</summary>
    public static string? ExportName(EmrtdFile f) => f.DataGroup > 0 ? $"DG{f.DataGroup}" : f.Name switch
    {
        "EF.COM" or "EF.SOD" or "EF.CardAccess" or "EF.CardSecurity" => f.Name,
        _ when f.Name.StartsWith("EF.Registration_") || f.Name.StartsWith("EF.Signature_") || f.Name.StartsWith("EF.C.IA_") => f.Name,
        _ => null,
    };

    /// <summary>File name for a single exported EF (SET-FORMAT.md 2): <c>DG&lt;n&gt;.bin</c>, <c>EF.COM.bin</c> …</summary>
    public static string SingleFileName(EmrtdFile f) => (ExportName(f) ?? f.Name) + ".bin";

    /// <summary>
    /// FID of the EF. Files read by SFI carry no FID; the standard FID of the application is entered then
    /// (9303-10 Table 34, 18013-2), which is informational only (SET-FORMAT.md 4).
    /// </summary>
    public static string FileId(SetDocumentType type, string name, int? dg, ushort? readFid)
    {
        if (readFid is { } fid) return fid.ToString("X4");
        return (type, name, dg) switch
        {
            (_, "EF.CardAccess", _) => "011C",
            (SetDocumentType.Idl, "EF.COM", _) => "001E",
            (SetDocumentType.Idl, "EF.SOD", _) => "001D",
            (SetDocumentType.Idl, _, { } n) => $"00{n:X2}",
            (_, "EF.COM", _) => "011E",
            (_, "EF.SOD", _) => "011D",
            (_, "EF.CardSecurity", _) => "011D",
            (_, _, { } n) => $"01{n:X2}",
            _ => "0000",
        };
    }

    /// <summary>
    /// SET-FORMAT.md 1.2: the file holds exactly the outer TLV object. Surplus bytes after it are cut off unless
    /// only the untrimmed content matches the SOD hash.
    /// </summary>
    public static (byte[] Data, string? Note) TrimToTlv(string name, byte[] data, SecurityObject? sod, int dataGroup)
    {
        int tlvLength;
        try { tlvLength = BerTlv.ParseSingle(data).TotalLength; }
        catch { return (data, $"{name}: kein gültiges BER-TLV, Rohbytes unverändert übernommen"); }
        if (tlvLength >= data.Length) return (data, null);
        var trimmed = data[..tlvLength];
        var surplus = data.Length - tlvLength;
        if (sod != null && dataGroup > 0 && sod.Hashes.FirstOrDefault(h => h.DataGroup == dataGroup) is { } expected
            && !sod.Hash(trimmed).AsSpan().SequenceEqual(expected.Hash) && sod.Hash(data).AsSpan().SequenceEqual(expected.Hash))
            return (data, $"{name}: {surplus} Byte hinter dem TLV behalten, weil nur so der SOD-Hash stimmt");
        return (trimmed, $"{name}: {surplus} Byte Padding hinter dem TLV abgeschnitten");
    }

    /// <summary>Builds the export of an eMRTD or IDL read.</summary>
    public static SetExport FromEmrtd(EmrtdReadResult result, bool isIdl, string? can = null)
    {
        var type = isIdl ? SetDocumentType.Idl : SetDocumentType.Icao;
        var export = new SetExport { DocumentType = type };
        var sod = result.PassiveAuthentication?.Sod;
        if (sod == null && result.File("EF.SOD") is { } sodBytes)
        {
            try { sod = new SecurityObject(sodBytes); } catch { sod = null; }
        }

        // Order: EF.COM, DGs ascending, EF.SOD, then the MF files (SET-FORMAT.md 5.2).
        int Rank(EmrtdFile f) => f.Name == "EF.COM" ? 0 : f.DataGroup > 0 ? f.DataGroup : f.Name == "EF.SOD" ? 100 : 200;
        foreach (var f in result.Files.OrderBy(Rank))
        {
            if (ExportName(f) is not { } name) continue;
            if (export.Files.Any(x => x.Name == name)) continue;
            var (data, note) = TrimToTlv(name, f.Data, sod, f.DataGroup);
            if (note != null) export.Origin.Notes.Add(note);
            export.Files.Add(new SetFile(name, f.DataGroup > 0 ? f.DataGroup : null, FileId(type, name, f.DataGroup > 0 ? f.DataGroup : null, f.Fid), data));
        }

        // Not (completely) read EFs: listed in EF.SOD or EF.COM, but without a file (SET-FORMAT.md 1.4).
        var expected = new SortedSet<int>(sod?.Hashes.Select(h => h.DataGroup) ?? []);
        foreach (var dg in result.DataGroupsListed) expected.Add(dg);
        foreach (var dg in expected.Where(d => !result.DataGroups.ContainsKey(d)))
        {
            var step = result.Steps.LastOrDefault(s => s.Name == $"Lesen EF.DG{dg}" && s.Outcome == StepOutcome.Failed);
            var reason = step?.Detail ?? (Lds.IsEacProtected(dg) && !isIdl ? "EAC erforderlich" : "nicht gelesen");
            export.Origin.NotRead[$"DG{dg}"] = reason.StartsWith($"EF.DG{dg}: ") ? reason[($"EF.DG{dg}: ").Length..] : reason;
        }

        // Access and security protocols as read (SET-FORMAT.md 5.1 / 5.3).
        var access = result.AccessControl ?? "";
        export.Origin.AccessProtocol = access.StartsWith("PACE") ? (access.Contains("CAN") ? "PACE-CAN" : "PACE-MRZ")
            : access.StartsWith("BAP") ? "BAP" : access.StartsWith("BAC") ? (isIdl ? "BAP" : "BAC") : "NONE";
        export.Authentication = export.Origin.AccessProtocol switch { "PACE-CAN" or "PACE-MRZ" => "PACE", "BAP" => "BAP", "BAC" => "BAC", _ => null };
        if (export.Origin.AccessProtocol == "PACE-CAN" && can is { Length: > 0 } && can.All(char.IsAsciiDigit)) export.Can = can;
        export.Origin.PassiveAuthentication = result.PassiveAuthentication is { } pa ? (pa.Valid ? "OK" : "FAILED") : "NOT_PERFORMED";
        export.Origin.ChipAuthentication = Outcome(result, "Chip Authentication");
        export.Origin.TerminalAuthentication = Outcome(result, "Terminal Authentication");
        export.Origin.ActiveAuthentication = Outcome(result, "Active Authentication");

        if (result.File("EF.CardAccess") is { } cardAccess)
        {
            try { export.PaceParamId = SecurityInfos.Parse(cardAccess).OfType<PaceInfo>().Select(p => p.ParameterId).FirstOrDefault(p => p != null); }
            catch { /* reference only */ }
        }
        if (sod != null) export.HashAlgorithm = HashName(sod.HashName.Name);
        export.LdsVersion = isIdl ? "0100" : LdsVersionFromCom(result.File("EF.COM"));
        if (isIdl && LdsVersionFromCom(result.File("EF.COM")) is { } idlCom && idlCom != "0100")
            export.Origin.Notes.Add($"EF.COM '5F01' = {idlCom}");
        if (result.PassiveAuthentication?.Chain?.Csca is { } csca) export.Csca = csca.GetEncoded();

        // Holder and document number for the display name and the folder name.
        if (!isIdl && result.DataGroups.TryGetValue(1, out var dg1))
        {
            try
            {
                if (Lds.ParseDg1(dg1) is { } mrz)
                {
                    export.Holder = Title($"{mrz.SecondaryIdentifier} {mrz.PrimaryIdentifier}");
                    export.DocumentNumber = mrz.DocumentNumber.TrimEnd('<');
                    export.MrzFormat = mrz.Format.ToString();
                }
            }
            catch (FormatException) { /* DG1 is exported byte-exact anyway */ }
        }
        if (isIdl)
        {
            var idl = Idl.Parse(result.DataGroups);
            string? Field(string n) => idl.Fields.FirstOrDefault(f => f.Name == n)?.Value;
            if (Field("Familienname") is { } family) export.Holder = Title($"{Field("Vornamen")} {family}");
            export.DocumentNumber = Field("Führerscheinnummer");
        }
        return export;
    }

    /// <summary>Builds the export of an eVRC read (SET-FORMAT.md 4.3).</summary>
    public static SetExport FromEvrc(EvrcReadResult result)
    {
        var export = new SetExport { DocumentType = SetDocumentType.Evrc };
        int Rank(string n) => (n.EndsWith("_B") || n.Contains("_B.") ? 10 : 0) + (n.StartsWith("EF.Registration") ? 0 : n.StartsWith("EF.Signature") ? 1 : 2);
        foreach (var f in result.Files.OrderBy(f => Rank(f.Name)))
        {
            if (ExportName(f) is not { } name) continue;
            // The registration file holds two TLV objects ('78' and the template); it is exported unchanged.
            export.Files.Add(new SetFile(name, null, FileId(SetDocumentType.Evrc, name, null, f.Fid), f.Data));
        }
        if (result.File("EF.Registration_A") is { } a)
        {
            try
            {
                var tags = BerTlv.ParseAll(a).Select(t => t.Tag).ToList();
                export.LdsVersion = tags.Contains(0x73u) ? "Part2" : tags.Contains(0x71u) ? "Part1" : null;
            }
            catch { /* unknown structure: no part information */ }
        }
        export.Holder = result.Fields.FirstOrDefault(f => f.TagHex == "81")?.Value;
        export.DocumentNumber = export.Holder;
        export.Origin.AccessProtocol = "NONE";
        var signatures = result.Signatures.Where(s => s.Valid != null).ToList();
        export.Origin.PassiveAuthentication = signatures.Count == 0 ? "NOT_PERFORMED" : signatures.All(s => s.Valid == true) ? "OK" : "FAILED";
        export.Origin.Notes.AddRange(result.Findings);
        return export;
    }

    /// <summary>Folder name proposal &lt;type&gt;_&lt;document number&gt;_&lt;yyyyMMdd-HHmmss&gt; with Windows-safe characters.</summary>
    public static string FolderName(SetExport export)
    {
        var type = export.DocumentType.ToString().ToUpperInvariant();
        var number = string.IsNullOrWhiteSpace(export.DocumentNumber) ? "unbekannt" : export.DocumentNumber;
        var invalid = Path.GetInvalidFileNameChars().Concat([' ']).ToHashSet();
        var safe = new string(number.Select(c => invalid.Contains(c) ? '_' : c).ToArray());
        return $"{type}_{safe}_{export.Created:yyyyMMdd-HHmmss}";
    }

    /// <summary>Writes the set into a new folder below <paramref name="parentDirectory"/> and returns its path.</summary>
    public static string Write(SetExport export, string parentDirectory)
    {
        var dir = Path.Combine(parentDirectory, FolderName(export));
        if (Directory.Exists(dir)) throw new IOException($"Ordner existiert bereits: {dir}");
        Directory.CreateDirectory(Path.Combine(dir, "ef"));
        var entries = new List<FileEntry>();
        foreach (var f in export.Files)
        {
            var path = $"ef/{f.Name}.bin";
            File.WriteAllBytes(Path.Combine(dir, "ef", f.Name + ".bin"), f.Data);
            entries.Add(new FileEntry(f.DataGroup, f.Name, path, f.FileId, f.Data.Length, Hex.Compact(SHA256.HashData(f.Data)).ToLowerInvariant()));
        }
        string? csca = null;
        string? cscaSha = null;
        if (export.Csca != null)
        {
            Directory.CreateDirectory(Path.Combine(dir, "reader"));
            File.WriteAllBytes(Path.Combine(dir, "reader", "CSCA.der"), export.Csca);
            csca = "reader/CSCA.der";
            cscaSha = Hex.Compact(SHA256.HashData(export.Csca)).ToLowerInvariant();
        }
        var project = new Project(
            SchemaVersion, "reader", export.DocumentType.ToString().ToUpperInvariant(), entries,
            Iso(export.Created), export.Holder, export.Authentication, export.Can, export.MrzFormat, export.PaceParamId,
            export.LdsVersion, export.HashAlgorithm, csca, cscaSha, export.Origin);
        File.WriteAllText(Path.Combine(dir, "project.json"), JsonSerializer.Serialize(project, JsonOptions), new UTF8Encoding(false));
        return dir;
    }

    public static string Iso(DateTimeOffset t) => t.ToString("yyyy-MM-dd'T'HH:mm:sszzz", CultureInfo.InvariantCulture);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DictionaryKeyPolicy = null,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private sealed record Project(
        int SchemaVersion, string Source, string DocumentType, List<FileEntry> Files,
        string Created, string? Holder, string? Authentication, string? Can, string? MrzFormat, int? PaceParamId,
        string? LdsVersion, string? HashAlgorithm, string? Csca, string? CscaSha256, SetOrigin Origin);

    /// <summary><c>dataGroup</c> is mandatory and written as <c>null</c> for non-DG files (SET-FORMAT.md 5.2).</summary>
    private sealed record FileEntry(
        [property: JsonIgnore(Condition = JsonIgnoreCondition.Never)] int? DataGroup,
        string Name, string Path, string FileId, int Length, string Sha256);

    private static string Outcome(EmrtdReadResult r, string step) => r.Steps.LastOrDefault(s => s.Name == step)?.Outcome switch
    {
        StepOutcome.Success => "OK",
        StepOutcome.Failed => "FAILED",
        _ => "NOT_PERFORMED",
    };

    private static string HashName(string name) => name switch
    {
        "SHA1" => "SHA-1", "SHA224" => "SHA-224", "SHA256" => "SHA-256", "SHA384" => "SHA-384", "SHA512" => "SHA-512", _ => name,
    };

    private static string? LdsVersionFromCom(byte[]? com)
    {
        if (com == null) return null;
        try
        {
            var v = BerTlv.ParseSingle(com).Find(0x5F01)?.Value;
            if (v == null) return null;
            return v.All(b => b is >= (byte)'0' and <= (byte)'9') ? Encoding.ASCII.GetString(v) : Hex.Compact(v);
        }
        catch { return null; }
    }

    private static string Title(string s) =>
        CultureInfo.GetCultureInfo("de-DE").TextInfo.ToTitleCase(s.Trim().ToLowerInvariant());
}
