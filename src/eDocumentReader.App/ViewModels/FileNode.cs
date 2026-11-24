using System.Text;
using eDocumentReader.Core.Documents;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Util;

namespace eDocumentReader.App.ViewModels;

/// <summary>Node of the file tree: an EF as read from the chip, or one BER-TLV data object inside it.</summary>
public sealed class FileNode
{
    private const int MaxHexBytes = 64 * 1024;

    public required string Header { get; init; }
    public required byte[] Data { get; init; }
    /// <summary>The EF this node represents; set on the top-level node of each file only.</summary>
    public EmrtdFile? File { get; init; }
    public string Details { get; init; } = string.Empty;
    public List<FileNode> Children { get; init; } = [];
    public bool HasFindings { get; init; }
    public bool IsExpanded { get; set; }

    public string HexDump => Data.Length <= MaxHexBytes
        ? Hex.Dump(Data)
        : Hex.Dump(Data.AsSpan(0, MaxHexBytes)) + $"{Environment.NewLine}… {Data.Length - MaxHexBytes} weitere Bytes";

    /// <param name="tagNames">Tag dictionary of the application the file belongs to (default: ICAO LDS).</param>
    public static FileNode FromFile(EmrtdFile file, Func<uint, string?>? tagNames = null)
    {
        tagNames ??= Lds.TagName;
        var children = new List<FileNode>();
        string details;
        var findings = false;
        var id = file.Fid is { } fid ? $"FID {fid:X4}" : $"SFI {file.Sfi:X2}";
        try
        {
            foreach (var tlv in BerTlv.ParseAll(file.Data))
            {
                var node = FromTlv(tlv, tagNames);
                findings |= node.HasFindings;
                children.Add(node);
            }
            details = $"{file.Name}, {id}, {file.Data.Length} Bytes";
        }
        catch (TlvException ex)
        {
            findings = true;
            details = $"{file.Name}, {id}, {file.Data.Length} Bytes{Environment.NewLine}⚠ {ex.Message}";
        }
        var content = file.DataGroup > 0 ? Lds.DataGroupContent(file.DataGroup) : null;
        return new FileNode
        {
            File = file,
            Header = $"{file.Name}{(string.IsNullOrEmpty(content) ? "" : $" – {content}")} ({file.Data.Length} B)",
            Data = file.Data,
            Details = details,
            Children = children,
            HasFindings = findings,
            IsExpanded = true,
        };
    }

    private static FileNode FromTlv(BerTlv tlv, Func<uint, string?> tagNames)
    {
        var children = tlv.Children.Select(c => FromTlv(c, tagNames)).ToList();
        var name = tagNames(tlv.Tag);
        var sb = new StringBuilder();
        sb.AppendLine($"Tag {tlv.TagHex}{(name != null ? $" ({name})" : "")}, {tlv.Class}, {(tlv.IsConstructed ? "konstruiert" : "primitiv")}");
        sb.AppendLine($"Offset {tlv.Offset}, Header {tlv.HeaderLength} B, Wert {tlv.Value.Length} B");
        if (!tlv.IsConstructed && tlv.Value.Length is > 0 and <= 512 && tlv.Value.All(b => b is >= 0x20 and < 0x7F))
            sb.AppendLine($"Text: \"{Encoding.ASCII.GetString(tlv.Value)}\"");
        foreach (var f in tlv.Findings) sb.AppendLine("⚠ " + f);
        return new FileNode
        {
            Header = $"{tlv.TagHex}{(name != null ? $" {name}" : "")} [{tlv.Value.Length}]",
            Data = tlv.Value,
            Details = sb.ToString().TrimEnd(),
            Children = children,
            HasFindings = tlv.Findings.Count > 0 || children.Any(c => c.HasFindings),
            IsExpanded = tlv.Value.Length < 4096 && children.Count <= 8,
        };
    }
}
