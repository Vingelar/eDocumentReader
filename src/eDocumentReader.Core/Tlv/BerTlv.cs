using System.Text;
using eDocumentReader.Core.Util;

namespace eDocumentReader.Core.Tlv;

public enum TagClass { Universal = 0, Application = 1, ContextSpecific = 2, Private = 3 }

/// <summary>
/// BER-TLV data object according to ISO/IEC 7816-4:2005 clause 5.2.2 (tag fields 5.2.2.1, length fields 5.2.2.2).
/// Parsing is tolerant, but every deviation from 7816-4 / DER is reported in <see cref="Findings"/>.
/// </summary>
public sealed class BerTlv
{
    public uint Tag { get; }
    public byte[] TagBytes { get; }
    public byte[] Value { get; }
    public int Offset { get; }
    public int HeaderLength { get; }
    public IReadOnlyList<BerTlv> Children { get; }
    public IReadOnlyList<string> Findings { get; }

    public TagClass Class => (TagClass)(TagBytes[0] >> 6);
    public bool IsConstructed => (TagBytes[0] & 0x20) != 0;
    public int TotalLength => HeaderLength + Value.Length;
    public string TagHex => Hex.Compact(TagBytes);

    private BerTlv(byte[] tagBytes, byte[] value, int offset, int headerLength, IReadOnlyList<BerTlv> children, IReadOnlyList<string> findings)
    {
        TagBytes = tagBytes;
        Tag = tagBytes.Aggregate(0u, (acc, b) => (acc << 8) | b);
        Value = value;
        Offset = offset;
        HeaderLength = headerLength;
        Children = children;
        Findings = findings;
    }

    public BerTlv? Find(uint tag) => Children.FirstOrDefault(c => c.Tag == tag);
    public IEnumerable<BerTlv> FindAll(uint tag) => Children.Where(c => c.Tag == tag);

    public BerTlv? FindRecursive(uint tag)
    {
        foreach (var child in Children)
        {
            if (child.Tag == tag) return child;
            var nested = child.FindRecursive(tag);
            if (nested != null) return nested;
        }
        return null;
    }

    /// <summary>Parses a single data object at the start of <paramref name="data"/>.</summary>
    public static BerTlv ParseSingle(ReadOnlySpan<byte> data, int baseOffset = 0)
    {
        var pos = 0;
        return ParseOne(data, ref pos, baseOffset, insideTemplate: false);
    }

    /// <summary>
    /// Parses a data field as a sequence of BER-TLV objects. '00' padding before, between or after objects is accepted
    /// at this (non-template) level as permitted by 7816-4 5.2.2.1.
    /// </summary>
    public static List<BerTlv> ParseAll(ReadOnlySpan<byte> data, int baseOffset = 0) => ParseSequence(data, baseOffset, insideTemplate: false);

    private static List<BerTlv> ParseSequence(ReadOnlySpan<byte> data, int baseOffset, bool insideTemplate)
    {
        var list = new List<BerTlv>();
        var pos = 0;
        while (pos < data.Length)
        {
            if (data[pos] == 0x00)
            {
                if (insideTemplate) throw new TlvException(baseOffset + pos, T("Füllbyte '00' innerhalb eines Templates ist nach ISO/IEC 7816-4 5.2.2.1 unzulässig.", "Padding byte '00' inside a template is not allowed (ISO/IEC 7816-4 5.2.2.1)."));
                pos++;
                continue;
            }
            list.Add(ParseOne(data, ref pos, baseOffset, insideTemplate));
        }
        return list;
    }

    private static BerTlv ParseOne(ReadOnlySpan<byte> data, ref int pos, int baseOffset, bool insideTemplate)
    {
        var start = pos;
        var findings = new List<string>();
        if (pos >= data.Length) throw new TlvException(baseOffset + pos, T("Unerwartetes Ende vor Tag-Feld.", "Unexpected end before the tag field."));
        if (data[pos] == 0x00) throw new TlvException(baseOffset + pos, T("Tag-Byte '00' ist ungültig (ISO/IEC 7816-4 5.2.2).", "Tag byte '00' is invalid (ISO/IEC 7816-4 5.2.2)."));

        var tagStart = pos++;
        if ((data[tagStart] & 0x1F) == 0x1F)
        {
            if (pos >= data.Length) throw new TlvException(baseOffset + pos, T("Unerwartetes Ende im Tag-Feld.", "Unexpected end in the tag field."));
            if ((data[pos] & 0x7F) == 0) findings.Add(T("Bits 7..1 des ersten Folgebytes im Tag sind alle 0 (ISO/IEC 7816-4 5.2.2.1).", "Bits 7..1 of the first subsequent tag byte are all 0 (ISO/IEC 7816-4 5.2.2.1)."));
            // 7816-4 5.2.2.1 forbids '00'..'1E' as second tag byte. ICAO 9303-10 / ISO/IEC 18013-2 nevertheless define
            // application-class tags '5F01'..'5F1E' (e.g. LDS version '5F01'); these are accepted as specified there.
            if (data[pos] <= 0x1E && !(data[tagStart] == 0x5F && data[pos] != 0x00))
                findings.Add(T($"Zweites Tag-Byte {data[pos]:X2} kodiert Tag-Nummer < 31 in Langform (ISO/IEC 7816-4 5.2.2.1: unzulässig).", $"Second tag byte {data[pos]:X2} encodes a tag number < 31 in long form (ISO/IEC 7816-4 5.2.2.1: not allowed)."));
            while ((data[pos] & 0x80) != 0)
            {
                pos++;
                if (pos >= data.Length) throw new TlvException(baseOffset + pos, T("Unerwartetes Ende im Tag-Feld.", "Unexpected end in the tag field."));
            }
            pos++;
            if (pos - tagStart > 3) findings.Add(T($"Tag-Feld mit {pos - tagStart} Bytes; ISO/IEC 7816 unterstützt max. 3 Bytes.", $"Tag field with {pos - tagStart} bytes; ISO/IEC 7816 supports at most 3 bytes."));
        }
        var tagBytes = data[tagStart..pos].ToArray();

        if (pos >= data.Length) throw new TlvException(baseOffset + pos, T($"Unerwartetes Ende vor Längenfeld (Tag {Hex.Compact(tagBytes)}).", $"Unexpected end before the length field (tag {Hex.Compact(tagBytes)})."));
        int length;
        var first = data[pos++];
        if (first < 0x80) length = first;
        else if (first == 0x80) throw new TlvException(baseOffset + pos - 1, T("Unbestimmte Länge '80' wird in ISO/IEC 7816 nicht verwendet.", "Indefinite length '80' is not used in ISO/IEC 7816."));
        else
        {
            var count = first & 0x7F;
            if (count > 4) throw new TlvException(baseOffset + pos - 1, T($"Längenfeld-Byte {first:X2} ungültig (nur '81'..'84').", $"Length field byte {first:X2} invalid (only '81'..'84')."));
            if (pos + count > data.Length) throw new TlvException(baseOffset + pos, T("Unerwartetes Ende im Längenfeld.", "Unexpected end in the length field."));
            long l = 0;
            for (var i = 0; i < count; i++) l = (l << 8) | data[pos++];
            if (l > int.MaxValue) throw new TlvException(baseOffset + pos, T("Länge zu groß.", "Length too large."));
            length = (int)l;
            var minimal = length < 0x80 ? 0 : length <= 0xFF ? 1 : length <= 0xFFFF ? 2 : length <= 0xFFFFFF ? 3 : 4;
            if (count != minimal) findings.Add(T($"Längenfeld nicht minimal kodiert ({count + 1} Bytes für {length}) – DER-Verstoß.", $"Length field not minimally encoded ({count + 1} bytes for {length}) – DER violation."));
        }

        var headerLength = pos - start;
        if (pos + length > data.Length)
            throw new TlvException(baseOffset + start, T($"Tag {Hex.Compact(tagBytes)}: Länge {length} überschreitet verfügbare {data.Length - pos} Bytes.", $"Tag {Hex.Compact(tagBytes)}: length {length} exceeds the available {data.Length - pos} bytes."));
        var value = data.Slice(pos, length);
        pos += length;

        IReadOnlyList<BerTlv> children = [];
        if ((tagBytes[0] & 0x20) != 0)
            children = ParseSequence(value, baseOffset + start + headerLength, insideTemplate: true);

        return new BerTlv(tagBytes, value.ToArray(), baseOffset + start, headerLength, children, findings);
    }

    public byte[] Encode() => Encode(TagBytes, Value);

    public static byte[] Encode(uint tag, ReadOnlySpan<byte> value) => Encode(TagToBytes(tag), value);

    public static byte[] Encode(ReadOnlySpan<byte> tag, ReadOnlySpan<byte> value)
    {
        var length = EncodeLength(value.Length);
        var result = new byte[tag.Length + length.Length + value.Length];
        tag.CopyTo(result);
        length.CopyTo(result.AsSpan(tag.Length));
        value.CopyTo(result.AsSpan(tag.Length + length.Length));
        return result;
    }

    public static byte[] EncodeConstructed(uint tag, params byte[][] children) => Encode(TagToBytes(tag), (ReadOnlySpan<byte>)children.SelectMany(c => c).ToArray());

    public static byte[] TagToBytes(uint tag)
    {
        if (tag <= 0xFF) return [(byte)tag];
        if (tag <= 0xFFFF) return [(byte)(tag >> 8), (byte)tag];
        if (tag <= 0xFFFFFF) return [(byte)(tag >> 16), (byte)(tag >> 8), (byte)tag];
        return [(byte)(tag >> 24), (byte)(tag >> 16), (byte)(tag >> 8), (byte)tag];
    }

    /// <summary>Minimal (DER) length encoding, ISO/IEC 7816-4 Table 8.</summary>
    public static byte[] EncodeLength(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        if (length < 0x80) return [(byte)length];
        if (length <= 0xFF) return [0x81, (byte)length];
        if (length <= 0xFFFF) return [0x82, (byte)(length >> 8), (byte)length];
        if (length <= 0xFFFFFF) return [0x83, (byte)(length >> 16), (byte)(length >> 8), (byte)length];
        return [0x84, (byte)(length >> 24), (byte)(length >> 16), (byte)(length >> 8), (byte)length];
    }

    public override string ToString() => $"{TagHex} [{Value.Length}]";

    public string ToTreeString()
    {
        var sb = new StringBuilder();
        AppendTree(sb, 0);
        return sb.ToString();
    }

    private void AppendTree(StringBuilder sb, int indent)
    {
        sb.Append(' ', indent * 2).Append(TagHex).Append(" L=").Append(Value.Length);
        if (!IsConstructed) sb.Append("  ").Append(Value.Length <= 64 ? Hex.Of(Value) : Hex.Of(Value.AsSpan(0, 64)) + " …");
        foreach (var f in Findings) sb.Append("  ⚠ ").Append(f);
        sb.AppendLine();
        foreach (var c in Children) c.AppendTree(sb, indent + 1);
    }
}

public sealed class TlvException(int offset, string message) : FormatException(T($"TLV-Fehler bei Offset {offset}: {message}", $"TLV error at offset {offset}: {message}"))
{
    public int Offset { get; } = offset;
}
