using System.Globalization;
using System.Text;

namespace eDocumentReader.Core.Util;

public static class Hex
{
    public static string Of(ReadOnlySpan<byte> data, string separator = " ")
    {
        if (data.IsEmpty) return string.Empty;
        var sb = new StringBuilder(data.Length * (2 + separator.Length));
        for (var i = 0; i < data.Length; i++)
        {
            if (i > 0) sb.Append(separator);
            sb.Append(data[i].ToString("X2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    public static string Compact(ReadOnlySpan<byte> data) => Of(data, string.Empty);

    /// <summary>Parses hex text; whitespace, ':' and '-' separators are ignored.</summary>
    public static byte[] Parse(string text)
    {
        var digits = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            if (char.IsWhiteSpace(c) || c is ':' or '-') continue;
            if (!Uri.IsHexDigit(c)) throw new FormatException($"Ungültiges Hex-Zeichen '{c}'.");
            digits.Append(c);
        }
        if (digits.Length % 2 != 0) throw new FormatException("Ungerade Anzahl Hex-Ziffern.");
        return Convert.FromHexString(digits.ToString());
    }

    /// <summary>Classic hex dump (16 bytes per line, offset + ASCII).</summary>
    public static string Dump(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder();
        for (var offset = 0; offset < data.Length; offset += 16)
        {
            var line = data.Slice(offset, Math.Min(16, data.Length - offset));
            sb.Append(offset.ToString("X4", CultureInfo.InvariantCulture)).Append("  ");
            for (var i = 0; i < 16; i++)
                sb.Append(i < line.Length ? line[i].ToString("X2", CultureInfo.InvariantCulture) + " " : "   ");
            sb.Append(' ');
            foreach (var b in line) sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
            sb.AppendLine();
        }
        return sb.ToString();
    }
}
