using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Tlv;
using eDocumentReader.Core.Transport;

namespace eDocumentReader.Core.Documents;

public sealed class FileReadException(string message, StatusWord? status = null) : Exception(message)
{
    public StatusWord? Status { get; } = status;
}

/// <summary>Reading transparent EFs according to ISO/IEC 7816-4 7.2.3 and ICAO 9303-10 (SFI access, 3.6 / 9303-11 Appendix D.4).</summary>
public sealed class FileReader(IApduChannel channel)
{
    /// <summary>Maximum Le per READ BINARY. 0xDF keeps protected responses below 256 bytes (3DES/AES SM overhead).</summary>
    public int MaxChunk { get; set; } = 0xDF;

    public IApduChannel Channel { get; } = channel;

    /// <summary>Called after each READ BINARY with (file name, bytes read, total bytes).</summary>
    public Action<string, int, int>? Progress { get; set; }

    public CancellationToken Cancellation { get; set; }

    /// <summary>Reads a complete BER-TLV structured EF identified by its short EF identifier.</summary>
    public byte[] ReadBySfi(byte sfi, string name)
    {
        Channel.Logger.Info(LogCategory.Protocol, T($"Lese {name} (SFI {sfi:X2})", $"Reading {name} (SFI {sfi:X2})"));
        // First READ BINARY with SFI selects the EF implicitly (ISO/IEC 7816-4 7.2.3, P1 b8=1).
        var head = Channel.Transmit(new CommandApdu(0x00, 0xB0, (byte)(0x80 | sfi), 0x00, null, 8), $"READ BINARY {name} (SFI {sfi:X2})");
        if (!head.Status.IsCompleted || head.Data.Length == 0)
            throw new FileReadException($"{name}: {head.Status} {head.Status.Description}", head.Status);
        return ReadRemaining(head.Data, name);
    }

    /// <summary>Reads a small EF without TLV structure (e.g. EF.CVCA) with a single READ BINARY, Le = 256.</summary>
    public byte[] ReadSmallBySfi(byte sfi, string name)
    {
        var r = Channel.Transmit(new CommandApdu(0x00, 0xB0, (byte)(0x80 | sfi), 0x00, null, 256), $"READ BINARY {name} (SFI {sfi:X2})");
        if (!r.Status.IsCompleted) throw new FileReadException($"{name}: {r.Status} {r.Status.Description}", r.Status);
        return r.Data;
    }

    /// <summary>Reads a complete EF after SELECT by file identifier (P1='02', P2='0C').</summary>
    public byte[] ReadByFid(ushort fid, string name)
    {
        var sel = Channel.Transmit(new CommandApdu(0x00, 0xA4, 0x02, 0x0C, [(byte)(fid >> 8), (byte)fid]), $"SELECT {name} ({fid:X4})");
        if (!sel.Status.IsSuccess) throw new FileReadException($"{name}: SELECT {sel.Status} {sel.Status.Description}", sel.Status);
        var head = ReadAt(0, 8, name);
        return ReadRemaining(head, name);
    }

    /// <summary>
    /// Reads up to <paramref name="size"/> bytes of the currently selected transparent EF from offset 0 (size e.g. from FCP tag '80').
    /// SW '6282' (end of file reached before reading Ne bytes, ISO/IEC 7816-4 Table 6) ends the file early; the caller
    /// sees this as a result shorter than <paramref name="size"/>.
    /// </summary>
    public byte[] ReadSelected(int size, string name)
    {
        var data = new byte[size];
        var have = 0;
        Progress?.Invoke(name, 0, size);
        while (have < size)
        {
            Cancellation.ThrowIfCancellationRequested();
            var (chunk, status) = ReadAtWithStatus(have, Math.Min(MaxChunk, size - have), name);
            var take = Math.Min(chunk.Length, size - have);
            Array.Copy(chunk, 0, data, have, take);
            have += take;
            Progress?.Invoke(name, have, size);
            if (status.Value == 0x6282)
            {
                Channel.Logger.Info(LogCategory.Protocol, T($"{name}: Dateiende nach {have} Bytes (6282)", $"{name}: end of file after {have} bytes (6282)"), null, "ISO/IEC 7816-4 7.2.3");
                Progress?.Invoke(name, have, have);
                return data[..have];
            }
            if (chunk.Length == 0) throw new FileReadException(T($"{name}: leere Antwort bei Offset {have}.", $"{name}: empty response at offset {have}."));
        }
        Channel.Logger.Detail(LogCategory.Protocol, T($"{name}: {size} Bytes gelesen", $"{name}: {size} bytes read"));
        return data;
    }

    private (byte[] Data, StatusWord Status) ReadAtWithStatus(int offset, int length, string name)
    {
        if (offset > 0x7FFF) return (ReadAt(offset, length, name), new StatusWord(0x90, 0x00));
        var r = Channel.Transmit(new CommandApdu(0x00, 0xB0, (byte)(offset >> 8), (byte)offset, null, length), $"READ BINARY {name} @{offset}");
        if (!r.Status.IsCompleted) throw new FileReadException($"{name}: READ BINARY @{offset}: {r.Status} {r.Status.Description}", r.Status);
        return (r.Data, r.Status);
    }

    private byte[] ReadRemaining(byte[] head, string name)
    {
        int total;
        try
        {
            total = TotalTlvLength(head);
        }
        catch (Exception ex)
        {
            throw new FileReadException(T($"{name}: Dateianfang ist keine gültige BER-TLV-Struktur ({ex.Message}).", $"{name}: start of file is not a valid BER-TLV structure ({ex.Message})."));
        }
        var data = new byte[total];
        var have = Math.Min(head.Length, total);
        Array.Copy(head, data, have);
        Progress?.Invoke(name, have, total);
        while (have < total)
        {
            Cancellation.ThrowIfCancellationRequested();
            var chunk = ReadAt(have, Math.Min(MaxChunk, total - have), name);
            if (chunk.Length == 0) throw new FileReadException(T($"{name}: leere Antwort bei Offset {have}.", $"{name}: empty response at offset {have}."));
            var take = Math.Min(chunk.Length, total - have);
            Array.Copy(chunk, 0, data, have, take);
            have += take;
            Progress?.Invoke(name, have, total);
        }
        Channel.Logger.Detail(LogCategory.Protocol, T($"{name}: {total} Bytes gelesen", $"{name}: {total} bytes read"));
        return data;
    }

    private byte[] ReadAt(int offset, int length, string name)
    {
        ResponseApdu r;
        if (offset <= 0x7FFF)
        {
            r = Channel.Transmit(new CommandApdu(0x00, 0xB0, (byte)(offset >> 8), (byte)offset, null, length), $"READ BINARY {name} @{offset}");
            if (!r.Status.IsCompleted) throw new FileReadException($"{name}: READ BINARY @{offset}: {r.Status} {r.Status.Description}", r.Status);
            return r.Data;
        }
        // Offsets > 32767: READ BINARY with odd INS 'B1', offset in DO'54', data in DO'53' (ISO/IEC 7816-4 7.2.3).
        var offsetBytes = offset <= 0xFFFF ? new[] { (byte)(offset >> 8), (byte)offset } : new[] { (byte)(offset >> 16), (byte)(offset >> 8), (byte)offset };
        var le = Math.Min(length + 4, 256);
        r = Channel.Transmit(new CommandApdu(0x00, 0xB1, 0x00, 0x00, BerTlv.Encode(0x54, offsetBytes), le), $"READ BINARY (B1) {name} @{offset}");
        if (!r.Status.IsCompleted) throw new FileReadException($"{name}: READ BINARY B1 @{offset}: {r.Status} {r.Status.Description}", r.Status);
        var do53 = BerTlv.ParseSingle(r.Data);
        if (do53.Tag != 0x53) throw new FileReadException(T($"{name}: Antwort auf B1 enthält kein DO'53'.", $"{name}: response to B1 contains no DO'53'."));
        return do53.Value;
    }

    /// <summary>Total length (header + value) of the first BER-TLV object.</summary>
    public static int TotalTlvLength(ReadOnlySpan<byte> head)
    {
        var p = 1;
        if ((head[0] & 0x1F) == 0x1F)
            while ((head[p++] & 0x80) != 0) { }
        var first = head[p++];
        if (first < 0x80) return p + first;
        var count = first & 0x7F;
        if (count is 0 or > 3) throw new FormatException(T($"Längenfeld {first:X2} nicht unterstützt.", $"Length field {first:X2} not supported."));
        var len = 0;
        for (var i = 0; i < count; i++) len = (len << 8) | head[p++];
        return p + len;
    }
}
