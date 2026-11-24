using System.Buffers.Binary;

namespace eDocumentReader.Core.Transport.Pcsc;

/// <summary>Reader features according to PC/SC Part 10 v2.02.09 (2.2 GET_FEATURE_REQUEST, 2.6.14 TLV properties).</summary>
public sealed class ReaderFeatures
{
    public const byte FeatureGetTlvProperties = 0x12;
    public const byte FeatureCcidEscCommand = 0x13;
    /// <summary>PC/SC Part 10 AMD1: PACE execution in the reader.</summary>
    public const byte FeatureExecutePace = 0x20;

    public static uint GetFeatureRequestCode => Native.CtlCode(3400);

    public IReadOnlyDictionary<byte, uint> ControlCodes { get; }
    public IReadOnlyDictionary<byte, byte[]> TlvProperties { get; }

    private ReaderFeatures(Dictionary<byte, uint> codes, Dictionary<byte, byte[]> props)
    {
        ControlCodes = codes;
        TlvProperties = props;
    }

    public bool SupportsPace => ControlCodes.ContainsKey(FeatureExecutePace);

    /// <summary>dwMaxAPDUDataSize (tag 0x0A): 0 = short APDUs only; null = not reported.</summary>
    public int? MaxApduDataSize => TlvProperties.TryGetValue(0x0A, out var v) && v.Length == 4 ? (int)BinaryPrimitives.ReadUInt32LittleEndian(v) : null;
    public string? FirmwareId => TlvProperties.TryGetValue(0x08, out var v) ? System.Text.Encoding.UTF8.GetString(v) : null;
    public ushort? UsbVendorId => TlvProperties.TryGetValue(0x0B, out var v) && v.Length == 2 ? BinaryPrimitives.ReadUInt16LittleEndian(v) : null;
    public ushort? UsbProductId => TlvProperties.TryGetValue(0x0C, out var v) && v.Length == 2 ? BinaryPrimitives.ReadUInt16LittleEndian(v) : null;

    public static ReaderFeatures Query(ICardTransport transport)
    {
        var codes = new Dictionary<byte, uint>();
        var props = new Dictionary<byte, byte[]>();
        try
        {
            var raw = transport.Control(GetFeatureRequestCode, []);
            for (var p = 0; p + 2 <= raw.Length;)
            {
                var tag = raw[p];
                var len = raw[p + 1];
                if (p + 2 + len > raw.Length) break;
                // Part 10 2.2: control code value is big-endian.
                if (len == 4) codes[tag] = BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(p + 2, 4));
                p += 2 + len;
            }
            if (codes.TryGetValue(FeatureGetTlvProperties, out var tlvCode))
            {
                var t = transport.Control(tlvCode, []);
                for (var p = 0; p + 2 <= t.Length;)
                {
                    var tag = t[p];
                    var len = t[p + 1];
                    if (p + 2 + len > t.Length) break;
                    props[tag] = t[(p + 2)..(p + 2 + len)];
                    p += 2 + len;
                }
            }
        }
        catch (Exception ex) when (ex is NotSupportedException or PcscException)
        {
            // Class 1 readers / drivers without Part 10 support.
        }
        return new ReaderFeatures(codes, props);
    }

    public static string FeatureName(byte tag) => tag switch
    {
        0x01 => "VERIFY_PIN_START", 0x02 => "VERIFY_PIN_FINISH", 0x03 => "MODIFY_PIN_START", 0x04 => "MODIFY_PIN_FINISH",
        0x05 => "GET_KEY_PRESSED", 0x06 => "VERIFY_PIN_DIRECT", 0x07 => "MODIFY_PIN_DIRECT", 0x08 => "MCT_READER_DIRECT",
        0x09 => "MCT_UNIVERSAL", 0x0A => "IFD_PIN_PROPERTIES", 0x0B => "ABORT", 0x0C => "SET_SPE_MESSAGE",
        0x0D => "VERIFY_PIN_DIRECT_APP_ID", 0x0E => "MODIFY_PIN_DIRECT_APP_ID", 0x0F => "WRITE_DISPLAY", 0x10 => "GET_KEY",
        0x11 => "IFD_DISPLAY_PROPERTIES", 0x12 => "GET_TLV_PROPERTIES", 0x13 => "CCID_ESC_COMMAND", 0x20 => "EXECUTE_PACE",
        _ => $"Feature 0x{tag:X2}",
    };
}
