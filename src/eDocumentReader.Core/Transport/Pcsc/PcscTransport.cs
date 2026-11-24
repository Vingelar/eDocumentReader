namespace eDocumentReader.Core.Transport.Pcsc;

public enum ShareMode { Exclusive = 1, Shared = 2 }

/// <summary>Windows PC/SC (winscard) transport. One connection; no automatic retries of card commands.</summary>
public sealed class PcscTransport : ICardTransport
{
    private nint context;
    private nint card;
    private uint protocol;
    private readonly ShareMode shareMode;

    public string Name { get; }
    public byte[] Atr { get; private set; } = [];
    public string Protocol => protocol switch { Native.SCARD_PROTOCOL_T0 => "T=0", Native.SCARD_PROTOCOL_T1 => "T=1", Native.SCARD_PROTOCOL_RAW => "RAW", _ => $"0x{protocol:X}" };
    public CardInterface Interface { get; private set; }

    public PcscTransport(string reader, ShareMode shareMode = ShareMode.Exclusive)
    {
        Name = reader;
        this.shareMode = shareMode;
        PcscException.Check(Native.SCardEstablishContext(Native.SCARD_SCOPE_USER, 0, 0, out context), "SCardEstablishContext");
        try
        {
            PcscException.Check(Native.SCardConnectW(context, reader, (uint)shareMode, Native.SCARD_PROTOCOL_T0 | Native.SCARD_PROTOCOL_T1, out card, out protocol), "SCardConnect");
            RefreshStatus();
        }
        catch
        {
            Native.SCardReleaseContext(context);
            context = 0;
            throw;
        }
    }

    private void RefreshStatus()
    {
        uint nameLength = 0;
        var atr = new byte[36];
        var atrLength = (uint)atr.Length;
        var code = Native.SCardStatusW(card, null, ref nameLength, out _, out protocol, atr, ref atrLength);
        if (code == unchecked((int)0x80100068))
        {
            // SCARD_W_RESET_CARD: another application reset the card; acknowledge via SCardReconnect (no further reset).
            PcscException.Check(Native.SCardReconnect(card, (uint)shareMode, Native.SCARD_PROTOCOL_T0 | Native.SCARD_PROTOCOL_T1, Native.SCARD_LEAVE_CARD, out protocol), "SCardReconnect");
            atrLength = (uint)atr.Length;
            nameLength = 0;
            code = Native.SCardStatusW(card, null, ref nameLength, out _, out protocol, atr, ref atrLength);
        }
        PcscException.Check(code, "SCardStatus");
        Atr = atr[..(int)atrLength];
        Interface = new AtrInfo(Atr).IsPcscContactless ? CardInterface.Contactless : CardInterface.Contact;
    }

    public byte[] Transmit(byte[] command)
    {
        ObjectDisposedException.ThrowIf(card == 0, this);
        var pci = new Native.SCARD_IO_REQUEST { dwProtocol = protocol, cbPciLength = 8 };
        var reply = new byte[65536 + 2];
        var size = (uint)reply.Length;
        PcscException.Check(Native.SCardTransmit(card, ref pci, command, (uint)command.Length, 0, reply, ref size), "SCardTransmit");
        return reply[..(int)size];
    }

    public byte[] Control(uint controlCode, byte[] input)
    {
        ObjectDisposedException.ThrowIf(card == 0, this);
        var output = new byte[4096];
        var code = Native.SCardControl(card, controlCode, input, (uint)input.Length, output, (uint)output.Length, out var returned);
        if (code is 1 or 0x32) throw new NotSupportedException($"SCardControl 0x{controlCode:X8} wird vom Leser nicht unterstützt.");
        PcscException.Check(code, $"SCardControl 0x{controlCode:X8}");
        return output[..(int)returned];
    }

    public void Reset(bool cold)
    {
        ObjectDisposedException.ThrowIf(card == 0, this);
        PcscException.Check(Native.SCardReconnect(card, (uint)shareMode, Native.SCARD_PROTOCOL_T0 | Native.SCARD_PROTOCOL_T1,
            cold ? Native.SCARD_UNPOWER_CARD : Native.SCARD_RESET_CARD, out protocol), "SCardReconnect");
        RefreshStatus();
    }

    public void Dispose()
    {
        if (card != 0) { Native.SCardDisconnect(card, Native.SCARD_RESET_CARD); card = 0; }
        if (context != 0) { Native.SCardReleaseContext(context); context = 0; }
    }

    public static IReadOnlyList<string> ListReaders()
    {
        PcscException.Check(Native.SCardEstablishContext(Native.SCARD_SCOPE_USER, 0, 0, out var ctx), "SCardEstablishContext");
        try { return ListReaders(ctx); }
        finally { Native.SCardReleaseContext(ctx); }
    }

    internal static IReadOnlyList<string> ListReaders(nint ctx)
    {
        uint count = 0;
        var code = Native.SCardListReadersW(ctx, null, null, ref count);
        if (code == Native.SCARD_E_NO_READERS_AVAILABLE) return [];
        PcscException.Check(code, "SCardListReaders");
        var buffer = new char[count];
        code = Native.SCardListReadersW(ctx, null, buffer, ref count);
        if (code == Native.SCARD_E_NO_READERS_AVAILABLE) return [];
        PcscException.Check(code, "SCardListReaders");
        return new string(buffer).Split('\0', StringSplitOptions.RemoveEmptyEntries);
    }
}
