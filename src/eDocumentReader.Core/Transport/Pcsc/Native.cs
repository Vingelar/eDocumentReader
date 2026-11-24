using System.Runtime.InteropServices;

namespace eDocumentReader.Core.Transport.Pcsc;

internal static class Native
{
    public const uint SCARD_SCOPE_USER = 0;
    public const uint SCARD_SHARE_EXCLUSIVE = 1;
    public const uint SCARD_SHARE_SHARED = 2;
    public const uint SCARD_SHARE_DIRECT = 3;
    public const uint SCARD_PROTOCOL_T0 = 1;
    public const uint SCARD_PROTOCOL_T1 = 2;
    public const uint SCARD_PROTOCOL_RAW = 0x10000;
    public const uint SCARD_LEAVE_CARD = 0;
    public const uint SCARD_RESET_CARD = 1;
    public const uint SCARD_UNPOWER_CARD = 2;
    public const uint INFINITE = 0xFFFFFFFF;

    public const uint SCARD_STATE_UNAWARE = 0x0000;
    public const uint SCARD_STATE_IGNORE = 0x0001;
    public const uint SCARD_STATE_CHANGED = 0x0002;
    public const uint SCARD_STATE_UNKNOWN = 0x0004;
    public const uint SCARD_STATE_UNAVAILABLE = 0x0008;
    public const uint SCARD_STATE_EMPTY = 0x0010;
    public const uint SCARD_STATE_PRESENT = 0x0020;
    public const uint SCARD_STATE_EXCLUSIVE = 0x0080;
    public const uint SCARD_STATE_INUSE = 0x0100;
    public const uint SCARD_STATE_MUTE = 0x0200;

    public const int SCARD_S_SUCCESS = 0;
    public const int SCARD_E_CANCELLED = unchecked((int)0x80100002);
    public const int SCARD_E_TIMEOUT = unchecked((int)0x8010000A);
    public const int SCARD_E_NO_READERS_AVAILABLE = unchecked((int)0x8010002E);
    public const int SCARD_E_NO_SERVICE = unchecked((int)0x8010001D);
    public const int SCARD_E_SERVICE_STOPPED = unchecked((int)0x8010001E);

    /// <summary>SCARD_CTL_CODE as defined for Windows (winsmcrd.h).</summary>
    public static uint CtlCode(uint code) => (0x31u << 16) | (code << 2);

    [StructLayout(LayoutKind.Sequential)]
    public struct SCARD_IO_REQUEST { public uint dwProtocol; public uint cbPciLength; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SCARD_READERSTATE
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string szReader;
        public nint pvUserData;
        public uint dwCurrentState;
        public uint dwEventState;
        public uint cbAtr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)] public byte[] rgbAtr;
    }

    [DllImport("winscard.dll")] public static extern int SCardEstablishContext(uint scope, nint r1, nint r2, out nint context);
    [DllImport("winscard.dll")] public static extern int SCardReleaseContext(nint context);
    [DllImport("winscard.dll")] public static extern int SCardCancel(nint context);
    [DllImport("winscard.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int SCardListReadersW(nint context, string? groups, [Out] char[]? readers, ref uint count);
    [DllImport("winscard.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int SCardConnectW(nint context, string reader, uint share, uint protocols, out nint card, out uint activeProtocol);
    [DllImport("winscard.dll")] public static extern int SCardReconnect(nint card, uint share, uint protocols, uint initialization, out uint activeProtocol);
    [DllImport("winscard.dll")] public static extern int SCardDisconnect(nint card, uint disposition);
    [DllImport("winscard.dll")] public static extern int SCardBeginTransaction(nint card);
    [DllImport("winscard.dll")] public static extern int SCardEndTransaction(nint card, uint disposition);
    [DllImport("winscard.dll")]
    public static extern int SCardTransmit(nint card, ref SCARD_IO_REQUEST sendPci, byte[] send, uint sendLength, nint recvPci, [Out] byte[] recv, ref uint recvLength);
    [DllImport("winscard.dll")]
    public static extern int SCardControl(nint card, uint controlCode, byte[] inBuffer, uint inSize, [Out] byte[] outBuffer, uint outSize, out uint returned);
    [DllImport("winscard.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int SCardStatusW(nint card, [Out] char[]? readerNames, ref uint readerLength, out uint state, out uint protocol, [Out] byte[] atr, ref uint atrLength);
    [DllImport("winscard.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int SCardGetStatusChangeW(nint context, uint timeout, [In, Out] SCARD_READERSTATE[] states, uint count);
    [DllImport("winscard.dll")]
    public static extern int SCardGetAttrib(nint card, uint attrId, [Out] byte[]? attr, ref uint attrLength);
}

public sealed class PcscException(int code, string operation)
    : InvalidOperationException($"{operation}: {Describe(code)} (0x{unchecked((uint)code):X8})")
{
    public int Code { get; } = code;

    public static string Describe(int code) => unchecked((uint)code) switch
    {
        0x80100002 => "Abgebrochen",
        0x80100004 => "Ungültiger Parameter",
        0x80100008 => "Puffer zu klein",
        0x80100009 => "Unbekannter Leser",
        0x8010000A => "Zeitüberschreitung",
        0x8010000B => "Karte/Leser wird von anderer Anwendung verwendet",
        0x8010000C => "Keine Karte im Leser",
        0x8010000F => "Protokoll nicht unterstützt",
        0x80100016 => "Keine Transaktion aktiv",
        0x80100017 => "Leser nicht verfügbar",
        0x8010001D => "Smartcard-Dienst läuft nicht",
        0x8010001E => "Smartcard-Dienst wurde beendet",
        0x8010002E => "Keine Leser verfügbar",
        0x80100066 => "Karte antwortet nicht",
        0x80100067 => "Karte nicht versorgt",
        0x80100068 => "Karte wurde zurückgesetzt",
        0x80100069 => "Karte wurde entfernt",
        0x80100001 => "Interner Fehler",
        0x80100013 => "Kommunikationsfehler",
        0x80100018 => "Funktion nicht unterstützt",
        0x00000001 => "Funktion nicht unterstützt (ERROR_INVALID_FUNCTION)",
        0x00000032 => "Nicht unterstützt (ERROR_NOT_SUPPORTED)",
        _ => "PC/SC-Fehler",
    };

    internal static void Check(int code, string operation)
    {
        if (code != Native.SCARD_S_SUCCESS) throw new PcscException(code, operation);
    }
}
