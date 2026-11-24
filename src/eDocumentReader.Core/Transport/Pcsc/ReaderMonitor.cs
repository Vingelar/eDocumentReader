namespace eDocumentReader.Core.Transport.Pcsc;

public sealed record ReaderState(string Name, bool CardPresent, bool InUse, bool Mute, byte[] Atr);

/// <summary>
/// Watches reader attach/detach (PnP notification) and card insertion/removal via SCardGetStatusChange.
/// Events are raised on a background thread.
/// </summary>
public sealed class ReaderMonitor : IDisposable
{
    private const string PnpNotification = @"\\?PnP?\Notification";
    private readonly Thread thread;
    private nint context;
    private volatile bool stopping;

    public event Action<IReadOnlyList<ReaderState>>? Changed;
    public event Action<Exception>? Failed;

    public ReaderMonitor()
    {
        thread = new Thread(Run) { IsBackground = true, Name = "PC/SC ReaderMonitor" };
    }

    public void Start() => thread.Start();

    private void Run()
    {
        try
        {
            PcscException.Check(Native.SCardEstablishContext(Native.SCARD_SCOPE_USER, 0, 0, out context), "SCardEstablishContext");
            var known = new Dictionary<string, uint>();
            while (!stopping)
            {
                var readers = PcscTransport.ListReaders(context);
                var states = new Native.SCARD_READERSTATE[readers.Count + 1];
                for (var i = 0; i < readers.Count; i++)
                    states[i] = new Native.SCARD_READERSTATE { szReader = readers[i], dwCurrentState = known.GetValueOrDefault(readers[i]), rgbAtr = new byte[36] };
                states[^1] = new Native.SCARD_READERSTATE { szReader = PnpNotification, dwCurrentState = (uint)(readers.Count << 16), rgbAtr = new byte[36] };

                var code = Native.SCardGetStatusChangeW(context, Native.INFINITE, states, (uint)states.Length);
                if (stopping || code == Native.SCARD_E_CANCELLED) break;
                if (code is Native.SCARD_E_NO_SERVICE or Native.SCARD_E_SERVICE_STOPPED)
                {
                    // Windows stops the smart card service when the last reader is removed; re-establish.
                    Native.SCardReleaseContext(context);
                    Thread.Sleep(1000);
                    PcscException.Check(Native.SCardEstablishContext(Native.SCARD_SCOPE_USER, 0, 0, out context), "SCardEstablishContext");
                    known.Clear();
                    Publish([]);
                    continue;
                }
                if (code != Native.SCARD_E_TIMEOUT) PcscException.Check(code, "SCardGetStatusChange");

                var result = new List<ReaderState>();
                known.Clear();
                for (var i = 0; i < readers.Count; i++)
                {
                    var s = states[i];
                    known[readers[i]] = s.dwEventState & ~Native.SCARD_STATE_CHANGED;
                    result.Add(new ReaderState(readers[i],
                        (s.dwEventState & Native.SCARD_STATE_PRESENT) != 0,
                        (s.dwEventState & (Native.SCARD_STATE_INUSE | Native.SCARD_STATE_EXCLUSIVE)) != 0,
                        (s.dwEventState & Native.SCARD_STATE_MUTE) != 0,
                        s.rgbAtr[..(int)Math.Min(s.cbAtr, 36)]));
                }
                Publish(result);
            }
        }
        catch (Exception ex) when (!stopping)
        {
            Failed?.Invoke(ex);
        }
    }

    private void Publish(IReadOnlyList<ReaderState> states) => Changed?.Invoke(states);

    public void Dispose()
    {
        stopping = true;
        if (context != 0) Native.SCardCancel(context);
        if (thread.IsAlive) thread.Join(2000);
        if (context != 0) { Native.SCardReleaseContext(context); context = 0; }
    }
}
