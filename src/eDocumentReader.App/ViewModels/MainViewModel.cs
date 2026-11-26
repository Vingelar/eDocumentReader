using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using eDocumentReader.Core.Apdu;
using eDocumentReader.Core.Logging;
using eDocumentReader.Core.Transport;
using eDocumentReader.Core.Transport.Pcsc;
using eDocumentReader.Core.Util;

namespace eDocumentReader.App.ViewModels;

public sealed partial class ReaderItem : ObservableObject
{
    public ReaderItem(string name) => Name = name;
    public string Name { get; }
    [ObservableProperty] private bool cardPresent;
    [ObservableProperty] private string atr = string.Empty;
    public string Display => Name;
}

/// <summary>Display level of one log category. The logger always records everything (Trace); this only filters the view.</summary>
public sealed partial class LogLevelSetting : ObservableObject
{
    private readonly Action changed;
    public LogLevelSetting(LogCategory category, LogLevel level, Action changed)
    {
        Category = category;
        this.level = level;
        this.changed = changed;
    }
    public LogCategory Category { get; }
    [ObservableProperty] private LogLevel level;
    partial void OnLevelChanged(LogLevel value) => changed();
    public bool Shows(LogEntry e) => e.Level != LogLevel.Off && e.Level <= Level;
}

public sealed partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly Dispatcher dispatcher = Application.Current.Dispatcher;
    private readonly ReaderMonitor monitor = new();
    private PcscTransport? transport;

    private const int MaxDisplayedLogEntries = 20000;
    /// <summary>Everything recorded (Trace for all categories), in the order of the log sink; the view shows a filtered part.</summary>
    private readonly List<LogEntry> allLogEntries = [];
    private readonly Dictionary<LogCategory, LogLevelSetting> logFilter = [];

    public Logger Logger { get; } = new(LogLevel.Trace);
    public MemoryLogSink LogSink { get; } = new();
    public ObservableCollection<ReaderItem> Readers { get; } = [];
    [ObservableProperty] private ObservableCollection<LogEntry> logEntries = [];
    public ObservableCollection<LogLevelSetting> LogLevels { get; } = [];
    public IReadOnlyList<LogLevel> AvailableLevels { get; } = Enum.GetValues<LogLevel>();
    public CardChannel? Channel { get; private set; }

    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(ConnectCommand), nameof(ReadDocumentCommand), nameof(ReadEvrcCommand))] private ReaderItem? selectedReader;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(ConnectCommand), nameof(DisconnectCommand), nameof(SendApduCommand))] private bool isConnected;
    [ObservableProperty] private string statusText = T("Bereit", "Ready");
    [ObservableProperty] private string cardInfo = string.Empty;
    [ObservableProperty] private string apduInput = "00 A4 04 0C 07 A0 00 00 02 47 10 01";
    [ObservableProperty] private string apduOutput = string.Empty;
    [ObservableProperty] private bool exclusiveMode = true;
    [ObservableProperty] private bool autoGetResponse = true;

    public MainViewModel()
    {
        Logger.AddSink(LogSink);
        foreach (var c in Enum.GetValues<LogCategory>())
        {
            var setting = new LogLevelSetting(c, LogLevel.Detail, RefilterLog);
            logFilter[c] = setting;
            LogLevels.Add(setting);
        }
        LogSink.EntryAdded += e => dispatcher.BeginInvoke(() =>
        {
            allLogEntries.Add(e);
            if (!IsLogVisible(e)) return;
            LogEntries.Add(e);
            if (LogEntries.Count > MaxDisplayedLogEntries) LogEntries.RemoveAt(0);
        });
        monitor.Changed += states => dispatcher.BeginInvoke(() => UpdateReaders(states));
        monitor.Failed += ex => dispatcher.BeginInvoke(() => Logger.Error(LogCategory.Reader, T($"Lesermonitor: {ex.Message}", $"Reader monitor: {ex.Message}")));
        monitor.Start();
        Logger.Info(LogCategory.Application, T("eDocumentReader gestartet", "eDocumentReader started"));
    }

    private void UpdateReaders(IReadOnlyList<ReaderState> states)
    {
        foreach (var gone in Readers.Where(r => states.All(s => s.Name != r.Name)).ToList())
        {
            Readers.Remove(gone);
            Logger.Info(LogCategory.Reader, T($"Leser entfernt: {gone.Name}", $"Reader removed: {gone.Name}"));
        }
        foreach (var s in states)
        {
            var item = Readers.FirstOrDefault(r => r.Name == s.Name);
            if (item == null)
            {
                item = new ReaderItem(s.Name);
                Readers.Add(item);
                Logger.Info(LogCategory.Reader, T($"Leser gefunden: {s.Name}", $"Reader found: {s.Name}"));
            }
            if (item.CardPresent != s.CardPresent)
                Logger.Info(LogCategory.Reader, s.CardPresent ? T($"Karte aufgelegt/gesteckt: {s.Name}", $"Card presented/inserted: {s.Name}") : T($"Karte entfernt: {s.Name}", $"Card removed: {s.Name}"), s.CardPresent ? s.Atr : null);
            item.CardPresent = s.CardPresent;
            item.Atr = Hex.Of(s.Atr);
            // While reading, the running inspection fails on its own; disposing the handle under it would hide the real error.
            if (!s.CardPresent && IsConnected && !IsReading && transport?.Name == s.Name) Disconnect();
        }
        SelectedReader ??= Readers.FirstOrDefault(r => r.CardPresent) ?? Readers.FirstOrDefault();
    }

    /// <summary>Selecting another reader closes the connection to the current one.</summary>
    partial void OnSelectedReaderChanged(ReaderItem? value)
    {
        if (IsConnected && !IsReading && transport != null && transport.Name != value?.Name) Disconnect();
    }

    private bool IsLogVisible(LogEntry e) => logFilter.TryGetValue(e.Category, out var f) && f.Shows(e);

    /// <summary>Rebuilds the log view from everything recorded, with the current display levels.</summary>
    private void RefilterLog() =>
        LogEntries = new ObservableCollection<LogEntry>(allLogEntries.Where(IsLogVisible).TakeLast(MaxDisplayedLogEntries));

    /// <summary>First displayed log entry at or after a log sink index (the start of a step), or null.</summary>
    public LogEntry? FindLogEntry(int anchor)
    {
        if (anchor < 0) return null;
        var shown = new HashSet<LogEntry>(LogEntries, ReferenceEqualityComparer.Instance);
        for (var i = anchor; i < allLogEntries.Count; i++)
            if (shown.Contains(allLogEntries[i])) return allLogEntries[i];
        return null;
    }

    private bool CanConnect() => SelectedReader != null && !IsConnected && !IsReading;

    private bool CanDisconnect() => IsConnected && !IsReading;

    [RelayCommand(CanExecute = nameof(CanConnect))]
    private void Connect()
    {
        if (SelectedReader == null) return;
        try
        {
            transport = new PcscTransport(SelectedReader.Name, ExclusiveMode ? ShareMode.Exclusive : ShareMode.Shared);
            Channel = new CardChannel(transport, Logger, new ChannelOptions { AutoGetResponse = AutoGetResponse, AutoCorrectLe = AutoGetResponse });
            IsConnected = true;
            Logger.Info(LogCategory.Reader, T($"Verbunden mit {transport.Name}, Protokoll {transport.Protocol}, Schnittstelle {transport.Interface}", $"Connected to {transport.Name}, protocol {transport.Protocol}, interface {transport.Interface}"), transport.Atr);
            CardInfo = BuildCardInfo(transport, Channel);
            StatusText = T($"Verbunden: {transport.Name} ({transport.Interface}, {transport.Protocol})", $"Connected: {transport.Name} ({transport.Interface}, {transport.Protocol})");
        }
        catch (Exception ex)
        {
            transport?.Dispose();
            transport = null;
            Logger.Error(LogCategory.Reader, T($"Verbindung fehlgeschlagen: {ex.Message}", $"Connection failed: {ex.Message}"));
            StatusText = ex.Message;
        }
    }

    private static string BuildCardInfo(PcscTransport t, CardChannel channel)
    {
        var sb = new StringBuilder();
        var atr = new AtrInfo(t.Atr);
        sb.AppendLine(T($"Leser: {t.Name}", $"Reader: {t.Name}"));
        sb.AppendLine(T($"Protokoll: {t.Protocol}   Schnittstelle: {(t.Interface == CardInterface.Contactless ? "kontaktlos (ISO/IEC 14443)" : "kontaktbehaftet (ISO/IEC 7816-3)")}", $"Protocol: {t.Protocol}   Interface: {(t.Interface == CardInterface.Contactless ? "contactless (ISO/IEC 14443)" : "contact (ISO/IEC 7816-3)")}"));
        sb.AppendLine();
        sb.AppendLine(atr.Describe());
        if (t.Interface == CardInterface.Contactless)
        {
            var uid = channel.GetContactlessData(historicalBytes: false);
            sb.AppendLine(T($"UID/PUPI: {(uid == null ? "nicht verfügbar" : Hex.Of(uid))}{(uid is { Length: 4 } && uid[0] == 0x08 ? " (zufällige UID, ISO/IEC 14443-3)" : string.Empty)}", $"UID/PUPI: {(uid == null ? "not available" : Hex.Of(uid))}{(uid is { Length: 4 } && uid[0] == 0x08 ? " (random UID, ISO/IEC 14443-3)" : string.Empty)}"));
            var hist = channel.GetContactlessData(historicalBytes: true);
            if (hist != null) sb.AppendLine(T($"ATS hist. Bytes (GET DATA P1=01): {Hex.Of(hist)}", $"ATS historical bytes (GET DATA P1=01): {Hex.Of(hist)}"));
            sb.AppendLine();
        }
        var features = ReaderFeatures.Query(t);
        sb.AppendLine("PC/SC Part 10 Features:");
        if (features.ControlCodes.Count == 0) sb.AppendLine(T("  keine (Klasse-1-Leser oder Treiber ohne Part 10)", "  none (class 1 reader or driver without Part 10)"));
        foreach (var (tag, code) in features.ControlCodes) sb.AppendLine($"  {ReaderFeatures.FeatureName(tag)} → 0x{code:X8}");
        if (features.MaxApduDataSize is { } max) sb.AppendLine(T($"  dwMaxAPDUDataSize: {max} ({(max == 0 ? "nur kurze APDUs" : "Extended Length bis " + max + " Bytes")})", $"  dwMaxAPDUDataSize: {max} ({(max == 0 ? "short APDUs only" : "extended length up to " + max + " bytes")})"));
        if (features.FirmwareId is { } fw) sb.AppendLine($"  Firmware: {fw}");
        if (features.UsbVendorId is { } vid) sb.AppendLine($"  USB VID/PID: {vid:X4}/{features.UsbProductId:X4}");
        sb.AppendLine(T($"  PACE im Leser: {(features.SupportsPace ? "ja" : "nein")}", $"  PACE in the reader: {(features.SupportsPace ? "yes" : "no")}"));
        return sb.ToString();
    }

    [RelayCommand(CanExecute = nameof(CanDisconnect))]
    private void Disconnect()
    {
        transport?.Dispose();
        transport = null;
        Channel = null;
        IsConnected = false;
        StatusText = T("Getrennt", "Disconnected");
        Logger.Info(LogCategory.Reader, T("Verbindung getrennt", "Connection closed"));
    }

    [RelayCommand]
    private void Reset()
    {
        if (transport == null) return;
        try
        {
            transport.Reset(cold: false);
            Logger.Info(LogCategory.Reader, T("Warm-Reset durchgeführt", "Warm reset performed"), transport.Atr);
        }
        catch (Exception ex) { Logger.Error(LogCategory.Reader, T($"Reset fehlgeschlagen: {ex.Message}", $"Reset failed: {ex.Message}")); }
    }

    [RelayCommand(CanExecute = nameof(IsConnected))]
    private void SendApdu()
    {
        if (Channel == null) return;
        try
        {
            var bytes = Hex.Parse(ApduInput);
            var command = CommandApdu.Parse(bytes);
            Channel.Options.AutoGetResponse = AutoGetResponse;
            Channel.Options.AutoCorrectLe = AutoGetResponse;
            var response = Channel.Transmit(command);
            ApduOutput = $">> {Hex.Of(bytes)}{Environment.NewLine}<< {response}{Environment.NewLine}   {response.Status.Description}{Environment.NewLine}{Environment.NewLine}" + ApduOutput;
        }
        catch (Exception ex)
        {
            ApduOutput = T($"Fehler: {ex.Message}{Environment.NewLine}", $"Error: {ex.Message}{Environment.NewLine}") + ApduOutput;
        }
    }

    [RelayCommand]
    private void ClearLog()
    {
        LogSink.Clear();
        allLogEntries.Clear();
        LogEntries.Clear();
    }

    [RelayCommand]
    private void SaveLog()
    {
        var dlg = new Microsoft.Win32.SaveFileDialog { Filter = T("Textdatei|*.txt", "Text file|*.txt"), FileName = $"eDocumentReader_{DateTime.Now:yyyyMMdd_HHmmss}.log.txt" };
        if (dlg.ShowDialog() == true) File.WriteAllText(dlg.FileName, LogSink.ToText(), Encoding.UTF8);
    }

    public void Dispose()
    {
        monitor.Dispose();
        transport?.Dispose();
    }
}
