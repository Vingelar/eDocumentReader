using System.Collections.Concurrent;
using System.Text;
using eDocumentReader.Core.Util;

namespace eDocumentReader.Core.Logging;

public enum LogCategory
{
    Reader,
    Apdu,
    SecureMessaging,
    Crypto,
    Protocol,
    Parser,
    Pki,
    Test,
    Application,
}

/// <summary>Ordered by increasing verbosity; a category threshold of <see cref="Detail"/> includes Error..Detail.</summary>
public enum LogLevel { Off = 0, Error = 1, Warning = 2, Info = 3, Detail = 4, Trace = 5 }

public enum ApduDirection { None, Command, Response }

public sealed record LogEntry(
    DateTimeOffset Timestamp,
    LogCategory Category,
    LogLevel Level,
    string Message,
    byte[]? Data = null,
    ApduDirection Direction = ApduDirection.None,
    TimeSpan? Duration = null,
    string? Reference = null)
{
    public string Format(bool includeData = true)
    {
        var sb = new StringBuilder();
        sb.Append(Timestamp.ToString("HH:mm:ss.fff")).Append(' ')
          .Append(Level.ToString().ToUpperInvariant()[0]).Append(' ')
          .Append('[').Append(Category).Append("] ");
        if (Direction == ApduDirection.Command) sb.Append(">> ");
        else if (Direction == ApduDirection.Response) sb.Append("<< ");
        sb.Append(Message);
        if (Duration is { } d) sb.Append($" ({d.TotalMilliseconds:0.0} ms)");
        if (Reference != null) sb.Append(" {").Append(Reference).Append('}');
        if (includeData && Data is { Length: > 0 }) sb.Append(": ").Append(Hex.Of(Data));
        return sb.ToString();
    }
}

public interface ILogSink
{
    void Write(LogEntry entry);
}

/// <summary>Central logger with per-category verbosity thresholds (adjustable at runtime from the GUI).</summary>
public sealed class Logger
{
    private readonly ConcurrentDictionary<LogCategory, LogLevel> thresholds = new();
    private readonly List<ILogSink> sinks = [];
    private readonly Lock gate = new();

    public static Logger Null { get; } = new(LogLevel.Off);

    public Logger(LogLevel defaultLevel = LogLevel.Detail)
    {
        foreach (var c in Enum.GetValues<LogCategory>()) thresholds[c] = defaultLevel;
    }

    public LogLevel this[LogCategory category]
    {
        get => thresholds[category];
        set => thresholds[category] = value;
    }

    public void AddSink(ILogSink sink) { lock (gate) sinks.Add(sink); }
    public void RemoveSink(ILogSink sink) { lock (gate) sinks.Remove(sink); }

    public bool IsEnabled(LogCategory category, LogLevel level) => level != LogLevel.Off && level <= thresholds[category];

    public void Write(LogEntry entry)
    {
        if (!IsEnabled(entry.Category, entry.Level)) return;
        ILogSink[] snapshot;
        lock (gate) snapshot = [.. sinks];
        foreach (var s in snapshot) s.Write(entry);
    }

    public void Log(LogCategory category, LogLevel level, string message, byte[]? data = null, string? reference = null)
        => Write(new LogEntry(DateTimeOffset.Now, category, level, message, data, Reference: reference));

    public void Error(LogCategory c, string m, byte[]? d = null, string? reference = null) => Log(c, LogLevel.Error, m, d, reference);
    public void Warning(LogCategory c, string m, byte[]? d = null, string? reference = null) => Log(c, LogLevel.Warning, m, d, reference);
    public void Info(LogCategory c, string m, byte[]? d = null, string? reference = null) => Log(c, LogLevel.Info, m, d, reference);
    public void Detail(LogCategory c, string m, byte[]? d = null, string? reference = null) => Log(c, LogLevel.Detail, m, d, reference);
    public void Trace(LogCategory c, string m, byte[]? d = null, string? reference = null) => Log(c, LogLevel.Trace, m, d, reference);
}

/// <summary>Keeps all entries in memory (for display, export and report generation).</summary>
public sealed class MemoryLogSink : ILogSink
{
    private readonly List<LogEntry> entries = [];
    private readonly Lock gate = new();

    public event Action<LogEntry>? EntryAdded;

    public void Write(LogEntry entry)
    {
        lock (gate) entries.Add(entry);
        EntryAdded?.Invoke(entry);
    }

    public IReadOnlyList<LogEntry> Snapshot() { lock (gate) return [.. entries]; }
    public void Clear() { lock (gate) entries.Clear(); }

    public string ToText() => string.Join(Environment.NewLine, Snapshot().Select(e => e.Format()));
}

public sealed class FileLogSink(string path) : ILogSink, IDisposable
{
    private readonly StreamWriter writer = new(path, append: false, Encoding.UTF8) { AutoFlush = true };
    private readonly Lock gate = new();

    public void Write(LogEntry entry) { lock (gate) writer.WriteLine(entry.Format()); }
    public void Dispose() => writer.Dispose();
}
