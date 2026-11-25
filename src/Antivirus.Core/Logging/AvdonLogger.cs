namespace AntivirusOS.Core.Logging;

public enum LogLevel { Info, Warning, Error }

public sealed record LogEntry(DateTime Timestamp, LogLevel Level, string Component, string Message);

/// <summary>
/// Lightweight file-based logger with daily rotation and 7-day retention.
/// Thread-safe via a dedicated background channel.
/// </summary>
public sealed class AvdonLogger : IDisposable
{
    private readonly string _logDir;
    private readonly System.Threading.Channels.Channel<LogEntry> _channel;
    private readonly Thread _worker;
    private bool _disposed;

    public static AvdonLogger Instance { get; private set; } = new(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "AVDON", "logs"));

    public AvdonLogger(string logDirectory)
    {
        _logDir = logDirectory;
        Directory.CreateDirectory(_logDir);
        _channel = System.Threading.Channels.Channel.CreateBounded<LogEntry>(
            new System.Threading.Channels.BoundedChannelOptions(4096)
            {
                FullMode = System.Threading.Channels.BoundedChannelFullMode.DropOldest,
                SingleReader = true,
            });

        _worker = new Thread(WriteLoop) { IsBackground = true, Name = "AvdonLogger" };
        _worker.Start();
    }

    public void Log(LogLevel level, string component, string message)
    {
        if (_disposed) return;
        _channel.Writer.TryWrite(new LogEntry(DateTime.Now, level, component, message));
    }

    public void Info(string component, string message)    => Log(LogLevel.Info,    component, message);
    public void Warn(string component, string message)    => Log(LogLevel.Warning, component, message);
    public void Error(string component, string message)   => Log(LogLevel.Error,   component, message);

    public IReadOnlyList<LogEntry> ReadTodaysEntries(int maxLines = 500)
    {
        var path = LogFilePath(DateTime.Today);
        if (!File.Exists(path)) return Array.Empty<LogEntry>();
        var entries = new List<LogEntry>();
        try
        {
            foreach (var line in File.ReadLines(path).TakeLast(maxLines))
            {
                var e = ParseLine(line);
                if (e != null) entries.Add(e);
            }
        }
        catch { }
        return entries;
    }

    private string LogFilePath(DateTime date) =>
        Path.Combine(_logDir, $"avdon-{date:yyyy-MM-dd}.log");

    private void WriteLoop()
    {
        var reader = _channel.Reader;
        while (reader.WaitToReadAsync().AsTask().GetAwaiter().GetResult())
        {
            while (reader.TryRead(out var entry))
            {
                try
                {
                    var path = LogFilePath(entry.Timestamp.Date);
                    var line = $"{entry.Timestamp:HH:mm:ss.fff} [{entry.Level,-7}] [{entry.Component}] {entry.Message}";
                    File.AppendAllText(path, line + Environment.NewLine);
                }
                catch { }
            }

            PurgeOldLogs();
        }
    }

    private void PurgeOldLogs()
    {
        try
        {
            var cutoff = DateTime.Today.AddDays(-7);
            foreach (var file in Directory.EnumerateFiles(_logDir, "avdon-*.log"))
            {
                var name = Path.GetFileNameWithoutExtension(file);
                if (name.Length >= 15 &&
                    DateTime.TryParse(name[6..], out var d) && d < cutoff)
                    File.Delete(file);
            }
        }
        catch { }
    }

    private static LogEntry? ParseLine(string line)
    {
        // Format: HH:mm:ss.fff [Level  ] [Component] Message
        try
        {
            if (line.Length < 25) return null;
            var time = TimeOnly.Parse(line[..12]);
            var lvlEnd  = line.IndexOf(']', 14);
            var compEnd = line.IndexOf(']', lvlEnd + 2);
            if (lvlEnd < 0 || compEnd < 0) return null;
            var lvlStr  = line[15..lvlEnd].Trim();
            var comp    = line[(lvlEnd + 3)..compEnd];
            var msg     = line[(compEnd + 2)..];
            var level   = lvlStr switch { "Warning" => LogLevel.Warning, "Error" => LogLevel.Error, _ => LogLevel.Info };
            return new LogEntry(DateTime.Today.Add(time.ToTimeSpan()), level, comp, msg);
        }
        catch { return null; }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _channel.Writer.TryComplete();
    }
}
