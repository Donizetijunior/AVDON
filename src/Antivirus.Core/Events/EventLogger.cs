using Microsoft.Data.Sqlite;

namespace AntivirusOS.Core.Events;

public enum EventKind
{
    ThreatDetected,
    FileQuarantined,
    ScanCompleted,
    ScanStarted,
    RealTimeEnabled,
    RealTimeDisabled,
    SignaturesUpdated,
    RansomwareAlert,
    ProcessThreat,
}

public sealed record AvdonEvent(
    int    Id,
    DateTime Timestamp,
    EventKind Kind,
    string Summary,
    string? Detail);

public sealed class EventLogger : IDisposable
{
    private readonly SqliteConnection _db;
    private bool _disposed;

    public EventLogger(string connectionString)
    {
        _db = new SqliteConnection(connectionString);
        _db.Open();
        EnsureSchema();
    }

    private void EnsureSchema()
    {
        using var cmd = _db.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        INTEGER NOT NULL,
                kind      INTEGER NOT NULL,
                summary   TEXT    NOT NULL,
                detail    TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
            """;
        cmd.ExecuteNonQuery();
    }

    public void Log(EventKind kind, string summary, string? detail = null)
    {
        try
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText =
                "INSERT INTO events(ts, kind, summary, detail) VALUES($ts,$k,$s,$d)";
            cmd.Parameters.AddWithValue("$ts",  DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            cmd.Parameters.AddWithValue("$k",   (int)kind);
            cmd.Parameters.AddWithValue("$s",   summary);
            cmd.Parameters.AddWithValue("$d",   (object?)detail ?? DBNull.Value);
            cmd.ExecuteNonQuery();
        }
        catch { /* non-critical */ }
    }

    public IReadOnlyList<AvdonEvent> GetRecent(int limit = 200)
    {
        var list = new List<AvdonEvent>();
        try
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText =
                "SELECT id,ts,kind,summary,detail FROM events ORDER BY ts DESC LIMIT $n";
            cmd.Parameters.AddWithValue("$n", limit);
            using var r = cmd.ExecuteReader();
            while (r.Read())
                list.Add(new AvdonEvent(
                    r.GetInt32(0),
                    DateTimeOffset.FromUnixTimeSeconds(r.GetInt64(1)).LocalDateTime,
                    (EventKind)r.GetInt32(2),
                    r.GetString(3),
                    r.IsDBNull(4) ? null : r.GetString(4)));
        }
        catch { }
        return list;
    }

    public int CountToday()
    {
        try
        {
            var midnight = new DateTimeOffset(DateTime.Today, TimeZoneInfo.Local.GetUtcOffset(DateTime.Today))
                .ToUnixTimeSeconds();
            using var cmd = _db.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM events WHERE ts >= $m";
            cmd.Parameters.AddWithValue("$m", midnight);
            return Convert.ToInt32(cmd.ExecuteScalar());
        }
        catch { return 0; }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _db.Dispose();
    }
}
