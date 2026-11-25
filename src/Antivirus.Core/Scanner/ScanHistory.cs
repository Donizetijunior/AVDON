using AntivirusOS.Core.Models;
using Microsoft.Data.Sqlite;

namespace AntivirusOS.Core.Scanner;

public sealed class ScanHistory : IScanHistory
{
    private readonly string _connectionString;

    public ScanHistory(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task InitializeAsync()
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                hash TEXT NOT NULL,
                level INTEGER NOT NULL,
                scanned_at TEXT NOT NULL
            );
            """;
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task AddAsync(ScanResult result)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO scan_history (file_path, hash, level, scanned_at) VALUES ($fp, $hash, $level, $at)";
        cmd.Parameters.AddWithValue("$fp", result.FilePath);
        cmd.Parameters.AddWithValue("$hash", result.Hash);
        cmd.Parameters.AddWithValue("$level", (int)result.Level);
        cmd.Parameters.AddWithValue("$at", result.ScannedAt.ToString("o"));
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<IReadOnlyList<ScanResult>> GetRecentAsync(int limit = 100)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT file_path, hash, level, scanned_at FROM scan_history ORDER BY scanned_at DESC LIMIT $limit";
        cmd.Parameters.AddWithValue("$limit", limit);

        var list = new List<ScanResult>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var filePath = reader.GetString(0);
            var hash = reader.GetString(1);
            var level = (ThreatLevel)reader.GetInt32(2);
            var scannedAt = DateTime.Parse(reader.GetString(3));
            list.Add(new ScanResult(filePath, hash, level, null, scannedAt));
        }
        return list;
    }

    public async Task<IReadOnlyList<ScanResult>> GetAllAsync()
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT file_path, hash, level, scanned_at FROM scan_history ORDER BY scanned_at DESC";

        var list = new List<ScanResult>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var filePath  = reader.GetString(0);
            var hash      = reader.GetString(1);
            var level     = (ThreatLevel)reader.GetInt32(2);
            var scannedAt = DateTime.Parse(reader.GetString(3));
            list.Add(new ScanResult(filePath, hash, level, null, scannedAt));
        }
        return list;
    }
}
