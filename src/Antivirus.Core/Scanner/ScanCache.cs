using AntivirusOS.Core.Models;
using Microsoft.Data.Sqlite;

namespace AntivirusOS.Core.Scanner;

public class ScanCache : IScanCache
{
    private readonly string _connectionString;

    public ScanCache(string dbPath)
    {
        _connectionString = $"Data Source={dbPath};Pooling=False";
        InitializeDb();
    }

    private void InitializeDb()
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS scan_cache (
                file_path TEXT PRIMARY KEY,
                hash TEXT NOT NULL,
                level INTEGER NOT NULL,
                scanned_at TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                last_modified TEXT NOT NULL
            )
            """;
        cmd.ExecuteNonQuery();
    }

    public async Task<ScanResult?> GetAsync(string filePath)
    {
        FileInfo fi;
        try { fi = new FileInfo(filePath); if (!fi.Exists) return null; }
        catch { return null; }

        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT hash, level, scanned_at, file_size, last_modified FROM scan_cache WHERE file_path = @p";
        cmd.Parameters.AddWithValue("@p", filePath);

        await using var reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync()) return null;

        var cachedSize = reader.GetInt64(3);
        var cachedMod = DateTime.Parse(reader.GetString(4), null, System.Globalization.DateTimeStyles.RoundtripKind);

        if (cachedSize != fi.Length || Math.Abs((cachedMod - fi.LastWriteTimeUtc).TotalSeconds) > 1)
            return null;

        var hash = reader.GetString(0);
        var level = (ThreatLevel)reader.GetInt32(1);
        var scannedAt = DateTime.Parse(reader.GetString(2), null, System.Globalization.DateTimeStyles.RoundtripKind);

        return new ScanResult(filePath, hash, level, null, scannedAt);
    }

    public async Task SetAsync(ScanResult result, long fileSize, DateTime lastModified)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO scan_cache (file_path, hash, level, scanned_at, file_size, last_modified)
            VALUES (@path, @hash, @level, @scanned, @size, @mod)
            ON CONFLICT(file_path) DO UPDATE SET
                hash = excluded.hash,
                level = excluded.level,
                scanned_at = excluded.scanned_at,
                file_size = excluded.file_size,
                last_modified = excluded.last_modified
            """;
        cmd.Parameters.AddWithValue("@path", result.FilePath);
        cmd.Parameters.AddWithValue("@hash", result.Hash);
        cmd.Parameters.AddWithValue("@level", (int)result.Level);
        cmd.Parameters.AddWithValue("@scanned", result.ScannedAt.ToString("O"));
        cmd.Parameters.AddWithValue("@size", fileSize);
        cmd.Parameters.AddWithValue("@mod", lastModified.ToString("O"));
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task InvalidateAsync(string filePath)
    {
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM scan_cache WHERE file_path = @p";
        cmd.Parameters.AddWithValue("@p", filePath);
        await cmd.ExecuteNonQueryAsync();
    }
}
