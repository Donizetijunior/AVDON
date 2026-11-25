using AntivirusOS.Core.Models;
using Microsoft.Data.Sqlite;

namespace AntivirusOS.Core.Signatures;

public class SignatureDatabase : ISignatureDatabase, IDisposable
{
    private readonly SqliteConnection _connection;

    public SignatureDatabase(string connectionString)
    {
        _connection = new SqliteConnection(connectionString);
        _connection.Open();
    }

    public async Task InitializeAsync()
    {
        var cmd = _connection.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS signatures (
                hash TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                level INTEGER NOT NULL,
                description TEXT NOT NULL
            )
            """;
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task AddSignatureAsync(ThreatInfo threat)
    {
        var cmd = _connection.CreateCommand();
        cmd.CommandText = "INSERT OR IGNORE INTO signatures (hash, name, level, description) VALUES ($hash, $name, $level, $description)";
        cmd.Parameters.AddWithValue("$hash", threat.Hash);
        cmd.Parameters.AddWithValue("$name", threat.Name);
        cmd.Parameters.AddWithValue("$level", (int)threat.Level);
        cmd.Parameters.AddWithValue("$description", threat.Description);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<ThreatInfo?> LookupAsync(string sha256Hash)
    {
        var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT hash, name, level, description FROM signatures WHERE hash = $hash";
        cmd.Parameters.AddWithValue("$hash", sha256Hash);
        using var reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
            return null;
        return new ThreatInfo(
            reader.GetString(0),
            reader.GetString(1),
            (ThreatLevel)reader.GetInt32(2),
            reader.GetString(3)
        );
    }

    public async Task<int> CountAsync()
    {
        var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM signatures";
        var result = await cmd.ExecuteScalarAsync();
        return Convert.ToInt32(result);
    }

    public void Dispose()
    {
        _connection.Dispose();
    }
}
