using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;

namespace AntivirusOS.Core.Integrity;

public enum IntegrityStatus { OK, Modified, Missing, New }

public sealed record IntegrityEntry(
    string FilePath,
    string ExpectedHash,
    string ActualHash,
    IntegrityStatus Status,
    DateTime SnapshotTime);

[SupportedOSPlatform("windows")]
public sealed class FileIntegrityService
{
    private static readonly string[] _criticalPaths =
    [
        @"C:\Windows\System32\drivers\etc\hosts",
        @"C:\Windows\System32\ntdll.dll",
        @"C:\Windows\System32\kernel32.dll",
        @"C:\Windows\System32\kernelbase.dll",
        @"C:\Windows\System32\user32.dll",
        @"C:\Windows\System32\advapi32.dll",
        @"C:\Windows\System32\ws2_32.dll",
        @"C:\Windows\System32\wininet.dll",
        @"C:\Windows\System32\winsock.dll",
        @"C:\Windows\System32\lsass.exe",
        @"C:\Windows\System32\svchost.exe",
        @"C:\Windows\System32\services.exe",
        @"C:\Windows\System32\csrss.exe",
        @"C:\Windows\System32\smss.exe",
        @"C:\Windows\System32\wininit.exe",
        @"C:\Windows\System32\winlogon.exe",
    ];

    private readonly string _snapshotPath;

    public FileIntegrityService(string appDataPath)
    {
        _snapshotPath = Path.Combine(appDataPath, "integrity_snapshot.json");
    }

    // Take a fresh snapshot of all critical files
    public async Task<IReadOnlyList<IntegrityEntry>> TakeSnapshotAsync(
        IEnumerable<string>? extraPaths = null,
        CancellationToken ct = default)
    {
        var paths = _criticalPaths.Concat(extraPaths ?? []).Distinct();
        var entries = new List<IntegrityEntry>();
        var now = DateTime.UtcNow;

        await Task.Run(() =>
        {
            foreach (var path in paths)
            {
                ct.ThrowIfCancellationRequested();
                var hash = ComputeHash(path);
                entries.Add(new IntegrityEntry(
                    path, hash, hash,
                    string.IsNullOrEmpty(hash) ? IntegrityStatus.Missing : IntegrityStatus.OK,
                    now));
            }
        }, ct);

        // Persist
        var dict = entries.ToDictionary(e => e.FilePath, e => new SnapshotRecord(e.ExpectedHash, now));
        await File.WriteAllTextAsync(_snapshotPath,
            JsonSerializer.Serialize(dict, new JsonSerializerOptions { WriteIndented = true }), ct);

        return entries;
    }

    // Verify current files against stored snapshot
    public async Task<IReadOnlyList<IntegrityEntry>> VerifyAsync(
        IEnumerable<string>? extraPaths = null,
        CancellationToken ct = default)
    {
        Dictionary<string, SnapshotRecord>? snapshot = null;
        if (File.Exists(_snapshotPath))
        {
            try
            {
                var json = await File.ReadAllTextAsync(_snapshotPath, ct);
                snapshot = JsonSerializer.Deserialize<Dictionary<string, SnapshotRecord>>(json);
            }
            catch { }
        }

        var paths = _criticalPaths.Concat(extraPaths ?? []).Distinct();
        var results = new List<IntegrityEntry>();

        await Task.Run(() =>
        {
            foreach (var path in paths)
            {
                ct.ThrowIfCancellationRequested();
                var actual = ComputeHash(path);

                if (snapshot == null || !snapshot.TryGetValue(path, out var rec))
                {
                    // No baseline — treat as new (needs snapshot first)
                    results.Add(new IntegrityEntry(path, string.Empty, actual,
                        IntegrityStatus.New, DateTime.UtcNow));
                    continue;
                }

                IntegrityStatus status;
                if (string.IsNullOrEmpty(actual))
                    status = IntegrityStatus.Missing;
                else if (actual == rec.Hash)
                    status = IntegrityStatus.OK;
                else
                    status = IntegrityStatus.Modified;

                results.Add(new IntegrityEntry(path, rec.Hash, actual, status, rec.Time));
            }
        }, ct);

        return results;
    }

    public bool HasSnapshot() => File.Exists(_snapshotPath);

    private static string ComputeHash(string path)
    {
        try
        {
            if (!File.Exists(path)) return string.Empty;
            using var sha = SHA256.Create();
            using var fs  = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
        }
        catch { return string.Empty; }
    }

    private sealed record SnapshotRecord(string Hash, DateTime Time);
}
