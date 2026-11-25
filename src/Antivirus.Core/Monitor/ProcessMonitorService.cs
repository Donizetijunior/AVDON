using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using AntivirusOS.Core.Models;
using AntivirusOS.Core.Signatures;

namespace AntivirusOS.Core.Monitor;

public sealed record ProcessEntry(
    int     Pid,
    string  Name,
    string  FilePath,
    string  Hash,
    long    WorkingSetMB,
    ThreatLevel Level,
    string  LevelNote);

[SupportedOSPlatform("windows")]
public sealed class ProcessMonitorService
{
    private readonly ISignatureDatabase _db;

    public ProcessMonitorService(ISignatureDatabase db) => _db = db;

    public async Task<IReadOnlyList<ProcessEntry>> ScanAsync(CancellationToken ct = default)
    {
        var procs = Process.GetProcesses();
        var results = new List<ProcessEntry>(procs.Length);

        await Parallel.ForEachAsync(procs, new ParallelOptions { MaxDegreeOfParallelism = 4, CancellationToken = ct }, async (p, token) =>
        {
            var entry = await InspectAsync(p, token);
            if (entry != null)
                lock (results) results.Add(entry);
            p.Dispose();
        });

        return results.OrderByDescending(e => (int)e.Level).ThenBy(e => e.Name).ToList();
    }

    private async Task<ProcessEntry?> InspectAsync(Process p, CancellationToken ct)
    {
        try
        {
            string path;
            try { path = p.MainModule?.FileName ?? string.Empty; }
            catch { return null; }

            if (string.IsNullOrEmpty(path)) return null;

            long wsBytes;
            try { wsBytes = p.WorkingSet64; } catch { wsBytes = 0; }

            var (hash, level, note) = await CheckFileAsync(path, ct);

            return new ProcessEntry(
                p.Id,
                p.ProcessName,
                path,
                hash,
                wsBytes / 1024 / 1024,
                level,
                note);
        }
        catch { return null; }
    }

    private async Task<(string hash, ThreatLevel level, string note)> CheckFileAsync(string path, CancellationToken ct)
    {
        try
        {
            byte[] bytes = await File.ReadAllBytesAsync(path, ct);
            string hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

            var sig = await _db.LookupAsync(hash);
            if (sig != null)
                return (hash, ThreatLevel.Malicious, $"Assinatura: {sig.Name}");

            // Heuristic: unsigned executable in temp/appdata
            if (IsInSuspiciousLocation(path))
                return (hash, ThreatLevel.Suspicious, "Local suspeito");

            return (hash, ThreatLevel.Clean, "Limpo");
        }
        catch (UnauthorizedAccessException) { return (string.Empty, ThreatLevel.Clean, "Sem acesso"); }
        catch (IOException)                 { return (string.Empty, ThreatLevel.Clean, "Arquivo bloqueado"); }
        catch (OperationCanceledException) { throw; }
        catch                               { return (string.Empty, ThreatLevel.Clean, "Erro ao ler"); }
    }

    private static bool IsInSuspiciousLocation(string path)
    {
        var temp    = Path.GetTempPath();
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var local   = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        return path.StartsWith(temp,    StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(appdata, StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(local,   StringComparison.OrdinalIgnoreCase);
    }
}
