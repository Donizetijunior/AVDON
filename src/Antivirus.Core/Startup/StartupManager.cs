using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace AntivirusOS.Core.Startup;

public enum StartupThreatLevel { Unknown, Clean, Suspicious, Malicious }

public sealed record StartupItem(
    string Name,
    string FilePath,
    string Hash,
    string Source,       // e.g. "HKCU\\Run", "HKLM\\Run", "Startup folder"
    bool   IsEnabled,
    StartupThreatLevel Level,
    string Publisher);

[SupportedOSPlatform("windows")]
public sealed class StartupManager
{
    private static readonly string[] _runKeys =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    public IReadOnlyList<StartupItem> Enumerate()
    {
        var items = new List<StartupItem>();

        foreach (var (root, label) in new[] {
            (Registry.CurrentUser,  "HKCU"),
            (Registry.LocalMachine, "HKLM") })
        {
            foreach (var keyPath in _runKeys)
            {
                using var key = root.OpenSubKey(keyPath);
                if (key is null) continue;
                var suffix = keyPath.Contains("RunOnce") ? "\\RunOnce" : "\\Run";
                foreach (var name in key.GetValueNames())
                {
                    var raw = key.GetValue(name)?.ToString() ?? string.Empty;
                    var exePath = ExtractExePath(raw);
                    items.Add(BuildItem(name, exePath, $"{label}{suffix}"));
                }
            }
        }

        // User Startup folder
        var startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (Directory.Exists(startupFolder))
        {
            foreach (var f in Directory.GetFiles(startupFolder, "*.lnk"))
            {
                items.Add(BuildItem(Path.GetFileNameWithoutExtension(f), f, "Startup folder"));
            }
        }

        return items;
    }

    public (bool ok, string msg) Disable(StartupItem item)
    {
        try
        {
            if (!item.Source.StartsWith("HK")) return (false, "Apenas entradas de registro podem ser desabilitadas aqui.");
            var (root, path) = ResolveKey(item.Source);
            using var key = root?.OpenSubKey(path, writable: true);
            if (key is null) return (false, "Chave de registro não encontrada.");
            var disabledPath = path + @"\AutorunsDisabled";
            using var disabled = root!.CreateSubKey(disabledPath, writable: true);
            var current = key.GetValue(item.Name);
            disabled.SetValue(item.Name, current ?? string.Empty);
            key.DeleteValue(item.Name, throwOnMissingValue: false);
            return (true, $"'{item.Name}' desabilitado.");
        }
        catch (UnauthorizedAccessException)
        {
            return (false, "Permissão negada. Execute como Administrador.");
        }
        catch (Exception ex) { return (false, $"Erro: {ex.Message}"); }
    }

    private static StartupItem BuildItem(string name, string exePath, string source)
    {
        var hash      = ComputeHash(exePath);
        var publisher = GetPublisher(exePath);
        var level     = ClassifyPath(exePath);
        return new StartupItem(name, exePath, hash, source, IsEnabled: true, level, publisher);
    }

    private static string ComputeHash(string path)
    {
        try
        {
            if (!File.Exists(path)) return string.Empty;
            using var sha = SHA256.Create();
            using var fs  = File.OpenRead(path);
            return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
        }
        catch { return string.Empty; }
    }

    private static string GetPublisher(string path)
    {
        try
        {
            if (!File.Exists(path)) return "—";
            var info = System.Diagnostics.FileVersionInfo.GetVersionInfo(path);
            return string.IsNullOrWhiteSpace(info.CompanyName) ? "—" : info.CompanyName;
        }
        catch { return "—"; }
    }

    private static StartupThreatLevel ClassifyPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return StartupThreatLevel.Unknown;
        var lower = path.ToLowerInvariant();
        // Flag entries pointing to Temp / AppData roaming user folders as Suspicious
        if (lower.Contains(@"\temp\") || lower.Contains(@"\appdata\roaming\") ||
            lower.Contains(@"\appdata\local\temp\"))
            return StartupThreatLevel.Suspicious;
        return StartupThreatLevel.Clean;
    }

    private static string ExtractExePath(string raw)
    {
        raw = raw.Trim();
        if (raw.StartsWith("\""))
        {
            var end = raw.IndexOf('"', 1);
            return end > 0 ? raw[1..end] : raw;
        }
        var spaceIdx = raw.IndexOf(' ');
        return spaceIdx > 0 ? raw[..spaceIdx] : raw;
    }

    private static (RegistryKey? root, string path) ResolveKey(string source)
    {
        // source is like "HKCU\Run" or "HKLM\RunOnce" — map to full registry path
        var (root, hive) = source.StartsWith("HKCU")
            ? (Registry.CurrentUser,  "HKCU\\")
            : source.StartsWith("HKLM")
                ? (Registry.LocalMachine, "HKLM\\")
                : ((RegistryKey?)null, string.Empty);

        if (root is null) return (null, string.Empty);

        var suffix = source[hive.Length..]; // "Run" or "RunOnce"
        var fullPath = suffix switch
        {
            "Run"     => @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "RunOnce" => @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            _         => string.Empty
        };

        return string.IsNullOrEmpty(fullPath) ? (null, string.Empty) : (root, fullPath);
    }
}
