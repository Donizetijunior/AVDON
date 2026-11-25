using AntivirusOS.Core.Models;
using AntivirusOS.Core.Scanner;
using AntivirusOS.Core.Quarantine;
using System.Collections.Concurrent;

namespace AntivirusOS.Core.Monitor;

public class RealTimeMonitor : IRealTimeMonitor, IDisposable
{
    private readonly IFileScanner _scanner;
    private readonly IQuarantineManager _quarantineManager;
    private FileSystemWatcher? _watcher;
    private readonly ConcurrentDictionary<string, DateTime> _recentlyScanned = new();

    public event EventHandler<FileDetectedEventArgs>? ThreatDetected;

    public RealTimeMonitor(IFileScanner scanner, IQuarantineManager quarantineManager)
    {
        _scanner = scanner;
        _quarantineManager = quarantineManager;
    }

    public void StartMonitoring(string path)
    {
        _watcher?.Dispose();
        _watcher = new FileSystemWatcher(path)
        {
            InternalBufferSize = 65536,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
            EnableRaisingEvents = true
        };
        _watcher.Created += OnFileEvent;
        _watcher.Changed += OnFileEvent;
        _watcher.Error += OnError;
    }

    public void StopMonitoring()
    {
        _watcher?.Dispose();
        _watcher = null;
    }

    private async void OnFileEvent(object sender, FileSystemEventArgs e)
    {
        var path = e.FullPath;
        var now = DateTime.UtcNow;

        if (_recentlyScanned.TryGetValue(path, out var lastScanned) &&
            (now - lastScanned).TotalSeconds < 2)
        {
            return;
        }

        _recentlyScanned[path] = now;

        try
        {
            var result = await _scanner.ScanFileAsync(path);
            if (result.Level != ThreatLevel.Clean)
            {
                await _quarantineManager.QuarantineAsync(path, result.Hash);
                ThreatDetected?.Invoke(this, new FileDetectedEventArgs(result));
            }

            // Clean up entries older than 5 seconds
            var cutoff = DateTime.UtcNow.AddSeconds(-5);
            foreach (var key in _recentlyScanned.Keys)
            {
                if (_recentlyScanned.TryGetValue(key, out var ts) && ts < cutoff)
                    _recentlyScanned.TryRemove(key, out _);
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error scanning file {path}: {ex.Message}");
        }
    }

    private void OnError(object sender, ErrorEventArgs e)
    {
        System.Diagnostics.Debug.WriteLine($"FileSystemWatcher error: {e.GetException()?.Message}");
    }

    public void Dispose()
    {
        _watcher?.Dispose();
        _watcher = null;
    }
}
