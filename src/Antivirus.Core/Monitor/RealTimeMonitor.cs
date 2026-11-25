using AntivirusOS.Core.Models;
using AntivirusOS.Core.Scanner;
using AntivirusOS.Core.Quarantine;

namespace AntivirusOS.Core.Monitor;

public class RealTimeMonitor : IRealTimeMonitor, IDisposable
{
    private readonly IFileScanner _scanner;
    private readonly IQuarantineManager _quarantineManager;
    private FileSystemWatcher? _watcher;

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
        try
        {
            var result = await _scanner.ScanFileAsync(e.FullPath);
            if (result.Level != ThreatLevel.Clean)
            {
                await _quarantineManager.QuarantineAsync(e.FullPath, result.Hash);
                ThreatDetected?.Invoke(this, new FileDetectedEventArgs(result));
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error scanning file {e.FullPath}: {ex.Message}");
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
