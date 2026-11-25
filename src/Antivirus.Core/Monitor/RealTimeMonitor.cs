using AntivirusOS.Core.Models;
using AntivirusOS.Core.Scanner;
using AntivirusOS.Core.Quarantine;
using System.Threading.Channels;

namespace AntivirusOS.Core.Monitor;

public class RealTimeMonitor : IRealTimeMonitor, IDisposable
{
    private readonly IFileScanner _scanner;
    private readonly IQuarantineManager _quarantineManager;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly List<string> _monitoredPaths = [];
    private Channel<string>? _channel;
    private CancellationTokenSource? _cts;
    private Task? _consumerTask;

    public event EventHandler<FileDetectedEventArgs>? ThreatDetected;
    public IReadOnlyList<string> MonitoredPaths => _monitoredPaths.AsReadOnly();

    public RealTimeMonitor(IFileScanner scanner, IQuarantineManager quarantineManager)
    {
        _scanner = scanner;
        _quarantineManager = quarantineManager;
    }

    public void StartMonitoring(string path) => StartMonitoring([path]);

    public void StartMonitoring(IEnumerable<string> paths)
    {
        StopMonitoring();

        _channel = Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleReader = true });
        _cts = new CancellationTokenSource();
        _consumerTask = Task.Run(() => ConsumeAsync(_cts.Token));

        foreach (var path in paths.Where(Directory.Exists).Distinct())
        {
            var watcher = new FileSystemWatcher(path)
            {
                InternalBufferSize = 65536,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                EnableRaisingEvents = true
            };
            watcher.Created += OnFileEvent;
            watcher.Changed += OnFileEvent;
            watcher.Error += OnError;
            _watchers.Add(watcher);
            _monitoredPaths.Add(path);
        }
    }

    public void StopMonitoring()
    {
        foreach (var w in _watchers)
            w.Dispose();
        _watchers.Clear();
        _monitoredPaths.Clear();

        _channel?.Writer.TryComplete();
        _cts?.Cancel();
        try { _consumerTask?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        _cts?.Dispose();
        _cts = null;
        _consumerTask = null;
        _channel = null;
    }

    private void OnFileEvent(object sender, FileSystemEventArgs e)
    {
        _channel?.Writer.TryWrite(e.FullPath);
    }

    private async Task ConsumeAsync(CancellationToken token)
    {
        if (_channel == null) return;

        // Track pending paths with debounce
        var pending = new Dictionary<string, DateTime>();

        try
        {
            while (!token.IsCancellationRequested)
            {
                // Drain newly arrived paths
                while (_channel.Reader.TryRead(out var path))
                    pending[path] = DateTime.UtcNow;

                // Wait for channel or debounce timeout
                if (pending.Count == 0)
                {
                    // Block until something arrives
                    if (!await _channel.Reader.WaitToReadAsync(token))
                        break;
                    continue;
                }

                // Debounce: 500ms wait
                await Task.Delay(500, token);

                // Drain again after delay
                while (_channel.Reader.TryRead(out var path))
                    pending[path] = DateTime.UtcNow;

                var toScan = pending.Keys.ToList();
                pending.Clear();

                foreach (var filePath in toScan)
                {
                    if (token.IsCancellationRequested) break;
                    await ScanFileWithRetryAsync(filePath, token);
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    private async Task ScanFileWithRetryAsync(string filePath, CancellationToken token)
    {
        // Check if file exists and is accessible
        if (!File.Exists(filePath)) return;

        // Try to open with FileShare.Read to check if it's locked
        bool accessible = false;
        for (int attempt = 0; attempt < 3 && !token.IsCancellationRequested; attempt++)
        {
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                accessible = true;
                break;
            }
            catch (IOException)
            {
                await Task.Delay(500, token);
            }
        }

        if (!accessible) return;

        try
        {
            var result = await _scanner.ScanFileAsync(filePath);
            if (result.Level != ThreatLevel.Clean)
            {
                await _quarantineManager.QuarantineAsync(filePath, result.Hash);
                ThreatDetected?.Invoke(this, new FileDetectedEventArgs(result));
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error scanning file {filePath}: {ex.Message}");
        }
    }

    private void OnError(object sender, ErrorEventArgs e)
    {
        System.Diagnostics.Debug.WriteLine($"FileSystemWatcher error: {e.GetException()?.Message}");
    }

    public void Dispose()
    {
        StopMonitoring();
    }
}
