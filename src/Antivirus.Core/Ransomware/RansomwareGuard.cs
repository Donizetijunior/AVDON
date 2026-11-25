using System.Collections.Concurrent;
using System.Threading.Channels;
using AntivirusOS.Core.Monitor;

namespace AntivirusOS.Core.Ransomware;

/// <summary>
/// Detects ransomware by watching for mass-file modification bursts and honeypot file tampering.
/// </summary>
public sealed class RansomwareGuard : IDisposable
{
    private readonly List<string> _honeypotPaths = [];
    private readonly ConcurrentDictionary<string, Queue<DateTime>> _modWindows = new();
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly Channel<RansomwareAlert> _alertChannel;
    private CancellationTokenSource? _cts;
    private Task? _consumer;

    // Alert fires on: honeypot touched OR >ThresholdCount file writes in ThresholdWindow
    public const int ThresholdCount = 20;
    public static readonly TimeSpan ThresholdWindow = TimeSpan.FromSeconds(10);

    public event EventHandler<RansomwareAlert>? AlertRaised;

    public RansomwareGuard()
    {
        _alertChannel = Channel.CreateUnbounded<RansomwareAlert>(
            new UnboundedChannelOptions { SingleReader = true });
    }

    public void Start(IEnumerable<string> watchPaths)
    {
        Stop();
        _cts = new CancellationTokenSource();
        _consumer = Task.Run(() => ConsumeAsync(_cts.Token));

        foreach (var root in watchPaths.Where(Directory.Exists).Distinct())
        {
            // Plant honeypot in each watched folder
            var honeypot = PlantHoneypot(root);
            if (honeypot != null)
                _honeypotPaths.Add(honeypot);

            var w = new FileSystemWatcher(root)
            {
                IncludeSubdirectories = true,
                InternalBufferSize = 65536,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                EnableRaisingEvents = true
            };
            w.Changed += OnFileActivity;
            w.Created += OnFileActivity;
            w.Renamed += OnFileRenamed;
            w.Error   += OnError;
            _watchers.Add(w);
        }
    }

    public void Stop()
    {
        foreach (var w in _watchers) w.Dispose();
        _watchers.Clear();
        _modWindows.Clear();

        _alertChannel.Writer.TryComplete();
        _cts?.Cancel();
        try { _consumer?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        _cts?.Dispose();
        _cts = null;
        _consumer = null;

        // Remove honeypots
        foreach (var hp in _honeypotPaths)
        {
            try { File.Delete(hp); } catch { }
        }
        _honeypotPaths.Clear();
    }

    private string? PlantHoneypot(string folder)
    {
        try
        {
            // Name starts with "AAAA_" so it sorts first alphabetically → ransomware hits it early
            var path = Path.Combine(folder, "AAAA_avdon_sentinel.tmp");
            File.WriteAllText(path, "AVDON ransomware sentinel — do not modify.");
            File.SetAttributes(path, FileAttributes.Hidden);
            return path;
        }
        catch
        {
            return null;
        }
    }

    private void OnFileActivity(object sender, FileSystemEventArgs e)
    {
        if (_honeypotPaths.Contains(e.FullPath, StringComparer.OrdinalIgnoreCase))
        {
            _alertChannel.Writer.TryWrite(new RansomwareAlert(
                RansomwareAlertKind.HoneypotTriggered, e.FullPath, 1));
            return;
        }

        TrackModification(e.FullPath);
    }

    private void OnFileRenamed(object sender, RenamedEventArgs e)
    {
        // Ransomware renames files to add an encryption extension
        var ext = Path.GetExtension(e.FullPath).ToLowerInvariant();
        if (ext.Length > 1 && ext.Length <= 8 && IsLikelyEncryptedExt(e.OldFullPath, e.FullPath))
        {
            TrackModification(e.FullPath);
        }
    }

    private static bool IsLikelyEncryptedExt(string oldPath, string newPath)
    {
        var oldExt = Path.GetExtension(oldPath).ToLowerInvariant();
        var newExt = Path.GetExtension(newPath).ToLowerInvariant();
        // Common doc extensions renamed to something unknown
        string[] knownExts = [".txt", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".jpg", ".png", ".mp4", ".zip"];
        return knownExts.Contains(oldExt) && !knownExts.Contains(newExt);
    }

    private void TrackModification(string filePath)
    {
        var dir = Path.GetDirectoryName(filePath) ?? filePath;
        var window = _modWindows.GetOrAdd(dir, _ => new Queue<DateTime>());

        lock (window)
        {
            var now = DateTime.UtcNow;
            window.Enqueue(now);

            // Evict old entries
            while (window.Count > 0 && now - window.Peek() > ThresholdWindow)
                window.Dequeue();

            if (window.Count >= ThresholdCount)
            {
                _alertChannel.Writer.TryWrite(new RansomwareAlert(
                    RansomwareAlertKind.MassEncryption, dir, window.Count));
                window.Clear(); // reset to avoid spam
            }
        }
    }

    private async Task ConsumeAsync(CancellationToken token)
    {
        try
        {
            await foreach (var alert in _alertChannel.Reader.ReadAllAsync(token))
                AlertRaised?.Invoke(this, alert);
        }
        catch (OperationCanceledException) { }
    }

    private static void OnError(object sender, ErrorEventArgs e)
    {
        System.Diagnostics.Debug.WriteLine($"RansomwareGuard FSW error: {e.GetException()?.Message}");
    }

    public void Dispose() => Stop();
}

public record RansomwareAlert(RansomwareAlertKind Kind, string Path, int FileCount);

public enum RansomwareAlertKind
{
    HoneypotTriggered,
    MassEncryption
}
