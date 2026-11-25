using AntivirusOS.Core.Models;
using AntivirusOS.Core.Quarantine;

namespace AntivirusOS.Core.Scanner;

public sealed class ScheduledScanner
{
    private readonly IFileScanner _scanner;
    private readonly IQuarantineManager _quarantine;
    private PeriodicTimer? _timer;

    public event EventHandler<ScanCompletedEventArgs>? ScanCompleted;

    public ScheduledScanner(IFileScanner scanner, IQuarantineManager quarantine)
    {
        _scanner = scanner;
        _quarantine = quarantine;
    }

    public async Task StartAsync(string path, TimeSpan interval, CancellationToken cancellationToken = default)
    {
        _timer = new PeriodicTimer(interval);
        try
        {
            while (await _timer.WaitForNextTickAsync(cancellationToken))
            {
                try
                {
                    int total = 0, threats = 0;
                    await foreach (var result in _scanner.ScanDirectoryAsync(path, recursive: true)
                        .WithCancellation(cancellationToken))
                    {
                        total++;
                        if (result.Level == ThreatLevel.Malicious)
                        {
                            threats++;
                            try { await _quarantine.QuarantineAsync(result.FilePath, result.Hash); }
                            catch { /* ignore individual quarantine errors */ }
                        }
                    }
                    ScanCompleted?.Invoke(this, new ScanCompletedEventArgs(total, threats));
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    // Log silently; next tick will retry
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
        finally
        {
            _timer?.Dispose();
            _timer = null;
        }
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
    }
}

public sealed class ScanCompletedEventArgs : EventArgs
{
    public int Total { get; }
    public int Threats { get; }
    public ScanCompletedEventArgs(int total, int threats) { Total = total; Threats = threats; }
}
