namespace AntivirusOS.Core.Updater;

public sealed class AutoUpdater
{
    private readonly ISignatureUpdater _updater;
    private readonly TimeSpan _interval;
    private PeriodicTimer? _timer;

    public AutoUpdater(ISignatureUpdater updater, TimeSpan interval)
    {
        _updater = updater;
        _interval = interval;
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        _timer = new PeriodicTimer(_interval);
        try
        {
            while (await _timer.WaitForNextTickAsync(cancellationToken))
            {
                try
                {
                    await _updater.UpdateFromMalwareBazaarAsync(cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    // Silently ignore update errors — will retry next interval
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
