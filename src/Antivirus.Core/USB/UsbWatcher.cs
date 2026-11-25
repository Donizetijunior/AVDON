using System.Management;
using System.Runtime.Versioning;

namespace AntivirusOS.Core.USB;

public sealed class DriveInsertedEventArgs(string driveLetter, string volumeName) : EventArgs
{
    public string DriveLetter { get; } = driveLetter;
    public string VolumeName  { get; } = volumeName;
}

[SupportedOSPlatform("windows")]
public sealed class UsbWatcher : IDisposable
{
    private ManagementEventWatcher? _insertWatcher;
    private bool _disposed;

    public event EventHandler<DriveInsertedEventArgs>? DriveInserted;

    public void Start()
    {
        if (_insertWatcher != null) return;

        // Win32_VolumeChangeEvent EventType=2 means "Drive Inserted"
        var query = new WqlEventQuery(
            "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2");
        _insertWatcher = new ManagementEventWatcher(query);
        _insertWatcher.EventArrived += OnInserted;
        _insertWatcher.Start();
    }

    private void OnInserted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var letter     = e.NewEvent.Properties["DriveName"].Value?.ToString() ?? string.Empty;
            var volumeName = GetVolumeLabel(letter);
            DriveInserted?.Invoke(this, new DriveInsertedEventArgs(letter, volumeName));
        }
        catch { }
    }

    private static string GetVolumeLabel(string driveLetter)
    {
        try
        {
            var info = new DriveInfo(driveLetter);
            return info.IsReady ? (info.VolumeLabel.Length > 0 ? info.VolumeLabel : "Sem nome") : string.Empty;
        }
        catch { return string.Empty; }
    }

    public void Stop()
    {
        _insertWatcher?.Stop();
        _insertWatcher?.Dispose();
        _insertWatcher = null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }
}
