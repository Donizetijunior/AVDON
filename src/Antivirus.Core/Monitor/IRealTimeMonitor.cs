namespace AntivirusOS.Core.Monitor;
public interface IRealTimeMonitor
{
    void StartMonitoring(string path);
    void StartMonitoring(IEnumerable<string> paths);
    void StopMonitoring();
    IReadOnlyList<string> MonitoredPaths { get; }
    event EventHandler<FileDetectedEventArgs> ThreatDetected;
}
