namespace AntivirusOS.Core.Monitor;
public interface IRealTimeMonitor
{
    void StartMonitoring(string path);
    void StopMonitoring();
    event EventHandler<FileDetectedEventArgs> ThreatDetected;
}
