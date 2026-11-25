using AntivirusOS.Core.Models;
using AntivirusOS.Core.Scanner;
using AntivirusOS.Core.Quarantine;
using AntivirusOS.Core.Monitor;
using Moq;

namespace Antivirus.Tests.Monitor;

public class RealTimeMonitorTests
{
    [Fact]
    public async Task Monitor_DetectsNewFile_RaisesThreatDetected()
    {
        var scannerMock = new Mock<IFileScanner>();
        var threat = new ThreatInfo("xx", "T", ThreatLevel.Malicious, "");
        scannerMock.Setup(s => s.ScanFileAsync(It.IsAny<string>()))
            .ReturnsAsync(new ScanResult("", "xx", ThreatLevel.Malicious, threat, DateTime.UtcNow));
        var quarMock = new Mock<IQuarantineManager>();
        quarMock.Setup(q => q.QuarantineAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(new QuarantineEntry("", "", "", DateTime.UtcNow));

        using var monitor = new RealTimeMonitor(scannerMock.Object, quarMock.Object);
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        try
        {
            FileDetectedEventArgs? detected = null;
            monitor.ThreatDetected += (_, e) => detected = e;
            monitor.StartMonitoring(tempDir);

            await File.WriteAllTextAsync(Path.Combine(tempDir, "test.exe"), "data");
            await Task.Delay(500);

            Assert.NotNull(detected);
        }
        finally
        {
            monitor.StopMonitoring();
            Directory.Delete(tempDir, true);
        }
    }
}
