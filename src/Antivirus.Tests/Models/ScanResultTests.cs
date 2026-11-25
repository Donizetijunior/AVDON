using AntivirusOS.Core.Models;
using Xunit;

namespace Antivirus.Tests.Models;

public class ScanResultTests
{
    [Fact]
    public void ScanResult_Clean_HasNullThreat()
    {
        var r = new ScanResult("C:\\file.exe", "abc123", ThreatLevel.Clean, null, DateTime.UtcNow);
        Assert.Null(r.Threat);
        Assert.Equal(ThreatLevel.Clean, r.Level);
    }

    [Fact]
    public void ScanResult_Malicious_HasThreatInfo()
    {
        var threat = new ThreatInfo("abc123", "Trojan.GenericKD", ThreatLevel.Malicious, "Known trojan");
        var r = new ScanResult("C:\\evil.exe", "abc123", ThreatLevel.Malicious, threat, DateTime.UtcNow);
        Assert.NotNull(r.Threat);
        Assert.Equal("Trojan.GenericKD", r.Threat.Name);
    }
}
