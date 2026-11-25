using AntivirusOS.Core.Models;
using AntivirusOS.Core.Scanner;
using AntivirusOS.Core.Signatures;
using Moq;
using Xunit;

namespace Antivirus.Tests.Scanner;

public class FileScannerTests
{
    [Fact]
    public async Task ScanFile_KnownMalicious_ReturnsMaliciousResult()
    {
        var hashMock = new Mock<IHashAnalyzer>();
        hashMock.Setup(h => h.ComputeAsync(It.IsAny<string>())).ReturnsAsync("deadbeef");
        var dbMock = new Mock<ISignatureDatabase>();
        var threat = new ThreatInfo("deadbeef", "Trojan.Test", ThreatLevel.Malicious, "test");
        dbMock.Setup(d => d.LookupAsync("deadbeef")).ReturnsAsync(threat);

        var scanner = new FileScanner(hashMock.Object, dbMock.Object);
        var result = await scanner.ScanFileAsync("C:\\evil.exe");

        Assert.Equal(ThreatLevel.Malicious, result.Level);
        Assert.NotNull(result.Threat);
    }

    [Fact]
    public async Task ScanFile_UnknownHash_ReturnsClean()
    {
        var hashMock = new Mock<IHashAnalyzer>();
        hashMock.Setup(h => h.ComputeAsync(It.IsAny<string>())).ReturnsAsync("aabbcc");
        var dbMock = new Mock<ISignatureDatabase>();
        dbMock.Setup(d => d.LookupAsync("aabbcc")).ReturnsAsync((ThreatInfo?)null);

        var scanner = new FileScanner(hashMock.Object, dbMock.Object);
        var result = await scanner.ScanFileAsync("C:\\clean.exe");

        Assert.Equal(ThreatLevel.Clean, result.Level);
    }
}
