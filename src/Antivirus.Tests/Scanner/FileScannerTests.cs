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

    [Fact]
    public async Task ScanFile_NullHash_ReturnsCleanWithEmptyHash()
    {
        var hashMock = new Mock<IHashAnalyzer>();
        hashMock.Setup(h => h.ComputeAsync(It.IsAny<string>())).ReturnsAsync((string?)null);
        var dbMock = new Mock<ISignatureDatabase>();

        var scanner = new FileScanner(hashMock.Object, dbMock.Object);
        var result = await scanner.ScanFileAsync("C:\\locked.exe");

        Assert.Equal(ThreatLevel.Clean, result.Level);
        Assert.Equal(string.Empty, result.Hash);
        dbMock.Verify(d => d.LookupAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task ScanDirectory_ReturnsResultsForEachFile()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(tempDir, "a.txt"), "a");
            await File.WriteAllTextAsync(Path.Combine(tempDir, "b.txt"), "b");

            var hashMock = new Mock<IHashAnalyzer>();
            hashMock.Setup(h => h.ComputeAsync(It.IsAny<string>())).ReturnsAsync("aabbcc");
            var dbMock = new Mock<ISignatureDatabase>();
            dbMock.Setup(d => d.LookupAsync(It.IsAny<string>())).ReturnsAsync((ThreatInfo?)null);

            var scanner = new FileScanner(hashMock.Object, dbMock.Object);
            var results = new List<ScanResult>();
            await foreach (var r in scanner.ScanDirectoryAsync(tempDir, recursive: false))
                results.Add(r);

            Assert.Equal(2, results.Count);
            Assert.All(results, r => Assert.Equal(ThreatLevel.Clean, r.Level));
        }
        finally
        {
            Directory.Delete(tempDir, true);
        }
    }
}
