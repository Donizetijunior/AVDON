using AntivirusOS.Core.Models;
using AntivirusOS.Core.Scanner;
using Moq;
using System.IO.Compression;

namespace Antivirus.Tests.Scanner;

public class ArchiveScannerTests
{
    [Fact]
    public async Task ZipWithTextFile_ReturnsResult()
    {
        // Create an in-memory ZIP with one text file
        var zipPath = Path.GetTempFileName() + ".zip";
        try
        {
            using (var fs = new FileStream(zipPath, FileMode.Create))
            using (var zip = new ZipArchive(fs, ZipArchiveMode.Create))
            {
                var entry = zip.CreateEntry("hello.txt");
                await using var entryStream = entry.Open();
                var bytes = System.Text.Encoding.UTF8.GetBytes("Hello World");
                await entryStream.WriteAsync(bytes);
            }

            var scannerMock = new Mock<IFileScanner>();
            scannerMock.Setup(s => s.ScanFileAsync(It.IsAny<string>()))
                .ReturnsAsync((string p) => new ScanResult(p, "abc123", ThreatLevel.Clean, null, DateTime.UtcNow));

            var archiveScanner = new ArchiveScanner();
            Assert.True(archiveScanner.SupportsFile(zipPath));

            var results = new List<ScanResult>();
            await foreach (var r in archiveScanner.ScanAsync(zipPath, scannerMock.Object))
                results.Add(r);

            Assert.Single(results);
            Assert.Contains("hello.txt", results[0].FilePath);
        }
        finally
        {
            if (File.Exists(zipPath)) File.Delete(zipPath);
        }
    }
}
