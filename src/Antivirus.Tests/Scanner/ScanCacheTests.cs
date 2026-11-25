using AntivirusOS.Core.Models;
using AntivirusOS.Core.Scanner;

namespace Antivirus.Tests.Scanner;

public class ScanCacheTests
{
    [Fact]
    public async Task NewFile_CacheMiss()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".db");
        try
        {
            var cache = new ScanCache(dbPath);
            var tempFile = Path.GetTempFileName();
            try
            {
                await File.WriteAllTextAsync(tempFile, "some content");
                var result = await cache.GetAsync(tempFile);
                Assert.Null(result);
            }
            finally { File.Delete(tempFile); }
        }
        finally { if (File.Exists(dbPath)) File.Delete(dbPath); }
    }

    [Fact]
    public async Task SameFile_CacheHit()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".db");
        try
        {
            var cache = new ScanCache(dbPath);
            var tempFile = Path.GetTempFileName();
            try
            {
                await File.WriteAllTextAsync(tempFile, "stable content");
                var fi = new FileInfo(tempFile);

                var stored = new ScanResult(tempFile, "deadbeef", ThreatLevel.Clean, null, DateTime.UtcNow);
                await cache.SetAsync(stored, fi.Length, fi.LastWriteTimeUtc);

                var hit = await cache.GetAsync(tempFile);
                Assert.NotNull(hit);
                Assert.Equal("deadbeef", hit.Hash);
                Assert.Equal(ThreatLevel.Clean, hit.Level);
            }
            finally { File.Delete(tempFile); }
        }
        finally { if (File.Exists(dbPath)) File.Delete(dbPath); }
    }
}
