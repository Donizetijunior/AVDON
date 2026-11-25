using AntivirusOS.Core.Quarantine;

namespace Antivirus.Tests.Quarantine;

public class QuarantineManagerTests
{
    [Fact]
    public async Task Quarantine_MovesFileAndDeletesOriginal()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        var quarDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        var manager = new QuarantineManager(quarDir);
        var original = Path.Combine(tempDir, "malware.exe");
        await File.WriteAllTextAsync(original, "malware content");

        var entry = await manager.QuarantineAsync(original, "aabbcc");

        Assert.False(File.Exists(original));
        Assert.True(File.Exists(entry.QuarantinePath));

        // cleanup
        Directory.Delete(quarDir, true);
        Directory.Delete(tempDir, true);
    }

    [Fact]
    public async Task ListAsync_ReturnsEntryAfterQuarantine()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        var quarDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        var manager = new QuarantineManager(quarDir);
        var original = Path.Combine(tempDir, "malware2.exe");
        await File.WriteAllTextAsync(original, "bad content");

        await manager.QuarantineAsync(original, "deadbeef");
        var list = await manager.ListAsync();

        Assert.Single(list);
        Assert.Equal("deadbeef", list[0].Hash);

        // cleanup
        Directory.Delete(quarDir, true);
        Directory.Delete(tempDir, true);
    }

    [Fact]
    public async Task RestoreAsync_MovesFileBackToOriginal()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        var quarDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        var manager = new QuarantineManager(quarDir);
        var original = Path.Combine(tempDir, "malware3.exe");
        await File.WriteAllTextAsync(original, "bad content again");

        var entry = await manager.QuarantineAsync(original, "cafebabe");
        await manager.RestoreAsync(entry);

        Assert.True(File.Exists(original));
        Assert.False(File.Exists(entry.QuarantinePath));

        var list = await manager.ListAsync();
        Assert.Empty(list);

        // cleanup
        Directory.Delete(quarDir, true);
        Directory.Delete(tempDir, true);
    }
}
