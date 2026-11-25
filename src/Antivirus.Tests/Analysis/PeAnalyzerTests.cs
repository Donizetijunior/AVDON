using AntivirusOS.Core.Analysis;

namespace Antivirus.Tests.Analysis;

public class PeAnalyzerTests
{
    [Fact]
    public async Task TextFile_IsNotPe()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "This is a plain text file, not a PE.");
            var analyzer = new PeAnalyzer();
            var result = await analyzer.AnalyzeAsync(path);
            Assert.False(result.IsPe);
            Assert.False(result.IsSuspicious);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task MzHeader_IsPe()
    {
        var path = Path.GetTempFileName();
        try
        {
            // Write MZ header followed by padding
            var data = new byte[512];
            data[0] = 0x4D; // M
            data[1] = 0x5A; // Z
            await File.WriteAllBytesAsync(path, data);

            var analyzer = new PeAnalyzer();
            var result = await analyzer.AnalyzeAsync(path);
            Assert.True(result.IsPe);
        }
        finally { File.Delete(path); }
    }
}
