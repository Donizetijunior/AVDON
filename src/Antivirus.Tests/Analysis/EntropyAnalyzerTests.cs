using AntivirusOS.Core.Analysis;

namespace Antivirus.Tests.Analysis;

public class EntropyAnalyzerTests
{
    [Fact]
    public async Task TextFile_HasLowEntropy()
    {
        var path = Path.GetTempFileName();
        try
        {
            // Repetitive text has low entropy
            await File.WriteAllTextAsync(path, new string('A', 10000));
            var analyzer = new EntropyAnalyzer();
            var entropy = await analyzer.ComputeAsync(path);
            Assert.True(entropy < 6.0, $"Expected entropy < 6.0 but got {entropy}");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task RandomBytesFile_HasHighEntropy()
    {
        var path = Path.GetTempFileName();
        try
        {
            var random = new Random(42);
            var bytes = new byte[65536];
            random.NextBytes(bytes);
            await File.WriteAllBytesAsync(path, bytes);

            var analyzer = new EntropyAnalyzer();
            var entropy = await analyzer.ComputeAsync(path);
            Assert.True(entropy > 7.5, $"Expected entropy > 7.5 but got {entropy}");
            Assert.True(analyzer.IsSuspicious(entropy));
        }
        finally { File.Delete(path); }
    }
}
