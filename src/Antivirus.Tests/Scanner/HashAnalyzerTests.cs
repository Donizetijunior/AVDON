using AntivirusOS.Core.Scanner;

namespace Antivirus.Tests.Scanner;

public class HashAnalyzerTests
{
    [Fact]
    public async Task Compute_ValidFile_ReturnsSha256Hex()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "hello");
            var analyzer = new HashAnalyzer();
            var hash = await analyzer.ComputeAsync(path);
            Assert.NotNull(hash);
            Assert.Equal(64, hash.Length);
            // SHA256("hello") known value (without newline, UTF-8)
            Assert.StartsWith("2cf24dba", hash);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Compute_NonExistentFile_ReturnsNull()
    {
        var analyzer = new HashAnalyzer();
        var hash = await analyzer.ComputeAsync(@"C:\does_not_exist_xyz_av.exe");
        Assert.Null(hash);
    }
}
