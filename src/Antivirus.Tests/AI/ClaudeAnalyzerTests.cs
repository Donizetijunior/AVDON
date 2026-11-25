using AntivirusOS.Core.AI;
using Xunit;

namespace AntivirusOS.Tests.AI;

public class ClaudeAnalyzerTests
{
    [Fact]
    public async Task Analyze_NoApiKey_ReturnsUnavailable()
    {
        var analyzer = new ClaudeAnalyzer(apiKey: "");
        var result = await analyzer.AnalyzeFileAsync("C:\\file.exe", "abc");
        Assert.False(result.IsAvailable);
    }

    [Fact]
    public async Task Analyze_NullApiKey_ReturnsUnavailable()
    {
        var analyzer = new ClaudeAnalyzer(apiKey: null!);
        var result = await analyzer.AnalyzeFileAsync("C:\\file.exe", "abc");
        Assert.False(result.IsAvailable);
    }
}
