namespace AntivirusOS.Core.AI;

public interface IClaudeAnalyzer
{
    Task<AnalysisResult> AnalyzeFileAsync(string filePath, string hash);
}
