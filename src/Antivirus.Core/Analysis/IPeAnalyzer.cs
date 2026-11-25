namespace AntivirusOS.Core.Analysis;

public record PeAnalysisResult(bool IsPe, bool IsSuspicious, List<string> Indicators);

public interface IPeAnalyzer
{
    Task<PeAnalysisResult> AnalyzeAsync(string filePath);
}
