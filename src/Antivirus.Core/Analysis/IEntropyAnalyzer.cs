namespace AntivirusOS.Core.Analysis;

public interface IEntropyAnalyzer
{
    Task<double> ComputeAsync(string filePath); // Shannon entropy 0.0–8.0
    bool IsSuspicious(double entropy);           // true if > 7.0
}
