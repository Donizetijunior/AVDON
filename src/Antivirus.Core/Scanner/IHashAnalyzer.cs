namespace AntivirusOS.Core.Scanner;

public interface IHashAnalyzer
{
    Task<string?> ComputeAsync(string filePath);
}
