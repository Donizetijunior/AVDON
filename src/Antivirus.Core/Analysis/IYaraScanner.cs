namespace AntivirusOS.Core.Analysis;

public record YaraMatch(string RuleName, string Description);

public interface IYaraScanner
{
    void LoadRules(string rulesDirectory); // loads *.yar files
    Task<List<YaraMatch>> ScanAsync(string filePath);
}
