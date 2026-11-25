using System.Text;
using AntivirusOS.Core.Models;

namespace AntivirusOS.Core.Reports;

public record ScanSummary(
    int Total,
    int Clean,
    int Suspicious,
    int Malicious,
    DateTime? FirstScan,
    DateTime? LastScan,
    string MostCommonThreat);

public class ScanReporter
{
    public async Task ExportToCsvAsync(IEnumerable<ScanResult> results, string outputPath)
    {
        await using var writer = new StreamWriter(outputPath, append: false, encoding: Encoding.UTF8);
        await writer.WriteLineAsync("FilePath,Hash,ThreatLevel,ThreatName,ScannedAt");

        foreach (var r in results)
        {
            var line = string.Join(',',
                CsvEscape(r.FilePath),
                CsvEscape(r.Hash),
                CsvEscape(r.Level.ToString()),
                CsvEscape(r.Threat?.Name ?? string.Empty),
                CsvEscape(r.ScannedAt.ToString("o")));
            await writer.WriteLineAsync(line);
        }
    }

    public ScanSummary GetSummary(IEnumerable<ScanResult> results)
    {
        var list = results.ToList();
        if (list.Count == 0)
            return new ScanSummary(0, 0, 0, 0, null, null, string.Empty);

        var clean      = list.Count(r => r.Level == ThreatLevel.Clean);
        var suspicious = list.Count(r => r.Level == ThreatLevel.Suspicious);
        var malicious  = list.Count(r => r.Level == ThreatLevel.Malicious);

        var mostCommon = list
            .Where(r => r.Threat != null)
            .GroupBy(r => r.Threat!.Name)
            .OrderByDescending(g => g.Count())
            .FirstOrDefault()?.Key ?? string.Empty;

        return new ScanSummary(
            list.Count,
            clean,
            suspicious,
            malicious,
            list.Min(r => r.ScannedAt),
            list.Max(r => r.ScannedAt),
            mostCommon);
    }

    // RFC 4180: wrap in quotes if field contains comma, quote or newline; escape quotes by doubling
    private static string CsvEscape(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
            return '"' + value.Replace("\"", "\"\"") + '"';
        return value;
    }
}
