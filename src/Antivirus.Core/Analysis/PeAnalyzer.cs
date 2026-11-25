using System.Text;

namespace AntivirusOS.Core.Analysis;

public class PeAnalyzer : IPeAnalyzer
{
    private const int MaxBytes = 2 * 1024 * 1024; // 2 MB

    private static readonly string[] SuspiciousSectionNames = ["UPX0", "UPX1", ".themida", ".vmp0"];
    private static readonly string[] SuspiciousImports =
    [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection"
    ];

    public async Task<PeAnalysisResult> AnalyzeAsync(string filePath)
    {
        try
        {
            byte[] data;
            await using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, useAsync: true))
            {
                var size = (int)Math.Min(stream.Length, MaxBytes);
                data = new byte[size];
                int offset = 0;
                while (offset < size)
                {
                    int read = await stream.ReadAsync(data.AsMemory(offset, size - offset));
                    if (read == 0) break;
                    offset += read;
                }
            }

            if (data.Length < 2 || data[0] != 0x4D || data[1] != 0x5A)
                return new PeAnalysisResult(false, false, []);

            var indicators = new List<string>();
            var text = Encoding.ASCII.GetString(data);

            foreach (var section in SuspiciousSectionNames)
            {
                if (text.Contains(section, StringComparison.Ordinal))
                    indicators.Add($"Suspicious section: {section}");
            }

            foreach (var import in SuspiciousImports)
            {
                if (text.Contains(import, StringComparison.Ordinal))
                    indicators.Add($"Suspicious import: {import}");
            }

            return new PeAnalysisResult(true, indicators.Count >= 2, indicators);
        }
        catch (IOException) { return new PeAnalysisResult(false, false, []); }
        catch (UnauthorizedAccessException) { return new PeAnalysisResult(false, false, []); }
    }
}
