namespace AntivirusOS.Core.Analysis;

public class EntropyAnalyzer : IEntropyAnalyzer
{
    private const int MaxBytes = 1024 * 1024; // 1 MB
    private const double SuspiciousThreshold = 7.0;

    public async Task<double> ComputeAsync(string filePath)
    {
        try
        {
            var counts = new long[256];
            long total = 0;

            await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, useAsync: true);
            var buffer = new byte[4096];
            int read;
            while (total < MaxBytes && (read = await stream.ReadAsync(buffer)) > 0)
            {
                var toProcess = (int)Math.Min(read, MaxBytes - total);
                for (int i = 0; i < toProcess; i++)
                    counts[buffer[i]]++;
                total += toProcess;
            }

            if (total == 0) return 0.0;

            double entropy = 0.0;
            for (int b = 0; b < 256; b++)
            {
                if (counts[b] == 0) continue;
                double p = (double)counts[b] / total;
                entropy -= p * Math.Log2(p);
            }

            return entropy;
        }
        catch (IOException) { return 0.0; }
        catch (UnauthorizedAccessException) { return 0.0; }
    }

    public bool IsSuspicious(double entropy) => entropy > SuspiciousThreshold;
}
