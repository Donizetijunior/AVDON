using AntivirusOS.Core.Models;

namespace AntivirusOS.Core.Quarantine;

public sealed class QuarantineInspector
{
    public QuarantineFileInfo Inspect(QuarantineEntry entry)
    {
        if (!File.Exists(entry.QuarantinePath))
            return new QuarantineFileInfo(entry, 0, 0.0, Array.Empty<byte>(), "Arquivo não encontrado.");

        var info = new FileInfo(entry.QuarantinePath);
        byte[] preview = Array.Empty<byte>();
        double entropy = 0.0;

        try
        {
            using var fs = File.OpenRead(entry.QuarantinePath);
            int previewLen = (int)Math.Min(512, info.Length);
            preview = new byte[previewLen];
            _ = fs.Read(preview, 0, previewLen);

            // Shannon entropy over first 4KB (or whole file if smaller)
            int sampleLen = (int)Math.Min(4096, info.Length);
            byte[] sample = previewLen >= sampleLen ? preview[..sampleLen] : ReadSample(entry.QuarantinePath, sampleLen);
            entropy = ShannonEntropy(sample);
        }
        catch { }

        string note = entropy > 7.2 ? "Alta entropia — provável arquivo comprimido ou cifrado." : string.Empty;
        return new QuarantineFileInfo(entry, info.Length, entropy, preview, note);
    }

    private static byte[] ReadSample(string path, int len)
    {
        using var fs = File.OpenRead(path);
        var buf = new byte[len];
        fs.Read(buf, 0, len);
        return buf;
    }

    private static double ShannonEntropy(byte[] data)
    {
        if (data.Length == 0) return 0.0;
        int[] freq = new int[256];
        foreach (var b in data) freq[b]++;
        double entropy = 0.0;
        double len = data.Length;
        foreach (var f in freq)
        {
            if (f == 0) continue;
            double p = f / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}

public sealed class QuarantineFileInfo
{
    public QuarantineEntry Entry    { get; }
    public long   FileSize          { get; }
    public double Entropy           { get; }
    public byte[] PreviewBytes      { get; }
    public string Note              { get; }

    public string FileSizeDisplay =>
        FileSize < 1024 ? $"{FileSize} B"
        : FileSize < 1024 * 1024 ? $"{FileSize / 1024.0:F1} KB"
        : $"{FileSize / 1024.0 / 1024.0:F2} MB";

    public string EntropyDisplay => $"{Entropy:F2} / 8.00";

    public string HexPreview
    {
        get
        {
            if (PreviewBytes.Length == 0) return string.Empty;
            var lines = new System.Text.StringBuilder();
            int perRow = 16;
            for (int i = 0; i < Math.Min(PreviewBytes.Length, 128); i += perRow)
            {
                int end = Math.Min(i + perRow, PreviewBytes.Length);
                var hex  = string.Join(" ", PreviewBytes[i..end].Select(b => b.ToString("X2")));
                var ascii = new string(PreviewBytes[i..end].Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
                lines.AppendLine($"{i:X4}  {hex,-47}  {ascii}");
            }
            return lines.ToString();
        }
    }

    public QuarantineFileInfo(QuarantineEntry entry, long fileSize, double entropy, byte[] previewBytes, string note)
    {
        Entry        = entry;
        FileSize     = fileSize;
        Entropy      = entropy;
        PreviewBytes = previewBytes;
        Note         = note;
    }
}
