using AntivirusOS.Core.Models;
using SharpCompress.Archives;

namespace AntivirusOS.Core.Scanner;

public class ArchiveScanner : IArchiveScanner
{
    private static readonly string[] SupportedExtensions = [".zip", ".rar", ".7z", ".tar", ".gz"];
    private const int MaxEntries = 100;
    private const long MaxEntryBytes = 50L * 1024 * 1024; // 50 MB

    public bool SupportsFile(string filePath)
    {
        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        return SupportedExtensions.Contains(ext);
    }

    public async IAsyncEnumerable<ScanResult> ScanAsync(string filePath, IFileScanner innerScanner)
    {
        IArchive archive;
        try
        {
            archive = ArchiveFactory.Open(filePath);
        }
        catch
        {
            yield break;
        }

        using (archive)
        {
            int count = 0;
            foreach (var entry in archive.Entries)
            {
                if (entry.IsDirectory) continue;
                if (count >= MaxEntries) break;
                if (entry.Size > MaxEntryBytes) continue;
                count++;

                var tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + Path.GetExtension(entry.Key ?? ""));
                ScanResult? result = null;
                try
                {
                    await using (var fs = new FileStream(tempFile, FileMode.Create, FileAccess.Write, FileShare.None))
                        entry.WriteTo(fs);

                    var entryResult = await innerScanner.ScanFileAsync(tempFile);
                    var entryPath = $"{filePath}!{entry.Key}";
                    result = entryResult with { FilePath = entryPath };
                }
                catch
                {
                    // skip corrupt/encrypted entries
                }
                finally
                {
                    try { File.Delete(tempFile); } catch { }
                }

                if (result != null)
                    yield return result;
            }
        }
    }
}
