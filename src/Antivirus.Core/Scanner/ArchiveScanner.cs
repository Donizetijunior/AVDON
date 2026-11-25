using System.IO.Compression;
using AntivirusOS.Core.Models;

namespace AntivirusOS.Core.Scanner;

public class ArchiveScanner : IArchiveScanner
{
    private static readonly string[] SupportedExtensions = [".zip"];
    private const int MaxEntries = 100;
    private const long MaxEntryBytes = 50L * 1024 * 1024; // 50 MB

    public bool SupportsFile(string filePath)
    {
        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        return SupportedExtensions.Contains(ext);
    }

    public async IAsyncEnumerable<ScanResult> ScanAsync(string filePath, IFileScanner innerScanner)
    {
        ZipArchive archive;
        try
        {
            archive = ZipFile.OpenRead(filePath);
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
                if (string.IsNullOrEmpty(entry.Name)) continue; // directory entry
                if (count >= MaxEntries) break;
                if (entry.Length > MaxEntryBytes) continue;
                count++;

                var tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + Path.GetExtension(entry.Name));
                ScanResult? result = null;
                try
                {
                    entry.ExtractToFile(tempFile, overwrite: true);
                    var entryResult = await innerScanner.ScanFileAsync(tempFile);
                    result = entryResult with { FilePath = $"{filePath}!{entry.FullName}" };
                }
                catch
                {
                    // skip corrupt or inaccessible entries
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
