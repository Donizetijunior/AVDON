using AntivirusOS.Core.Models;

namespace AntivirusOS.Core.Scanner;

public interface IArchiveScanner
{
    bool SupportsFile(string filePath); // .zip, .rar, .7z, .tar, .gz
    IAsyncEnumerable<ScanResult> ScanAsync(string filePath, IFileScanner innerScanner);
}
