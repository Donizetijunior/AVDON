using AntivirusOS.Core.Models;
namespace AntivirusOS.Core.Scanner;

public interface IFileScanner
{
    Task<ScanResult> ScanFileAsync(string filePath);
    IAsyncEnumerable<ScanResult> ScanDirectoryAsync(string dirPath, bool recursive = true);
}
