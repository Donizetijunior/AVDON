using AntivirusOS.Core.Models;

namespace AntivirusOS.Core.Scanner;

public interface IScanCache
{
    Task<ScanResult?> GetAsync(string filePath);
    Task SetAsync(ScanResult result, long fileSize, DateTime lastModified);
    Task InvalidateAsync(string filePath);
}
