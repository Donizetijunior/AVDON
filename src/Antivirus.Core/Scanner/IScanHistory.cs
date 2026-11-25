using AntivirusOS.Core.Models;

namespace AntivirusOS.Core.Scanner;

public interface IScanHistory
{
    Task InitializeAsync();
    Task AddAsync(ScanResult result);
    Task<IReadOnlyList<ScanResult>> GetRecentAsync(int limit = 100);
}
