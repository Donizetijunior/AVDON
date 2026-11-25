using AntivirusOS.Core.Models;

namespace AntivirusOS.Core.Quarantine;

public interface IQuarantineManager
{
    Task<QuarantineEntry> QuarantineAsync(string filePath, string hash);
    Task RestoreAsync(QuarantineEntry entry);
    Task DeleteAsync(QuarantineEntry entry);
    Task<IReadOnlyList<QuarantineEntry>> ListAsync();
}
