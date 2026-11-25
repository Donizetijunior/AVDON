using AntivirusOS.Core.Models;

namespace AntivirusOS.Core.Signatures;

public interface ISignatureDatabase
{
    Task InitializeAsync();
    Task AddSignatureAsync(ThreatInfo threat);
    Task<ThreatInfo?> LookupAsync(string sha256Hash);
    Task<int> CountAsync();
}
