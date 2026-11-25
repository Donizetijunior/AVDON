namespace AntivirusOS.Core.Updater;

public interface ISignatureUpdater
{
    /// <summary>
    /// Downloads and imports signatures from MalwareBazaar CSV export.
    /// Returns the number of signatures added.
    /// </summary>
    Task<int> UpdateFromMalwareBazaarAsync(CancellationToken cancellationToken = default);
}
