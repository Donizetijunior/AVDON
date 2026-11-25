using System.Text.Json;
using AntivirusOS.Core.Models;

namespace AntivirusOS.Core.Quarantine;

public class QuarantineManager : IQuarantineManager
{
    private readonly string _quarantinePath;
    private readonly string _jsonPath;
    private static readonly JsonSerializerOptions _jsonOptions = new() { WriteIndented = true };

    public QuarantineManager(string? quarantinePath = null)
    {
        _quarantinePath = quarantinePath
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AntivirusOS", "Quarantine");
        _jsonPath = Path.Combine(_quarantinePath, "quarantine.json");
        Directory.CreateDirectory(_quarantinePath);
    }

    public async Task<QuarantineEntry> QuarantineAsync(string filePath, string hash)
    {
        var timestamp = DateTime.UtcNow;
        var fileName = $"{hash}_{timestamp:yyyyMMddHHmmssfff}.quar";
        var destPath = Path.Combine(_quarantinePath, fileName);

        File.Move(filePath, destPath);

        var entry = new QuarantineEntry(filePath, destPath, hash, timestamp);

        var entries = await ReadEntriesAsync();
        var updated = entries.ToList();
        updated.Add(entry);
        await WriteEntriesAsync(updated);

        return entry;
    }

    public async Task RestoreAsync(QuarantineEntry entry)
    {
        File.Move(entry.QuarantinePath, entry.OriginalPath);

        var entries = await ReadEntriesAsync();
        var updated = entries.Where(e => e.QuarantinePath != entry.QuarantinePath).ToList();
        await WriteEntriesAsync(updated);
    }

    public async Task DeleteAsync(QuarantineEntry entry)
    {
        if (File.Exists(entry.QuarantinePath))
            File.Delete(entry.QuarantinePath);

        var entries = await ReadEntriesAsync();
        var updated = entries.Where(e => e.QuarantinePath != entry.QuarantinePath).ToList();
        await WriteEntriesAsync(updated);
    }

    public async Task<IReadOnlyList<QuarantineEntry>> ListAsync()
    {
        return await ReadEntriesAsync();
    }

    private async Task<List<QuarantineEntry>> ReadEntriesAsync()
    {
        if (!File.Exists(_jsonPath))
            return new List<QuarantineEntry>();

        var json = await File.ReadAllTextAsync(_jsonPath);
        return JsonSerializer.Deserialize<List<QuarantineEntry>>(json, _jsonOptions) ?? new List<QuarantineEntry>();
    }

    private async Task WriteEntriesAsync(List<QuarantineEntry> entries)
    {
        var json = JsonSerializer.Serialize(entries, _jsonOptions);
        await File.WriteAllTextAsync(_jsonPath, json);
    }
}
