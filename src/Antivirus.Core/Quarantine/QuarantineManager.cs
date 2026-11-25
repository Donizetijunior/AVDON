using System.Text.Json;
using AntivirusOS.Core.Models;

namespace AntivirusOS.Core.Quarantine;

public class QuarantineManager : IQuarantineManager
{
    private readonly string _quarantinePath;
    private readonly string _jsonPath;
    private static readonly JsonSerializerOptions _jsonOptions = new() { WriteIndented = true };
    private readonly SemaphoreSlim _jsonLock = new(1, 1);

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

        await _jsonLock.WaitAsync();
        try
        {
            var entries = await ReadEntriesAsync();
            var updated = entries.ToList();
            updated.Add(entry);
            await WriteEntriesAsync(updated);
        }
        finally
        {
            _jsonLock.Release();
        }

        return entry;
    }

    public async Task RestoreAsync(QuarantineEntry entry)
    {
        File.Move(entry.QuarantinePath, entry.OriginalPath);

        await _jsonLock.WaitAsync();
        try
        {
            var entries = await ReadEntriesAsync();
            var updated = entries.Where(e => e.QuarantinePath != entry.QuarantinePath).ToList();
            await WriteEntriesAsync(updated);
        }
        finally
        {
            _jsonLock.Release();
        }
    }

    public async Task DeleteAsync(QuarantineEntry entry)
    {
        if (File.Exists(entry.QuarantinePath))
            File.Delete(entry.QuarantinePath);

        await _jsonLock.WaitAsync();
        try
        {
            var entries = await ReadEntriesAsync();
            var updated = entries.Where(e => e.QuarantinePath != entry.QuarantinePath).ToList();
            await WriteEntriesAsync(updated);
        }
        finally
        {
            _jsonLock.Release();
        }
    }

    public async Task<IReadOnlyList<QuarantineEntry>> ListAsync()
    {
        await _jsonLock.WaitAsync();
        try
        {
            return await ReadEntriesAsync();
        }
        finally
        {
            _jsonLock.Release();
        }
    }

    private async Task<List<QuarantineEntry>> ReadEntriesAsync()
    {
        if (!File.Exists(_jsonPath))
            return new List<QuarantineEntry>();

        var json = await File.ReadAllTextAsync(_jsonPath);
        try
        {
            return JsonSerializer.Deserialize<List<QuarantineEntry>>(json, _jsonOptions) ?? new List<QuarantineEntry>();
        }
        catch (JsonException)
        {
            return new List<QuarantineEntry>();
        }
    }

    private async Task WriteEntriesAsync(List<QuarantineEntry> entries)
    {
        var json = JsonSerializer.Serialize(entries, _jsonOptions);
        var tempPath = _jsonPath + ".tmp";
        await File.WriteAllTextAsync(tempPath, json);
        File.Move(tempPath, _jsonPath, overwrite: true);
    }
}
