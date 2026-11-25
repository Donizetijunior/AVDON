using System.IO;
using System.Text.Json;

namespace Antivirus.UI.Properties;

/// <summary>Simple JSON-backed settings store (no designer dependency).</summary>
public sealed class Settings
{
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "AntivirusOS", "settings.json");

    private static Settings? _default;
    public static Settings Default => _default ??= Load();

    public string? ClaudeApiKey { get; set; }

    private static Settings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                return JsonSerializer.Deserialize<Settings>(json) ?? new Settings();
            }
        }
        catch { /* ignore */ }
        return new Settings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(SettingsPath, json);
        }
        catch { /* ignore */ }
    }
}
