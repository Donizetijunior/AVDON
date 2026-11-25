using System.Text.Json;

namespace AntivirusOS.Core.Settings;

public sealed class AppSettings
{
    public bool  AutoQuarantine          { get; set; } = true;
    public bool  NotifyOnThreat          { get; set; } = true;
    public bool  NotifyOnScheduledScan   { get; set; } = true;
    public bool  ScanArchives            { get; set; } = false;
    public int   MaxFileSizeMB           { get; set; } = 50;
    public List<string> ExclusionPaths   { get; set; } = new();

    private static readonly JsonSerializerOptions _opts = new() { WriteIndented = true };

    public static AppSettings Load(string appDataPath)
    {
        var path = FilePath(appDataPath);
        if (!File.Exists(path)) return new AppSettings();
        try
        {
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
        }
        catch { return new AppSettings(); }
    }

    public void Save(string appDataPath)
    {
        Directory.CreateDirectory(appDataPath);
        File.WriteAllText(FilePath(appDataPath), JsonSerializer.Serialize(this, _opts));
    }

    private static string FilePath(string appDataPath) =>
        Path.Combine(appDataPath, "settings.json");
}
