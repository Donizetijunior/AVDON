using System.Text.Json;

namespace AntivirusOS.Core.Scheduler;

public sealed class ScheduledScanConfig
{
    public bool Enabled { get; set; } = false;
    public int IntervalHours { get; set; } = 24;
    public List<string> ScanPaths { get; set; } = new();
    public DateTime? LastRun { get; set; }
    public DateTime? NextRun { get; set; }

    private static string ConfigPath(string appDataPath) =>
        Path.Combine(appDataPath, "schedule.json");

    public static ScheduledScanConfig Load(string appDataPath)
    {
        var path = ConfigPath(appDataPath);
        try
        {
            if (File.Exists(path))
            {
                var json = File.ReadAllText(path);
                return JsonSerializer.Deserialize<ScheduledScanConfig>(json)
                       ?? new ScheduledScanConfig();
            }
        }
        catch { }
        return new ScheduledScanConfig();
    }

    public void Save(string appDataPath)
    {
        try
        {
            var path = ConfigPath(appDataPath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json);
        }
        catch { }
    }
}
