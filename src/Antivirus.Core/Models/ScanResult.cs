namespace AntivirusOS.Core.Models;

public record ScanResult(string FilePath, string Hash, ThreatLevel Level, ThreatInfo? Threat, DateTime ScannedAt);
