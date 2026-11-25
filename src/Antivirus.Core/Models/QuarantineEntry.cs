namespace AntivirusOS.Core.Models;

public record QuarantineEntry(string OriginalPath, string QuarantinePath, string Hash, DateTime QuarantinedAt);
