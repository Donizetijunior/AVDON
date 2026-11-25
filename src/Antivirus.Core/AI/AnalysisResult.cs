using AntivirusOS.Core.Models;
namespace AntivirusOS.Core.AI;

public record AnalysisResult(bool IsAvailable, bool IsSuspicious, string Reasoning, ThreatLevel SuggestedLevel);
