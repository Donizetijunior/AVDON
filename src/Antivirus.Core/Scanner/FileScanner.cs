using AntivirusOS.Core.Analysis;
using AntivirusOS.Core.Models;
using AntivirusOS.Core.Signatures;

namespace AntivirusOS.Core.Scanner;

public class FileScanner : IFileScanner
{
    private readonly IHashAnalyzer _hashAnalyzer;
    private readonly ISignatureDatabase _signatureDatabase;
    private readonly IEntropyAnalyzer? _entropyAnalyzer;
    private readonly IPeAnalyzer? _peAnalyzer;
    private readonly IYaraScanner? _yaraScanner;
    private readonly IAuthenticodeChecker? _authenticodeChecker;
    private readonly IScanCache? _scanCache;

    public FileScanner(
        IHashAnalyzer hashAnalyzer,
        ISignatureDatabase signatureDatabase,
        IEntropyAnalyzer? entropyAnalyzer = null,
        IPeAnalyzer? peAnalyzer = null,
        IYaraScanner? yaraScanner = null,
        IAuthenticodeChecker? authenticodeChecker = null,
        IScanCache? scanCache = null)
    {
        _hashAnalyzer = hashAnalyzer;
        _signatureDatabase = signatureDatabase;
        _entropyAnalyzer = entropyAnalyzer;
        _peAnalyzer = peAnalyzer;
        _yaraScanner = yaraScanner;
        _authenticodeChecker = authenticodeChecker;
        _scanCache = scanCache;
    }

    public async Task<ScanResult> ScanFileAsync(string filePath)
    {
        // T7: Check cache first
        if (_scanCache != null)
        {
            var cached = await _scanCache.GetAsync(filePath);
            if (cached != null) return cached;
        }

        // T5: If trusted signed, skip deeper analysis
        if (_authenticodeChecker != null && _authenticodeChecker.IsTrustedSigned(filePath))
        {
            var cleanResult = new ScanResult(filePath, string.Empty, ThreatLevel.Clean, null, DateTime.UtcNow);
            if (_scanCache != null)
            {
                try
                {
                    var fi = new FileInfo(filePath);
                    await _scanCache.SetAsync(cleanResult, fi.Length, fi.LastWriteTimeUtc);
                }
                catch { }
            }
            return cleanResult;
        }

        var hash = await _hashAnalyzer.ComputeAsync(filePath);
        if (hash is null)
            return new ScanResult(filePath, string.Empty, ThreatLevel.Clean, null, DateTime.UtcNow);

        var threat = await _signatureDatabase.LookupAsync(hash);
        var level = threat?.Level ?? ThreatLevel.Clean;
        ThreatInfo? resolvedThreat = threat;

        // T4: YARA scan — if match, escalate to Malicious
        if (_yaraScanner != null && level != ThreatLevel.Malicious)
        {
            var yaraMatches = await _yaraScanner.ScanAsync(filePath);
            if (yaraMatches.Count > 0)
            {
                level = ThreatLevel.Malicious;
                var first = yaraMatches[0];
                resolvedThreat = new ThreatInfo(hash, first.RuleName, ThreatLevel.Malicious, first.Description);
            }
        }

        // T1 & T2: entropy and PE analysis only if still Clean
        if (level == ThreatLevel.Clean)
        {
            // T1: Entropy
            if (_entropyAnalyzer != null)
            {
                var entropy = await _entropyAnalyzer.ComputeAsync(filePath);
                if (_entropyAnalyzer.IsSuspicious(entropy))
                {
                    level = ThreatLevel.Suspicious;
                    resolvedThreat = new ThreatInfo(hash, "High Entropy File", ThreatLevel.Suspicious, $"Entropy: {entropy:F2}");
                }
            }

            // T2: PE analysis
            if (_peAnalyzer != null && level == ThreatLevel.Clean)
            {
                var peResult = await _peAnalyzer.AnalyzeAsync(filePath);
                if (peResult.IsSuspicious)
                {
                    level = ThreatLevel.Suspicious;
                    var indicators = string.Join(", ", peResult.Indicators);
                    resolvedThreat = new ThreatInfo(hash, "Suspicious PE", ThreatLevel.Suspicious, indicators);
                }
            }
        }

        var result = new ScanResult(filePath, hash, level, resolvedThreat, DateTime.UtcNow);

        // T7: Store in cache
        if (_scanCache != null)
        {
            try
            {
                var fi = new FileInfo(filePath);
                if (fi.Exists)
                    await _scanCache.SetAsync(result, fi.Length, fi.LastWriteTimeUtc);
            }
            catch { }
        }

        return result;
    }

    public async IAsyncEnumerable<ScanResult> ScanDirectoryAsync(string dirPath, bool recursive = true)
    {
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = recursive,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.System | FileAttributes.ReparsePoint
        };
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(dirPath, "*", options);
        }
        catch (UnauthorizedAccessException)
        {
            yield break;
        }

        foreach (var file in files)
        {
            ScanResult result;
            try
            {
                result = await ScanFileAsync(file);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }
            yield return result;
        }
    }
}
