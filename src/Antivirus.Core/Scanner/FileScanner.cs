using AntivirusOS.Core.Models;
using AntivirusOS.Core.Signatures;

namespace AntivirusOS.Core.Scanner;

public class FileScanner : IFileScanner
{
    private readonly IHashAnalyzer _hashAnalyzer;
    private readonly ISignatureDatabase _signatureDatabase;

    public FileScanner(IHashAnalyzer hashAnalyzer, ISignatureDatabase signatureDatabase)
    {
        _hashAnalyzer = hashAnalyzer;
        _signatureDatabase = signatureDatabase;
    }

    public async Task<ScanResult> ScanFileAsync(string filePath)
    {
        var hash = await _hashAnalyzer.ComputeAsync(filePath);
        if (hash is null)
            return new ScanResult(filePath, string.Empty, ThreatLevel.Clean, null, DateTime.UtcNow);

        var threat = await _signatureDatabase.LookupAsync(hash);
        var level = threat?.Level ?? ThreatLevel.Clean;
        return new ScanResult(filePath, hash, level, threat, DateTime.UtcNow);
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
