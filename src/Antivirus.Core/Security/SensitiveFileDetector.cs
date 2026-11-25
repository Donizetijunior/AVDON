using System.Runtime.Versioning;

namespace AntivirusOS.Core.Security;

public enum SensitiveFileRisk { Low, Medium, High }

public sealed record SensitiveFileResult(
    string FilePath,
    string MatchedPattern,
    SensitiveFileRisk Risk,
    long SizeKB);

[SupportedOSPlatform("windows")]
public sealed class SensitiveFileDetector
{
    private static readonly (string pattern, SensitiveFileRisk risk, string label)[] _patterns =
    [
        ("id_rsa",          SensitiveFileRisk.High,   "Chave SSH privada"),
        ("id_dsa",          SensitiveFileRisk.High,   "Chave SSH privada"),
        ("id_ecdsa",        SensitiveFileRisk.High,   "Chave SSH privada"),
        ("id_ed25519",      SensitiveFileRisk.High,   "Chave SSH privada"),
        ("*.pem",           SensitiveFileRisk.High,   "Certificado PEM"),
        ("*.pfx",           SensitiveFileRisk.High,   "Certificado PFX"),
        ("*.p12",           SensitiveFileRisk.High,   "Certificado P12"),
        ("*.key",           SensitiveFileRisk.High,   "Arquivo de chave"),
        (".env",            SensitiveFileRisk.High,   "Variáveis de ambiente (.env)"),
        ("*.env",           SensitiveFileRisk.High,   "Variáveis de ambiente"),
        ("password*.*",     SensitiveFileRisk.High,   "Arquivo de senhas"),
        ("passwords*.*",    SensitiveFileRisk.High,   "Arquivo de senhas"),
        ("credentials*.*",  SensitiveFileRisk.High,   "Credenciais"),
        ("secret*.*",       SensitiveFileRisk.Medium, "Segredos"),
        ("*.kdbx",          SensitiveFileRisk.Medium, "Banco de dados KeePass"),
        ("wallet.dat",      SensitiveFileRisk.High,   "Carteira Bitcoin"),
        ("*.wallet",        SensitiveFileRisk.High,   "Arquivo de carteira crypto"),
        ("token*.*",        SensitiveFileRisk.Medium, "Token de acesso"),
        ("apikey*.*",       SensitiveFileRisk.Medium, "Chave de API"),
        ("api_key*.*",      SensitiveFileRisk.Medium, "Chave de API"),
        ("private*key*.*",  SensitiveFileRisk.High,   "Chave privada"),
    ];

    private static readonly string[] _searchRoots;

    static SensitiveFileDetector()
    {
        var home    = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var docs    = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var downloads = Path.Combine(home, "Downloads");
        _searchRoots = [home, desktop, docs, downloads,
            Path.Combine(home, ".ssh"),
            Path.Combine(home, ".aws"),
            Path.Combine(home, ".config")];
    }

    public async Task<IReadOnlyList<SensitiveFileResult>> ScanAsync(
        CancellationToken ct = default)
    {
        var results = new List<SensitiveFileResult>();

        await Task.Run(() =>
        {
            foreach (var root in _searchRoots.Where(Directory.Exists).Distinct())
            {
                try
                {
                    // Depth-limited search (3 levels) to keep it fast
                    ScanDir(root, 0, results, ct);
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }, ct);

        return results.DistinctBy(r => r.FilePath.ToLowerInvariant()).ToList();
    }

    private static void ScanDir(string dir, int depth, List<SensitiveFileResult> results,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (depth > 3) return;

        try
        {
            foreach (var file in Directory.GetFiles(dir))
            {
                ct.ThrowIfCancellationRequested();
                var name = Path.GetFileName(file).ToLowerInvariant();
                foreach (var (pattern, risk, label) in _patterns)
                {
                    if (MatchesPattern(name, pattern.ToLowerInvariant()))
                    {
                        long sizeKb = 0;
                        try { sizeKb = new FileInfo(file).Length / 1024; } catch { }
                        results.Add(new SensitiveFileResult(file, label, risk, sizeKb));
                        break;
                    }
                }
            }

            foreach (var sub in Directory.GetDirectories(dir))
            {
                try { ScanDir(sub, depth + 1, results, ct); }
                catch { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private static bool MatchesPattern(string name, string pattern)
    {
        if (!pattern.Contains('*'))
            return name == pattern || name.EndsWith(pattern);

        // Simple glob: prefix*suffix or *ext
        var parts = pattern.Split('*', 2);
        if (parts.Length != 2) return name.Contains(pattern.TrimStart('*').TrimEnd('*'));
        return name.StartsWith(parts[0]) && name.EndsWith(parts[1]);
    }
}
