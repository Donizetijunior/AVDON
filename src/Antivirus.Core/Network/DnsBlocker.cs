namespace AntivirusOS.Core.Network;

/// <summary>
/// Blocks malicious domains by writing entries to the Windows hosts file.
/// Requires the process to run as administrator, or uses a fallback warning.
/// </summary>
public class DnsBlocker
{
    private static readonly string HostsPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            @"drivers\etc\hosts");

    private const string BlockMarkerStart = "# AVDON_BLOCK_START";
    private const string BlockMarkerEnd   = "# AVDON_BLOCK_END";

    // Built-in block list — well-known malware C2 / phishing domains
    public static readonly string[] DefaultBlockList =
    [
        // Malware C2 / known bad actors (generic examples; real deployments use threat feeds)
        "malware-c2.example.com",
        "phishing-site.example.com",
        // Common ad/tracking abuse domains (a few representative examples)
        "tracker.malware.example",
        // Miner pools (generic)
        "xmr.pool.minergate.com",
        "cryptonote.social",
        "pool.minexmr.com",
        "pool.supportxmr.com",
        "xmrpool.eu",
        "monerohash.com",
        "hashvault.pro",
        // Known phishing kit hosts (generic examples)
        "phish-host.example.net",
    ];

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public bool IsAdministrator()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    public List<string> GetCurrentBlockedDomains()
    {
        var blocked = new List<string>();
        try
        {
            var lines = File.ReadAllLines(HostsPath);
            bool inBlock = false;
            foreach (var line in lines)
            {
                if (line.TrimStart().StartsWith(BlockMarkerStart)) { inBlock = true; continue; }
                if (line.TrimStart().StartsWith(BlockMarkerEnd))   { inBlock = false; continue; }
                if (inBlock && !string.IsNullOrWhiteSpace(line) && !line.StartsWith('#'))
                {
                    var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2) blocked.Add(parts[1]);
                }
            }
        }
        catch { }
        return blocked;
    }

    public async Task<(bool success, string message)> ApplyBlockListAsync(IEnumerable<string> domains)
    {
        if (!IsAdministrator())
            return (false, "AVDON precisa de privilégios de administrador para editar o arquivo hosts.");

        try
        {
            var allLines = (await File.ReadAllLinesAsync(HostsPath)).ToList();

            // Remove existing AVDON block
            RemoveBlock(allLines);

            // Add new block
            allLines.Add(string.Empty);
            allLines.Add(BlockMarkerStart);
            foreach (var domain in domains.Distinct())
                allLines.Add($"0.0.0.0 {domain}");
            allLines.Add(BlockMarkerEnd);

            await File.WriteAllLinesAsync(HostsPath, allLines);
            return (true, $"{domains.Count()} domínio(s) bloqueado(s) com sucesso.");
        }
        catch (UnauthorizedAccessException)
        {
            return (false, "Acesso negado ao arquivo hosts. Execute o AVDON como administrador.");
        }
        catch (Exception ex)
        {
            return (false, $"Erro: {ex.Message}");
        }
    }

    public async Task<(bool success, string message)> ClearBlockListAsync()
    {
        if (!IsAdministrator())
            return (false, "AVDON precisa de privilégios de administrador para editar o arquivo hosts.");

        try
        {
            var allLines = (await File.ReadAllLinesAsync(HostsPath)).ToList();
            RemoveBlock(allLines);
            await File.WriteAllLinesAsync(HostsPath, allLines);
            return (true, "Bloqueio DNS removido com sucesso.");
        }
        catch (Exception ex)
        {
            return (false, $"Erro: {ex.Message}");
        }
    }

    private static void RemoveBlock(List<string> lines)
    {
        int start = -1, end = -1;
        for (int i = 0; i < lines.Count; i++)
        {
            if (lines[i].TrimStart().StartsWith(BlockMarkerStart)) start = i;
            if (lines[i].TrimStart().StartsWith(BlockMarkerEnd))   end   = i;
        }
        if (start >= 0 && end >= start)
            lines.RemoveRange(start > 0 ? start - 1 : start, end - start + 2);
    }
}
