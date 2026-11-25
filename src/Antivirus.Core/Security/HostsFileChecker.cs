using System.Runtime.Versioning;

namespace AntivirusOS.Core.Security;

public enum HostsEntryRisk { Normal, Suspicious, Malicious }

public sealed record HostsEntry(
    string IP,
    string Hostname,
    HostsEntryRisk Risk,
    string Reason);

[SupportedOSPlatform("windows")]
public sealed class HostsFileChecker
{
    private const string HostsPath = @"C:\Windows\System32\drivers\etc\hosts";

    // Well-known domains that should never be redirected
    private static readonly HashSet<string> _protectedDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "google.com", "www.google.com",
        "microsoft.com", "www.microsoft.com", "windowsupdate.com",
        "apple.com", "icloud.com",
        "github.com", "raw.githubusercontent.com",
        "paypal.com", "www.paypal.com",
        "amazon.com", "aws.amazon.com",
        "facebook.com", "instagram.com", "twitter.com", "x.com",
        "bank.com", "chase.com", "wellsfargo.com",
        "virustotal.com", "malwarebytes.com", "avast.com", "avg.com",
        "defender.microsoft.com", "update.microsoft.com",
    };

    public async Task<IReadOnlyList<HostsEntry>> AnalyzeAsync(CancellationToken ct = default)
    {
        var results = new List<HostsEntry>();
        if (!File.Exists(HostsPath))
        {
            results.Add(new HostsEntry("—", "—", HostsEntryRisk.Suspicious,
                "Arquivo hosts não encontrado!"));
            return results;
        }

        var lines = await File.ReadAllLinesAsync(HostsPath, ct);
        foreach (var raw in lines)
        {
            ct.ThrowIfCancellationRequested();
            var line = raw.Trim();
            if (string.IsNullOrEmpty(line) || line.StartsWith('#')) continue;

            // Remove inline comments
            var commentIdx = line.IndexOf('#');
            if (commentIdx > 0) line = line[..commentIdx].Trim();

            var parts = line.Split((char[])null!, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;

            var ip       = parts[0];
            var hostname = parts[1].ToLowerInvariant();
            var (risk, reason) = Classify(ip, hostname);
            results.Add(new HostsEntry(ip, hostname, risk, reason));
        }

        return results;
    }

    private static (HostsEntryRisk risk, string reason) Classify(string ip, string hostname)
    {
        // localhost/IPv6 loopback entries are always normal
        if (ip is "127.0.0.1" or "::1" or "0.0.0.0" &&
            (hostname is "localhost" or "localhost.localdomain" or "local"))
            return (HostsEntryRisk.Normal, "Entrada padrão");

        // Blocking an ad/tracking domain by redirecting to 0.0.0.0 is common and OK
        if (ip is "0.0.0.0" or "127.0.0.1")
        {
            if (_protectedDomains.Contains(hostname))
                return (HostsEntryRisk.Malicious,
                    $"Domínio protegido bloqueado: {hostname}");
            return (HostsEntryRisk.Normal, "Bloqueio de domínio (ad-block)");
        }

        // Any external IP redirect to a protected domain is malicious
        if (_protectedDomains.Contains(hostname))
            return (HostsEntryRisk.Malicious,
                $"Redirecionamento suspeito de {hostname} para {ip}");

        // External IP redirecting any other domain — flag as suspicious
        if (!ip.StartsWith("127.") && !ip.StartsWith("::") && ip != "0.0.0.0")
            return (HostsEntryRisk.Suspicious,
                $"Redirecionamento para IP externo {ip}");

        return (HostsEntryRisk.Normal, "OK");
    }
}
