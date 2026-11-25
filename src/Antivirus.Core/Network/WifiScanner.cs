using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;

namespace AntivirusOS.Core.Network;

public enum WifiSecurity { Unknown, Open, WEP, WPA, WPA2, WPA3, WPA2_WPA3 }

public sealed record WifiNetwork(
    string SSID,
    string BSSID,
    WifiSecurity Security,
    int    SignalPercent,
    string Channel,
    bool   IsConnected,
    bool   IsInsecure);

[SupportedOSPlatform("windows")]
public sealed class WifiScanner
{
    public async Task<(WifiNetwork? connected, IReadOnlyList<WifiNetwork> all)> ScanAsync(
        CancellationToken ct = default)
    {
        var interfaceOutput = await RunNetshAsync("wlan show interfaces", ct);
        var networksOutput  = await RunNetshAsync("wlan show networks mode=bssid", ct);

        var connectedSsid = ParseConnectedSsid(interfaceOutput);
        var networks      = ParseNetworks(networksOutput, connectedSsid);
        var connected     = networks.FirstOrDefault(n => n.IsConnected);

        return (connected, networks);
    }

    private static string ParseConnectedSsid(string output)
    {
        var m = Regex.Match(output, @"^\s+SSID\s+:\s+(.+)$", RegexOptions.Multiline);
        return m.Success ? m.Groups[1].Value.Trim() : string.Empty;
    }

    private static IReadOnlyList<WifiNetwork> ParseNetworks(string output, string connectedSsid)
    {
        var networks = new List<WifiNetwork>();

        // Split on SSID blocks
        var blocks = Regex.Split(output, @"(?=^SSID \d+ :)", RegexOptions.Multiline);
        foreach (var block in blocks)
        {
            if (string.IsNullOrWhiteSpace(block)) continue;

            var ssidMatch    = Regex.Match(block, @"^SSID \d+ : (.+)$", RegexOptions.Multiline);
            var bssidMatch   = Regex.Match(block, @"^\s+BSSID \d+\s+:\s+(.+)$", RegexOptions.Multiline);
            var signalMatch  = Regex.Match(block, @"^\s+Signal\s+:\s+(\d+)%", RegexOptions.Multiline);
            var authMatch    = Regex.Match(block, @"^\s+Authentication\s+:\s+(.+)$", RegexOptions.Multiline);
            var channelMatch = Regex.Match(block, @"^\s+Channel\s+:\s+(\d+)", RegexOptions.Multiline);

            if (!ssidMatch.Success) continue;

            var ssid     = ssidMatch.Groups[1].Value.Trim();
            var bssid    = bssidMatch.Success ? bssidMatch.Groups[1].Value.Trim() : "—";
            var signal   = signalMatch.Success ? int.Parse(signalMatch.Groups[1].Value) : 0;
            var authRaw  = authMatch.Success ? authMatch.Groups[1].Value.Trim() : string.Empty;
            var channel  = channelMatch.Success ? channelMatch.Groups[1].Value : "—";
            var security = ParseSecurity(authRaw);

            networks.Add(new WifiNetwork(
                ssid, bssid, security, signal, channel,
                IsConnected: ssid.Equals(connectedSsid, StringComparison.OrdinalIgnoreCase),
                IsInsecure: security is WifiSecurity.Open or WifiSecurity.WEP or WifiSecurity.Unknown));
        }

        return networks;
    }

    private static WifiSecurity ParseSecurity(string auth)
    {
        if (string.IsNullOrEmpty(auth))             return WifiSecurity.Unknown;
        if (auth.Contains("WPA3", StringComparison.OrdinalIgnoreCase)
            && auth.Contains("WPA2", StringComparison.OrdinalIgnoreCase))
                                                    return WifiSecurity.WPA2_WPA3;
        if (auth.Contains("WPA3", StringComparison.OrdinalIgnoreCase)) return WifiSecurity.WPA3;
        if (auth.Contains("WPA2", StringComparison.OrdinalIgnoreCase)) return WifiSecurity.WPA2;
        if (auth.Contains("WPA",  StringComparison.OrdinalIgnoreCase)) return WifiSecurity.WPA;
        if (auth.Contains("WEP",  StringComparison.OrdinalIgnoreCase)) return WifiSecurity.WEP;
        if (auth.Equals("Open",   StringComparison.OrdinalIgnoreCase)) return WifiSecurity.Open;
        return WifiSecurity.Unknown;
    }

    private static async Task<string> RunNetshAsync(string args, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo("netsh", args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
            };
            using var proc = Process.Start(psi)!;
            var output = await proc.StandardOutput.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct);
            return output;
        }
        catch { return string.Empty; }
    }
}
