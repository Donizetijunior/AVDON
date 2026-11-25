using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;

namespace AntivirusOS.Core.Network;

public record NetworkConnectionInfo(
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string State,
    bool IsSuspicious,
    string? SuspicionReason);

public class NetworkMonitor
{
    private static readonly int[] RatPorts = [1234, 4444, 5555, 6666, 7777, 8888, 31337];

    [SupportedOSPlatform("windows")]
    public Task<List<NetworkConnectionInfo>> GetConnectionsAsync()
    {
        var props = IPGlobalProperties.GetIPGlobalProperties();
        var conns = props.GetActiveTcpConnections();

        var result = conns.Select(c =>
        {
            var remote = c.RemoteEndPoint.Address.ToString();
            var localPort = c.LocalEndPoint.Port;
            var remotePort = c.RemoteEndPoint.Port;
            var state = c.State.ToString();
            var (suspicious, reason) = EvaluateSuspicion(remote, remotePort, c.State);
            return new NetworkConnectionInfo(
                c.LocalEndPoint.Address.ToString(),
                localPort,
                remote,
                remotePort,
                state,
                suspicious,
                reason);
        }).ToList();

        return Task.FromResult(result);
    }

    [SupportedOSPlatform("windows")]
    public async Task<List<NetworkConnectionInfo>> GetSuspiciousConnectionsAsync()
    {
        var all = await GetConnectionsAsync();
        return all.Where(c => c.IsSuspicious).ToList();
    }

    private static (bool suspicious, string? reason) EvaluateSuspicion(
        string remoteIp, int remotePort, TcpState state)
    {
        if (state != TcpState.Established)
            return (false, null);

        if (RatPorts.Contains(remotePort))
            return (true, $"Porta C2/RAT conhecida: {remotePort}");

        if (!IsPrivateIp(remoteIp))
        {
            if (RatPorts.Contains(remotePort))
                return (true, $"IP externo em porta suspeita {remotePort}");
        }

        return (false, null);
    }

    public static bool IsPrivateIp(string ip)
    {
        if (ip == "::1" || ip == "127.0.0.1") return true;
        if (!IPAddress.TryParse(ip, out var addr)) return false;

        var bytes = addr.GetAddressBytes();
        if (bytes.Length != 4) return ip.StartsWith("::") || ip.StartsWith("fe80");

        return bytes[0] == 10
            || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            || (bytes[0] == 192 && bytes[1] == 168)
            || bytes[0] == 127;
    }
}
