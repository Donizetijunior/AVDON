using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AntivirusOS.Core.DarkWeb;

public class DarkWebMonitor
{
    private static readonly HttpClient _http = new()
    {
        DefaultRequestHeaders = { { "User-Agent", "AVDON-AV" }, { "hibp-api-key", "" } }
    };

    // HaveIBeenPwned: check email breaches (k-anonymity model)
    public async Task<List<BreachInfo>> CheckEmailAsync(string email, string? apiKey = null, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(email))
            return [];

        using var client = new HttpClient();
        client.DefaultRequestHeaders.Add("User-Agent", "AVDON-AV");
        if (!string.IsNullOrEmpty(apiKey))
            client.DefaultRequestHeaders.Add("hibp-api-key", apiKey);

        var url = $"https://haveibeenpwned.com/api/v3/breachedaccount/{Uri.EscapeDataString(email)}?truncateResponse=false";
        try
        {
            var response = await client.GetAsync(url, ct);
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                return [];
            if (!response.IsSuccessStatusCode)
                throw new InvalidOperationException($"HIBP error: {response.StatusCode}");

            var json = await response.Content.ReadAsStringAsync(ct);
            var breaches = JsonSerializer.Deserialize<List<HibpBreach>>(json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? [];

            return breaches.Select(b => new BreachInfo(
                b.Name,
                b.Title,
                b.BreachDate,
                b.PwnCount,
                b.DataClasses ?? [],
                b.Description ?? string.Empty
            )).ToList();
        }
        catch (HttpRequestException ex)
        {
            throw new InvalidOperationException($"Falha ao conectar com HaveIBeenPwned: {ex.Message}", ex);
        }
    }

    // Check password exposure via k-anonymity (no full password sent)
    public async Task<int> CheckPasswordAsync(string password, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(password)) return 0;

        var hashBytes = SHA1.HashData(Encoding.UTF8.GetBytes(password));
        var hash = Convert.ToHexString(hashBytes).ToUpperInvariant();
        var prefix = hash[..5];
        var suffix = hash[5..];

        using var client = new HttpClient();
        client.DefaultRequestHeaders.Add("User-Agent", "AVDON-AV");

        var url = $"https://api.pwnedpasswords.com/range/{prefix}";
        var response = await client.GetAsync(url, ct);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadAsStringAsync(ct);
        foreach (var line in body.Split('\n'))
        {
            var parts = line.Trim().Split(':');
            if (parts.Length == 2 && parts[0].Equals(suffix, StringComparison.OrdinalIgnoreCase))
                return int.TryParse(parts[1], out var count) ? count : 0;
        }
        return 0;
    }

    private class HibpBreach
    {
        public string Name { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string BreachDate { get; set; } = string.Empty;
        public int PwnCount { get; set; }
        public List<string>? DataClasses { get; set; }
        public string? Description { get; set; }
    }
}

public record BreachInfo(
    string Name,
    string Title,
    string BreachDate,
    int PwnCount,
    List<string> DataClasses,
    string Description);
