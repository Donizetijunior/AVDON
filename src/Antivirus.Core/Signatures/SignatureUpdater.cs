using System.IO.Compression;
using AntivirusOS.Core.Models;
using AntivirusOS.Core.Signatures;

namespace AntivirusOS.Core.Updater;

/// <summary>
/// Downloads and imports malware signatures from MalwareBazaar's public CSV export.
/// The endpoint returns a ZIP file containing a CSV with sha256_hash and signature columns.
/// </summary>
public sealed class SignatureUpdater : ISignatureUpdater
{
    // Export recente (100 amostras) — endpoint ativo no MalwareBazaar
    private const string MalwareBazaarUrl = "https://bazaar.abuse.ch/export/csv/recent/";

    private readonly HttpClient _httpClient;
    private readonly ISignatureDatabase _database;

    public SignatureUpdater(HttpClient httpClient, ISignatureDatabase database)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _database = database ?? throw new ArgumentNullException(nameof(database));
    }

    public async Task<int> UpdateFromMalwareBazaarAsync(CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync(MalwareBazaarUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();

        await using var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var zip = new ZipArchive(responseStream, ZipArchiveMode.Read);

        // The ZIP contains a single CSV file; find it.
        var csvEntry = zip.Entries.FirstOrDefault(e => e.Name.EndsWith(".csv", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("No CSV file found inside the MalwareBazaar ZIP archive.");

        await using var csvStream = csvEntry.Open();
        using var reader = new StreamReader(csvStream);

        return await ParseAndImportAsync(reader, cancellationToken);
    }

    private async Task<int> ParseAndImportAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        // CSV header line (non-comment) looks like:
        // "first_seen","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh","tags"
        // Indices (0-based): sha256_hash=1, signature=8

        const int sha256Col = 1;
        const int signatureCol = 8;

        int added = 0;
        bool headerSkipped = false;

        while (!reader.EndOfStream)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is null) break;

            // Skip comment lines starting with '#'
            if (line.StartsWith('#')) continue;

            // Skip the header row (first non-comment line)
            if (!headerSkipped)
            {
                headerSkipped = true;
                continue;
            }

            var columns = ParseCsvLine(line);
            if (columns.Length <= Math.Max(sha256Col, signatureCol)) continue;

            var hash = columns[sha256Col].Trim('"', ' ');
            var signature = columns[signatureCol].Trim('"', ' ');

            if (string.IsNullOrWhiteSpace(hash) || hash.Length != 64) continue;

            var name = string.IsNullOrWhiteSpace(signature) ? "Unknown" : signature;

            var threat = new ThreatInfo(
                Hash: hash,
                Name: name,
                Level: ThreatLevel.Malicious,
                Description: $"MalwareBazaar: {name}");

            await _database.AddSignatureAsync(threat);
            added++;
        }

        return added;
    }

    /// <summary>
    /// Splits a CSV line respecting quoted fields (fields may contain commas inside quotes).
    /// </summary>
    private static string[] ParseCsvLine(string line)
    {
        var fields = new List<string>();
        var current = new System.Text.StringBuilder();
        bool inQuotes = false;

        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];

            if (c == '"')
            {
                if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                {
                    // Escaped quote inside quoted field
                    current.Append('"');
                    i++;
                }
                else
                {
                    inQuotes = !inQuotes;
                }
            }
            else if (c == ',' && !inQuotes)
            {
                fields.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }

        fields.Add(current.ToString());
        return fields.ToArray();
    }
}
