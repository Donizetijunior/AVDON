using System.IO.Compression;
using System.Net;
using AntivirusOS.Core.Models;
using AntivirusOS.Core.Signatures;
using AntivirusOS.Core.Updater;
using Moq;

namespace Antivirus.Tests.Signatures;

public class SignatureUpdaterTests
{
    // ------------------------------------------------------------------ helpers

    /// <summary>Creates an in-memory ZIP whose sole entry is a CSV with the given content.</summary>
    private static byte[] BuildZipWithCsv(string csvContent)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("full.csv");
            using var writer = new StreamWriter(entry.Open());
            writer.Write(csvContent);
        }
        return ms.ToArray();
    }

    private static HttpClient BuildHttpClient(byte[] body, HttpStatusCode status = HttpStatusCode.OK)
    {
        var handler = new FakeHttpMessageHandler(body, status);
        return new HttpClient(handler) { BaseAddress = new Uri("https://bazaar.abuse.ch") };
    }

    // ------------------------------------------------------------------ tests

    [Fact]
    public async Task UpdateFromMalwareBazaarAsync_ReturnsZeroForEmptyCsv()
    {
        const string csv =
            "# comment\n" +
            "\"first_seen\",\"sha256_hash\",\"md5_hash\",\"sha1_hash\",\"reporter\",\"file_name\",\"file_type_guess\",\"mime_type\",\"signature\",\"clamav\",\"vtpercent\",\"imphash\",\"ssdeep\",\"tlsh\",\"tags\"\n";

        var zipBytes = BuildZipWithCsv(csv);
        var db = new Mock<ISignatureDatabase>();
        var updater = new SignatureUpdater(BuildHttpClient(zipBytes), db.Object);

        var count = await updater.UpdateFromMalwareBazaarAsync();

        Assert.Equal(0, count);
        db.Verify(d => d.AddSignatureAsync(It.IsAny<ThreatInfo>()), Times.Never);
    }

    [Fact]
    public async Task UpdateFromMalwareBazaarAsync_ParsesValidRows()
    {
        var hash = new string('a', 64);
        var csv =
            "# MalwareBazaar export\n" +
            "\"first_seen\",\"sha256_hash\",\"md5_hash\",\"sha1_hash\",\"reporter\",\"file_name\",\"file_type_guess\",\"mime_type\",\"signature\",\"clamav\",\"vtpercent\",\"imphash\",\"ssdeep\",\"tlsh\",\"tags\"\n" +
            $"\"2024-01-01\",\"{hash}\",\"md5\",\"sha1\",\"reporter\",\"file.exe\",\"PE32\",\"application/x-dosexec\",\"Trojan.Foo\",\"\",\"75\",\"\",\"\",\"\",\"\"\n";

        var zipBytes = BuildZipWithCsv(csv);
        var db = new Mock<ISignatureDatabase>();
        var updater = new SignatureUpdater(BuildHttpClient(zipBytes), db.Object);

        var count = await updater.UpdateFromMalwareBazaarAsync();

        Assert.Equal(1, count);
        db.Verify(d => d.AddSignatureAsync(It.Is<ThreatInfo>(t =>
            t.Hash == hash &&
            t.Name == "Trojan.Foo" &&
            t.Level == ThreatLevel.Malicious)), Times.Once);
    }

    [Fact]
    public async Task UpdateFromMalwareBazaarAsync_SkipsRowsWithInvalidHash()
    {
        const string csv =
            "\"first_seen\",\"sha256_hash\",\"md5_hash\",\"sha1_hash\",\"reporter\",\"file_name\",\"file_type_guess\",\"mime_type\",\"signature\",\"clamav\",\"vtpercent\",\"imphash\",\"ssdeep\",\"tlsh\",\"tags\"\n" +
            "\"2024-01-01\",\"tooshort\",\"md5\",\"sha1\",\"reporter\",\"file.exe\",\"PE32\",\"app\",\"Trojan.X\",\"\",\"\",\"\",\"\",\"\",\"\"\n";

        var zipBytes = BuildZipWithCsv(csv);
        var db = new Mock<ISignatureDatabase>();
        var updater = new SignatureUpdater(BuildHttpClient(zipBytes), db.Object);

        var count = await updater.UpdateFromMalwareBazaarAsync();

        Assert.Equal(0, count);
        db.Verify(d => d.AddSignatureAsync(It.IsAny<ThreatInfo>()), Times.Never);
    }

    [Fact]
    public async Task UpdateFromMalwareBazaarAsync_UsesUnknownWhenSignatureEmpty()
    {
        var hash = new string('b', 64);
        var csv =
            "\"first_seen\",\"sha256_hash\",\"md5_hash\",\"sha1_hash\",\"reporter\",\"file_name\",\"file_type_guess\",\"mime_type\",\"signature\",\"clamav\",\"vtpercent\",\"imphash\",\"ssdeep\",\"tlsh\",\"tags\"\n" +
            $"\"2024-01-01\",\"{hash}\",\"md5\",\"sha1\",\"reporter\",\"file.exe\",\"PE32\",\"app\",\"\",\"\",\"\",\"\",\"\",\"\",\"\"\n";

        var zipBytes = BuildZipWithCsv(csv);
        var db = new Mock<ISignatureDatabase>();
        var updater = new SignatureUpdater(BuildHttpClient(zipBytes), db.Object);

        await updater.UpdateFromMalwareBazaarAsync();

        db.Verify(d => d.AddSignatureAsync(It.Is<ThreatInfo>(t => t.Name == "Unknown")), Times.Once);
    }

    [Fact]
    public async Task UpdateFromMalwareBazaarAsync_ThrowsOnHttpError()
    {
        var zipBytes = Array.Empty<byte>();
        var db = new Mock<ISignatureDatabase>();
        var updater = new SignatureUpdater(BuildHttpClient(zipBytes, HttpStatusCode.ServiceUnavailable), db.Object);

        await Assert.ThrowsAsync<HttpRequestException>(() => updater.UpdateFromMalwareBazaarAsync());
    }

    [Fact]
    public async Task UpdateFromMalwareBazaarAsync_SkipsCommentLines()
    {
        var hash = new string('c', 64);
        var csv =
            "# This is a comment\n" +
            "# Another comment\n" +
            "\"first_seen\",\"sha256_hash\",\"md5_hash\",\"sha1_hash\",\"reporter\",\"file_name\",\"file_type_guess\",\"mime_type\",\"signature\",\"clamav\",\"vtpercent\",\"imphash\",\"ssdeep\",\"tlsh\",\"tags\"\n" +
            $"\"2024-01-01\",\"{hash}\",\"md5\",\"sha1\",\"reporter\",\"file.exe\",\"PE32\",\"app\",\"Ransomware.Z\",\"\",\"\",\"\",\"\",\"\",\"\"\n";

        var zipBytes = BuildZipWithCsv(csv);
        var db = new Mock<ISignatureDatabase>();
        var updater = new SignatureUpdater(BuildHttpClient(zipBytes), db.Object);

        var count = await updater.UpdateFromMalwareBazaarAsync();

        Assert.Equal(1, count);
    }
}

// ------------------------------------------------------------------ fake handler

file sealed class FakeHttpMessageHandler : HttpMessageHandler
{
    private readonly byte[] _body;
    private readonly HttpStatusCode _status;

    public FakeHttpMessageHandler(byte[] body, HttpStatusCode status)
    {
        _body = body;
        _status = status;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = new HttpResponseMessage(_status)
        {
            Content = new ByteArrayContent(_body)
        };
        return Task.FromResult(response);
    }
}
