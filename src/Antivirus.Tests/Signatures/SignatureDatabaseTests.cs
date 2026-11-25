using AntivirusOS.Core.Models;
using AntivirusOS.Core.Signatures;

namespace Antivirus.Tests.Signatures;

public class SignatureDatabaseTests
{
    [Fact]
    public async Task Lookup_ExistingHash_ReturnsThreat()
    {
        var db = new SignatureDatabase("Data Source=:memory:");
        await db.InitializeAsync();
        var threat = new ThreatInfo("deadbeef", "Trojan.Test", ThreatLevel.Malicious, "test");
        await db.AddSignatureAsync(threat);
        var result = await db.LookupAsync("deadbeef");
        Assert.NotNull(result);
        Assert.Equal("Trojan.Test", result.Name);
    }

    [Fact]
    public async Task Lookup_UnknownHash_ReturnsNull()
    {
        var db = new SignatureDatabase("Data Source=:memory:");
        await db.InitializeAsync();
        var result = await db.LookupAsync("unknown");
        Assert.Null(result);
    }

    [Fact]
    public async Task AddSignature_Duplicate_DoesNotThrow()
    {
        var db = new SignatureDatabase("Data Source=:memory:");
        await db.InitializeAsync();
        var threat = new ThreatInfo("aabb", "Test", ThreatLevel.Suspicious, "");
        await db.AddSignatureAsync(threat);
        await db.AddSignatureAsync(threat); // INSERT OR IGNORE — sem exceção
    }
}
