using AntivirusOS.Core.Models;
using AntivirusOS.Core.Signatures;

namespace Antivirus.Tests.Signatures;

public class SignatureDatabaseTests
{
    [Fact]
    public async Task Lookup_ExistingHash_ReturnsThreat()
    {
        await using var db = new SignatureDatabase("Data Source=:memory:");
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
        await using var db = new SignatureDatabase("Data Source=:memory:");
        await db.InitializeAsync();
        var result = await db.LookupAsync("unknown");
        Assert.Null(result);
    }

    [Fact]
    public async Task AddSignature_Duplicate_DoesNotThrow()
    {
        await using var db = new SignatureDatabase("Data Source=:memory:");
        await db.InitializeAsync();
        var threat = new ThreatInfo("aabb", "Test", ThreatLevel.Suspicious, "");
        await db.AddSignatureAsync(threat);
        await db.AddSignatureAsync(threat); // INSERT OR IGNORE — sem exceção
    }

    [Fact]
    public async Task Count_AfterAddingSignatures_ReturnsCorrectCount()
    {
        await using var db = new SignatureDatabase("Data Source=:memory:");
        await db.InitializeAsync();
        await db.AddSignatureAsync(new ThreatInfo("hash1", "T1", ThreatLevel.Malicious, ""));
        await db.AddSignatureAsync(new ThreatInfo("hash2", "T2", ThreatLevel.Suspicious, ""));
        Assert.Equal(2, await db.CountAsync());
    }
}
