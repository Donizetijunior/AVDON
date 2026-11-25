using AntivirusOS.Core.Analysis;

namespace Antivirus.Tests.Analysis;

public class AuthenticodeCheckerTests
{
    [Fact]
    public void UnsignedFile_ReturnsFalse()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "not signed");
            var checker = new AuthenticodeChecker();
            Assert.False(checker.IsTrustedSigned(path));
        }
        finally { File.Delete(path); }
    }
}
