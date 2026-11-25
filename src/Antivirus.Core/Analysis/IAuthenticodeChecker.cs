namespace AntivirusOS.Core.Analysis;

public interface IAuthenticodeChecker
{
    bool IsTrustedSigned(string filePath); // true = signed by trusted publisher
}
