using System.Security.Cryptography.X509Certificates;

namespace AntivirusOS.Core.Analysis;

public class AuthenticodeChecker : IAuthenticodeChecker
{
    private static readonly string[] TrustedPublishers =
    [
        "Microsoft Corporation",
        "Google LLC",
        "Adobe Inc."
    ];

    public bool IsTrustedSigned(string filePath)
    {
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(filePath);
            var subject = cert.Subject;
            foreach (var publisher in TrustedPublishers)
            {
                if (subject.Contains(publisher, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }
}
