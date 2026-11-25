using AntivirusOS.Core.Analysis;

namespace Antivirus.Tests.Analysis;

public class YaraScannerTests
{
    [Fact]
    public async Task EicarFile_MatchesEicarRule()
    {
        var rulesDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(rulesDir);

        var eicarContent =
            "rule EICAR_Test_File\n" +
            "{\n" +
            "    meta:\n" +
            "        description = \"EICAR Standard Anti-Virus Test File\"\n" +
            "    strings:\n" +
            "        $eicar = \"EICAR-STANDARD-ANTIVIRUS-TEST-FILE\"\n" +
            "    condition:\n" +
            "        any of them\n" +
            "}\n";
        await File.WriteAllTextAsync(Path.Combine(rulesDir, "eicar.yar"), eicarContent);

        var filePath = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(filePath,
                System.Text.Encoding.ASCII.GetBytes("TESTEICAR-STANDARD-ANTIVIRUS-TEST-FILEEND"));

            var scanner = new YaraScanner();
            scanner.LoadRules(rulesDir);

            // Verify file content
            var fileBytes = await File.ReadAllBytesAsync(filePath);
            Assert.True(fileBytes.Length > 0, "File should have content");

            var matches = await scanner.ScanAsync(filePath);
            Assert.NotEmpty(matches);
            Assert.Contains(matches, m => m.RuleName == "EICAR_Test_File");
        }
        finally
        {
            File.Delete(filePath);
            Directory.Delete(rulesDir, true);
        }
    }
}
