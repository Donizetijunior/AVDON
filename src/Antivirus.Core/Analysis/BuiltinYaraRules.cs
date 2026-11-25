namespace AntivirusOS.Core.Analysis;

/// <summary>
/// Writes bundled YARA rules to disk and returns the directory path.
/// </summary>
public static class BuiltinYaraRules
{
    private const string RulesFolder = "yara_rules";

    public static string EnsureRules(string appDataPath)
    {
        var dir = Path.Combine(appDataPath, RulesFolder);
        Directory.CreateDirectory(dir);

        WriteRule(dir, "ransomware_markers.yar", RansomwareMarkers);
        WriteRule(dir, "rat_markers.yar", RatMarkers);
        WriteRule(dir, "dropper_markers.yar", DropperMarkers);
        WriteRule(dir, "miner_markers.yar", MinerMarkers);

        return dir;
    }

    private static void WriteRule(string dir, string filename, string content)
    {
        var path = Path.Combine(dir, filename);
        // Only write if newer content (simple length check avoids overwriting custom edits)
        if (!File.Exists(path))
            File.WriteAllText(path, content);
    }

    // ── Ransomware ──────────────────────────────────────────────────────────
    private const string RansomwareMarkers = """
rule Ransomware_FileMarkers {
    meta:
        description = "Common ransomware file markers and ransom note strings"
    strings:
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED"
        $note2 = "All your files are encrypted"
        $note3 = "decrypt your files"
        $note4 = "BTC"
        $note5 = "bitcoin"
        $note6 = "README_FOR_DECRYPT"
        $note7 = "DECRYPT_INSTRUCTION"
        $ext1  = ".locked"
        $ext2  = ".encrypted"
        $ext3  = ".enc"
        $ext4  = ".crypt"
    condition:
        2 of ($note*) or 1 of ($ext*)
}

rule Ransomware_VSSDelete {
    meta:
        description = "Volume Shadow Copy deletion commands used by ransomware"
    strings:
        $vss1 = "vssadmin delete shadows"
        $vss2 = "wmic shadowcopy delete"
        $vss3 = "bcdedit /set {default} recoveryenabled no"
        $vss4 = "wbadmin delete catalog"
    condition:
        any of them
}
""";

    // ── RAT / Backdoor ───────────────────────────────────────────────────────
    private const string RatMarkers = """
rule RAT_NetworkMarkers {
    meta:
        description = "Remote Access Tool network and command strings"
    strings:
        $cmd1 = "cmd.exe /c"
        $cmd2 = "powershell -enc"
        $cmd3 = "powershell -nop -w hidden"
        $cmd4 = "powershell -exec bypass"
        $rev1 = "reverse_shell"
        $rev2 = "reverse shell"
        $bc1  = "nc.exe"
        $bc2  = "netcat"
    condition:
        2 of ($cmd*) or any of ($rev*) or any of ($bc*)
}

rule RAT_RegistryPersistence {
    meta:
        description = "Registry autorun persistence keys written by malware"
    strings:
        $reg1 = "CurrentVersion\\Run"
        $reg2 = "CurrentVersion\\RunOnce"
        $reg3 = "Winlogon\\Shell"
        $reg4 = "Userinit"
    condition:
        any of them
}
""";

    // ── Dropper / Loader ─────────────────────────────────────────────────────
    private const string DropperMarkers = """
rule Dropper_Obfuscation {
    meta:
        description = "Common dropper/loader obfuscation patterns"
    strings:
        $ob1 = "CreateRemoteThread"
        $ob2 = "VirtualAllocEx"
        $ob3 = "WriteProcessMemory"
        $ob4 = "NtUnmapViewOfSection"
        $ob5 = "ZwUnmapViewOfSection"
        $ob6 = "ReflectiveDllInjection"
    condition:
        2 of them
}

rule Dropper_DownloadCradle {
    meta:
        description = "Download cradle patterns used by loaders"
    strings:
        $dl1 = "DownloadString"
        $dl2 = "DownloadFile"
        $dl3 = "WebClient"
        $dl4 = "Invoke-Expression"
        $dl5 = "IEX("
        $dl6 = "bitsadmin /transfer"
    condition:
        2 of them
}
""";

    // ── Miner ────────────────────────────────────────────────────────────────
    private const string MinerMarkers = """
rule Cryptominer_Strings {
    meta:
        description = "Cryptocurrency miner strings"
    strings:
        $m1 = "stratum+tcp://"
        $m2 = "stratum+ssl://"
        $m3 = "xmrig"
        $m4 = "monero"
        $m5 = "mining pool"
        $m6 = "--donate-level"
        $m7 = "cryptonight"
    condition:
        2 of them
}
""";
}
