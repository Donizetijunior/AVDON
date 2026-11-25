using System.Runtime.Versioning;
using Microsoft.Win32;

namespace AntivirusOS.Core.Shell;

[SupportedOSPlatform("windows")]
public sealed class ShellContextMenuService
{
    private const string MenuLabel   = "Escanear com AVDON";
    private const string FileKeyPath = @"*\shell\AVDON";
    private const string DirKeyPath  = @"Directory\shell\AVDON";
    private const string BgKeyPath   = @"Directory\Background\shell\AVDON";

    public (bool success, string message) Register(string exePath)
    {
        try
        {
            var cmd = $"\"{exePath}\" --scan \"%1\"";
            WriteKey(Registry.ClassesRoot, FileKeyPath, cmd);
            WriteKey(Registry.ClassesRoot, DirKeyPath,  cmd);

            var bgCmd = $"\"{exePath}\" --scan \"%V\"";
            WriteKey(Registry.ClassesRoot, BgKeyPath, bgCmd);

            return (true, "Menu de contexto registrado com sucesso.");
        }
        catch (UnauthorizedAccessException)
        {
            return (false, "Permissão negada. Execute o AVDON como Administrador para registrar o menu.");
        }
        catch (Exception ex) { return (false, $"Erro: {ex.Message}"); }
    }

    public (bool success, string message) Unregister()
    {
        try
        {
            DeleteKey(Registry.ClassesRoot, FileKeyPath);
            DeleteKey(Registry.ClassesRoot, DirKeyPath);
            DeleteKey(Registry.ClassesRoot, BgKeyPath);
            return (true, "Menu de contexto removido.");
        }
        catch (UnauthorizedAccessException)
        {
            return (false, "Permissão negada. Execute o AVDON como Administrador para remover o menu.");
        }
        catch (Exception ex) { return (false, $"Erro: {ex.Message}"); }
    }

    public bool IsRegistered()
    {
        using var key = Registry.ClassesRoot.OpenSubKey(FileKeyPath);
        return key != null;
    }

    private static void WriteKey(RegistryKey root, string keyPath, string command)
    {
        using var key = root.CreateSubKey(keyPath, writable: true);
        key.SetValue("", MenuLabel);
        key.SetValue("Icon", command.Split('"')[1]); // exe path
        using var cmdKey = key.CreateSubKey("command", writable: true);
        cmdKey.SetValue("", command);
    }

    private static void DeleteKey(RegistryKey root, string keyPath)
    {
        try { root.DeleteSubKeyTree(keyPath, throwOnMissingSubKey: false); }
        catch { }
    }
}
