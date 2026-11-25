using System.Diagnostics;
using System.Runtime.Versioning;

namespace AntivirusOS.Core.Scheduler;

/// <summary>
/// Registers/removes AVDON as a Windows Task Scheduler entry so scans run
/// even when the UI is closed. Uses schtasks.exe — no extra NuGet packages.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TaskSchedulerService
{
    private const string TaskName = "AVDON_ScheduledScan";

    public (bool success, string message) Register(string exePath, int intervalHours)
    {
        try
        {
            // Delete existing task first (ignore error if not present)
            RunSchtasks($"/Delete /TN \"{TaskName}\" /F");

            // Create repeating task: start at logon, repeat every N hours
            var trigger = $"/SC ONLOGON /RI {intervalHours * 60} /DU 9999:59";
            var action  = $"/TR \"\\\"{exePath}\\\" --background\" /TN \"{TaskName}\"";
            var result  = RunSchtasks($"/Create {trigger} {action} /RL HIGHEST /F");

            return result.exitCode == 0
                ? (true,  $"Tarefa '{TaskName}' registrada no Agendador do Windows.")
                : (false, $"Erro ao registrar tarefa: {result.output}");
        }
        catch (Exception ex)
        {
            return (false, $"Exceção: {ex.Message}");
        }
    }

    public (bool success, string message) Unregister()
    {
        try
        {
            var result = RunSchtasks($"/Delete /TN \"{TaskName}\" /F");
            return result.exitCode == 0
                ? (true,  "Tarefa removida do Agendador do Windows.")
                : (false, $"Erro ao remover tarefa: {result.output}");
        }
        catch (Exception ex)
        {
            return (false, $"Exceção: {ex.Message}");
        }
    }

    public bool IsRegistered()
    {
        try
        {
            var result = RunSchtasks($"/Query /TN \"{TaskName}\"");
            return result.exitCode == 0;
        }
        catch { return false; }
    }

    private static (int exitCode, string output) RunSchtasks(string args)
    {
        var psi = new ProcessStartInfo("schtasks.exe", args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute        = false,
            CreateNoWindow         = true,
        };
        using var proc = Process.Start(psi)!;
        var output = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        return (proc.ExitCode, output.Trim());
    }
}
