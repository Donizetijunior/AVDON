using System.Reflection;
using System.Windows;
using System.Windows.Media;
using AntivirusOS.Core.Logging;
using AntivirusOS.Core.Monitor;
using AntivirusOS.Core.Ransomware;
using AntivirusOS.Core.Network;
using AntivirusOS.Core.Scheduler;

namespace Antivirus.UI;

public partial class AboutWindow : Window
{
    public AboutWindow(
        IRealTimeMonitor monitor,
        RansomwareGuard ransomGuard,
        DnsBlocker dnsBlocker,
        TaskSchedulerService taskScheduler)
    {
        InitializeComponent();

        // Version
        var ver = Assembly.GetExecutingAssembly().GetName().Version;
        TxtVersion.Text = ver != null ? $"v{ver.Major}.{ver.Minor}.{ver.Build}" : "v—";

        // Component status
        var items = new[]
        {
            new ComponentStatus("Monitor em tempo real",
                monitor.MonitoredPaths.Count > 0 ? "Ativo" : "Inativo",
                monitor.MonitoredPaths.Count > 0),

            new ComponentStatus("Proteção contra ransomware",
                "Ativo", true),

            new ComponentStatus("Bloqueio DNS",
                dnsBlocker.GetCurrentBlockedDomains().Count > 0 ? "Ativo" : "Inativo",
                dnsBlocker.GetCurrentBlockedDomains().Count > 0),

            new ComponentStatus("Scan agendado (Task Scheduler)",
                taskScheduler.IsRegistered() ? "Registrado" : "Não registrado",
                taskScheduler.IsRegistered()),

            new ComponentStatus("Logger",
                "Ativo", true),
        };
        ComponentList.ItemsSource = items;

        // Today's log
        var entries = AvdonLogger.Instance.ReadTodaysEntries(200);
        TxtLog.Text = entries.Count == 0
            ? "(sem entradas hoje)"
            : string.Join("\n", entries.Select(e =>
                $"{e.Timestamp:HH:mm:ss} [{e.Level,-7}] [{e.Component}] {e.Message}"));

        Loaded += (_, _) =>
        {
            LogScroller.ScrollToBottom();
        };
    }

    private void BtnClose_Click(object sender, RoutedEventArgs e) => Close();
}

file sealed class ComponentStatus
{
    public string Name   { get; }
    public string Status { get; }
    public System.Windows.Media.Brush StatusColor { get; }

    public ComponentStatus(string name, string status, bool ok)
    {
        Name        = name;
        Status      = status;
        StatusColor = ok
            ? new SolidColorBrush(System.Windows.Media.Color.FromRgb(0x22, 0xC5, 0x5E))
            : new SolidColorBrush(System.Windows.Media.Color.FromRgb(0x94, 0xA3, 0xB8));
    }
}
