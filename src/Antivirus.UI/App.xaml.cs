using System.Drawing;
using System.IO;
using System.Windows;
using System.Windows.Forms;
using AntivirusOS.Core.AI;
using AntivirusOS.Core.Monitor;
using AntivirusOS.Core.Quarantine;
using AntivirusOS.Core.Scanner;
using AntivirusOS.Core.Signatures;
using AntivirusOS.Core.Updater;
using Antivirus.UI.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using UISettings = Antivirus.UI.Properties.Settings;
using WinApp = System.Windows.Application;

namespace Antivirus.UI;

public partial class App : WinApp
{
    private ServiceProvider? _serviceProvider;
    private NotifyIcon? _notifyIcon;
    private bool _exitRequested;
    private CancellationTokenSource _cts = new();

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var services = new ServiceCollection();
        ConfigureServices(services);
        _serviceProvider = services.BuildServiceProvider();

        // Build tray icon
        _notifyIcon = CreateNotifyIcon();

        var mainViewModel = _serviceProvider.GetRequiredService<MainViewModel>();
        await mainViewModel.InitializeAsync();

        // Subscribe tray balloon for threat notifications
        var monitor = _serviceProvider.GetRequiredService<IRealTimeMonitor>();
        monitor.ThreatDetected += OnThreatDetected;

        // Start auto-updater
        var autoUpdater = _serviceProvider.GetRequiredService<AutoUpdater>();
        _ = autoUpdater.StartAsync(_cts.Token);

        var mainWindow = new MainWindow(mainViewModel);
        mainWindow.Closing += (s, args) =>
        {
            if (!_exitRequested)
            {
                args.Cancel = true;
                mainWindow.Hide();
                _notifyIcon!.ShowBalloonTip(2000, "AntivirusOS", "Minimizado para a bandeja. Clique duas vezes para restaurar.", ToolTipIcon.Info);
            }
        };

        _notifyIcon.DoubleClick += (s, args) =>
        {
            mainWindow.Show();
            mainWindow.WindowState = System.Windows.WindowState.Normal;
            mainWindow.Activate();
        };

        mainWindow.Show();
    }

    private NotifyIcon CreateNotifyIcon()
    {
        // Create a simple 16x16 red shield icon programmatically
        var bmp = new Bitmap(16, 16);
        using (var g = Graphics.FromImage(bmp))
        {
            g.Clear(Color.Transparent);
            g.FillEllipse(Brushes.DarkRed, 1, 1, 14, 14);
            g.DrawString("A", new Font("Arial", 7, System.Drawing.FontStyle.Bold),
                Brushes.White, new PointF(3, 2));
        }
        var icon = Icon.FromHandle(bmp.GetHicon());

        var menu = new ContextMenuStrip();
        menu.Items.Add("Abrir", null, (s, e) =>
        {
            foreach (System.Windows.Window w in Windows)
            {
                w.Show();
                w.WindowState = System.Windows.WindowState.Normal;
                w.Activate();
            }
        });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Sair", null, (s, e) =>
        {
            _exitRequested = true;
            _cts.Cancel();
            _notifyIcon?.Dispose();
            Shutdown();
        });

        return new NotifyIcon
        {
            Icon = icon,
            Text = "AntivirusOS",
            Visible = true,
            ContextMenuStrip = menu
        };
    }

    private void OnThreatDetected(object? sender, FileDetectedEventArgs e)
    {
        var result = e.Result;
        _notifyIcon?.ShowBalloonTip(5000,
            "AntivirusOS — Ameaça Detectada!",
            $"Arquivo: {result.FilePath}\nNível: {result.Level}",
            ToolTipIcon.Warning);
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        var appDataPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "AntivirusOS");
        Directory.CreateDirectory(appDataPath);

        var dbPath = Path.Combine(appDataPath, "signatures.db");
        var quarantinePath = Path.Combine(appDataPath, "quarantine");
        var historyDbPath = Path.Combine(appDataPath, "scan_history.db");

        services.AddSingleton<ISignatureDatabase>(_ =>
            new SignatureDatabase($"Data Source={dbPath}"));

        services.AddSingleton<IHashAnalyzer, HashAnalyzer>();
        services.AddSingleton<IFileScanner, FileScanner>();
        services.AddSingleton<IQuarantineManager>(_ => new QuarantineManager(quarantinePath));
        services.AddSingleton<IRealTimeMonitor, RealTimeMonitor>();

        services.AddSingleton<IClaudeAnalyzer>(_ =>
            new ClaudeAnalyzer(UISettings.Default.ClaudeApiKey ?? string.Empty));

        services.AddSingleton<ISignatureUpdater>(sp =>
            new SignatureUpdater(new System.Net.Http.HttpClient(), sp.GetRequiredService<ISignatureDatabase>()));

        services.AddSingleton<AutoUpdater>(sp =>
            new AutoUpdater(sp.GetRequiredService<ISignatureUpdater>(), TimeSpan.FromHours(24)));

        services.AddSingleton<IScanHistory>(_ =>
            new ScanHistory($"Data Source={historyDbPath}"));

        services.AddSingleton<ScheduledScanner>();
        services.AddSingleton<MainViewModel>();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _notifyIcon?.Dispose();
        _cts.Cancel();
        _cts.Dispose();
        _serviceProvider?.Dispose();
        base.OnExit(e);
    }
}
