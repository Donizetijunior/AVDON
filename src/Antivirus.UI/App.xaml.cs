using System.Drawing;
using System.IO;
using System.Windows;
using System.Windows.Forms;
using AntivirusOS.Core.AI;
using AntivirusOS.Core.Analysis;
using AntivirusOS.Core.DarkWeb;
using AntivirusOS.Core.Monitor;
using AntivirusOS.Core.Network;
using AntivirusOS.Core.Reports;
using AntivirusOS.Core.Scheduler;
using AntivirusOS.Core.Logging;
using AntivirusOS.Core.Quarantine;
using AntivirusOS.Core.Ransomware;
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
    private AntivirusOS.Core.Settings.AppSettings _appSettings = new();

    // Single-instance enforcement
    private static Mutex? _instanceMutex;
    private static EventWaitHandle? _activateEvent;
    private const string MutexName  = "Global\\AVDON_SingleInstance";
    private const string EventName  = "Global\\AVDON_Activate";

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // ── Single-instance guard ───────────────────────────────────────────
        _instanceMutex = new Mutex(initiallyOwned: true, MutexName, out bool isNewInstance);
        if (!isNewInstance)
        {
            // Signal the running instance to show/activate itself
            if (EventWaitHandle.TryOpenExisting(EventName, out var ev))
            {
                ev.Set();
                ev.Dispose();
            }
            Shutdown();
            return;
        }

        // Listen for activation signals from future instances
        _activateEvent = new EventWaitHandle(false, EventResetMode.AutoReset, EventName);
        Task.Run(() =>
        {
            while (true)
            {
                _activateEvent.WaitOne();
                Current.Dispatcher.Invoke(() =>
                {
                    foreach (System.Windows.Window w in Current.Windows)
                    {
                        w.Show();
                        if (w.WindowState == System.Windows.WindowState.Minimized)
                            w.WindowState = System.Windows.WindowState.Normal;
                        w.Activate();
                        break;
                    }
                });
            }
        });
        // ───────────────────────────────────────────────────────────────────

        AvdonLogger.Instance.Info("App", "AVDON iniciando.");

        var appDataPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AVDON");
        _appSettings = AntivirusOS.Core.Settings.AppSettings.Load(appDataPath);

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

        // Auto-protect critical folders on startup
        var criticalPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Windows\Start Menu\Programs\Startup"),
        };
        monitor.StartMonitoring(criticalPaths);
        mainViewModel.IsMonitoring = true;
        mainViewModel.MonitoredPath = "Pastas críticas";

        // Start ransomware guard on critical folders
        var ransomGuard = _serviceProvider.GetRequiredService<RansomwareGuard>();
        ransomGuard.AlertRaised += OnRansomwareAlert;
        ransomGuard.Start(criticalPaths);

        // Start auto-updater
        var autoUpdater = _serviceProvider.GetRequiredService<AutoUpdater>();
        _ = autoUpdater.StartAsync(_cts.Token);

        // Wire scheduled scanner tray notifications
        var scheduledScanner = _serviceProvider.GetRequiredService<AntivirusOS.Core.Scanner.ScheduledScanner>();
        scheduledScanner.ScanCompleted += OnScheduledScanCompleted;

        var mainWindow = new MainWindow(mainViewModel,
            _serviceProvider.GetRequiredService<IQuarantineManager>(),
            _serviceProvider.GetRequiredService<IRealTimeMonitor>(),
            _serviceProvider.GetRequiredService<RansomwareGuard>(),
            _serviceProvider.GetRequiredService<DnsBlocker>(),
            _serviceProvider.GetRequiredService<TaskSchedulerService>());
        mainWindow.Closing += (s, args) =>
        {
            if (!_exitRequested)
            {
                args.Cancel = true;
                mainWindow.Hide();
                _notifyIcon!.ShowBalloonTip(2000, "AVDON", "Minimizado para a bandeja. Clique duas vezes para restaurar.", ToolTipIcon.Info);
            }
        };

        _notifyIcon.DoubleClick += (s, args) =>
        {
            mainWindow.Show();
            mainWindow.WindowState = System.Windows.WindowState.Normal;
            mainWindow.Activate();
        };

        // Silent/background mode: start minimized to tray (e.g. launched by Task Scheduler)
        bool silentStart = e.Args.Contains("--background", StringComparer.OrdinalIgnoreCase);
        if (!silentStart)
            mainWindow.Show();

        // --scan <path>: open and start scanning the given path immediately
        int scanIdx = Array.FindIndex(e.Args, a => a.Equals("--scan", StringComparison.OrdinalIgnoreCase));
        if (scanIdx >= 0 && scanIdx + 1 < e.Args.Length)
        {
            var scanPath = e.Args[scanIdx + 1];
            mainWindow.Show();
            mainViewModel.ScanPath = scanPath;
            _ = mainViewModel.FullScanCommand.ExecuteAsync(null);
        }
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
        menu.Items.Add("🔍 Scan Rápido", null, (s, e) =>
        {
            Current.Dispatcher.Invoke(() =>
            {
                var vm = _serviceProvider?.GetService<Antivirus.UI.ViewModels.MainViewModel>();
                if (vm != null && !vm.IsScanning)
                    vm.QuickScanCommand.Execute(null);

                // Bring window to front
                foreach (System.Windows.Window w in Windows)
                { w.Show(); w.WindowState = System.Windows.WindowState.Normal; w.Activate(); break; }
            });
        });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Sobre", null, (s, e) =>
        {
            Current.Dispatcher.Invoke(() =>
            {
                var about = new AboutWindow(
                    _serviceProvider!.GetRequiredService<IRealTimeMonitor>(),
                    _serviceProvider!.GetRequiredService<RansomwareGuard>(),
                    _serviceProvider!.GetRequiredService<DnsBlocker>(),
                    _serviceProvider!.GetRequiredService<TaskSchedulerService>());
                about.Show();
            });
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
            Text = "AVDON",
            Visible = true,
            ContextMenuStrip = menu
        };
    }

    private void OnThreatDetected(object? sender, FileDetectedEventArgs e)
    {
        var result = e.Result;

        // Auto-quarantine malicious files when setting is on
        if (_appSettings.AutoQuarantine && result.Level == AntivirusOS.Core.Models.ThreatLevel.Malicious)
        {
            try
            {
                var qm = _serviceProvider!.GetRequiredService<IQuarantineManager>();
                _ = qm.QuarantineAsync(result.FilePath, result.Hash);
                AvdonLogger.Instance.Warn("AutoQuarantine",
                    $"Auto-quarentenado: {result.FilePath}");
            }
            catch (Exception ex)
            {
                AvdonLogger.Instance.Error("AutoQuarantine",
                    $"Falha ao quarentenar {result.FilePath}: {ex.Message}");
            }
        }

        if (_appSettings.NotifyOnThreat)
        {
            Current.Dispatcher.Invoke(() =>
            {
                var toast = new ThreatToastWindow(result, _serviceProvider!.GetRequiredService<MainViewModel>());
                toast.Show();
            });
        }
    }

    private void OnScheduledScanCompleted(object? sender, AntivirusOS.Core.Scanner.ScanCompletedEventArgs e)
    {
        var logMsg = $"Scan agendado: {e.Total} arquivo(s), {e.Threats} ameaça(s).";
        if (e.Threats > 0)
            AvdonLogger.Instance.Warn("ScheduledScanner", logMsg);
        else
            AvdonLogger.Instance.Info("ScheduledScanner", logMsg);

        Current.Dispatcher.Invoke(() =>
        {
            var msg = e.Threats == 0
                ? $"Scan agendado concluído: {e.Total} arquivo(s) verificado(s). Nenhuma ameaça."
                : $"⚠ Scan agendado: {e.Threats} ameaça(s) encontrada(s) em {e.Total} arquivo(s).";

            _notifyIcon?.ShowBalloonTip(5000, "AVDON — Scan Agendado", msg,
                e.Threats > 0 ? ToolTipIcon.Warning : ToolTipIcon.Info);
        });
    }

    private void OnRansomwareAlert(object? sender, AntivirusOS.Core.Ransomware.RansomwareAlert alert)
    {
        AvdonLogger.Instance.Warn("RansomwareGuard",
            $"Alerta: {alert.Kind} — {alert.Path} ({alert.FileCount} arquivos)");

        Current.Dispatcher.Invoke(() =>
        {
            var msg = alert.Kind == AntivirusOS.Core.Ransomware.RansomwareAlertKind.HoneypotTriggered
                ? $"⚠ Arquivo sentinela modificado!\n{alert.Path}"
                : $"⚠ Possível ransomware detectado!\n{alert.FileCount} arquivos modificados em {alert.Path}";

            _notifyIcon?.ShowBalloonTip(5000, "AVDON — Alerta de Ransomware", msg, ToolTipIcon.Warning);
        });
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        var appDataPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "AVDON");
        Directory.CreateDirectory(appDataPath);

        var dbPath = Path.Combine(appDataPath, "signatures.db");
        var quarantinePath = Path.Combine(appDataPath, "quarantine");
        var historyDbPath = Path.Combine(appDataPath, "scan_history.db");

        services.AddSingleton<ISignatureDatabase>(_ =>
            new SignatureDatabase($"Data Source={dbPath}"));

        services.AddSingleton<IHashAnalyzer, HashAnalyzer>();
        services.AddSingleton<IClaudeAnalyzer>(_ =>
            new ClaudeAnalyzer(UISettings.Default.ClaudeApiKey ?? string.Empty));

        // YARA — load builtin rules
        services.AddSingleton<IYaraScanner>(_ =>
        {
            var scanner = new YaraScanner();
            var rulesDir = BuiltinYaraRules.EnsureRules(appDataPath);
            scanner.LoadRules(rulesDir);
            return scanner;
        });

        services.AddSingleton<IFileScanner>(sp =>
            new FileScanner(
                sp.GetRequiredService<IHashAnalyzer>(),
                sp.GetRequiredService<ISignatureDatabase>(),
                yaraScanner: sp.GetRequiredService<IYaraScanner>(),
                claudeAnalyzer: sp.GetRequiredService<IClaudeAnalyzer>()));

        services.AddSingleton<RansomwareGuard>();
        services.AddSingleton<IQuarantineManager>(_ => new QuarantineManager(quarantinePath));
        services.AddSingleton<IRealTimeMonitor, RealTimeMonitor>();

        services.AddSingleton<ISignatureUpdater>(sp =>
            new SignatureUpdater(new System.Net.Http.HttpClient(), sp.GetRequiredService<ISignatureDatabase>()));

        services.AddSingleton<AutoUpdater>(sp =>
            new AutoUpdater(sp.GetRequiredService<ISignatureUpdater>(), TimeSpan.FromHours(24)));

        services.AddSingleton<IScanHistory>(_ =>
            new ScanHistory($"Data Source={historyDbPath}"));

        services.AddSingleton<ScheduledScanner>();
        services.AddSingleton<DarkWebMonitor>();
        services.AddSingleton<DnsBlocker>();
        services.AddSingleton<NetworkMonitor>();
        services.AddSingleton<ScanReporter>();
        services.AddSingleton<TaskSchedulerService>();
        services.AddSingleton<AntivirusOS.Core.Monitor.ProcessMonitorService>();
        services.AddSingleton<AntivirusOS.Core.Shell.ShellContextMenuService>();
        services.AddSingleton<MainViewModel>();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        AvdonLogger.Instance.Info("App", "AVDON encerrando.");
        AvdonLogger.Instance.Dispose();
        _serviceProvider?.GetService<RansomwareGuard>()?.Dispose();
        _notifyIcon?.Dispose();
        _cts.Cancel();
        _cts.Dispose();
        _serviceProvider?.Dispose();
        _activateEvent?.Dispose();
        try { _instanceMutex?.ReleaseMutex(); } catch { }
        _instanceMutex?.Dispose();
        base.OnExit(e);
    }
}
