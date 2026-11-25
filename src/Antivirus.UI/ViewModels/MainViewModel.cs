using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using AntivirusOS.Core.DarkWeb;
using AntivirusOS.Core.Network;
using AntivirusOS.Core.Reports;
using AntivirusOS.Core.Scheduler;
using AntivirusOS.Core.Logging;
using AntivirusOS.Core.Settings;
using System.Collections.Generic;
using AntivirusOS.Core.Models;
using AntivirusOS.Core.Scanner;
using AntivirusOS.Core.Quarantine;
using AntivirusOS.Core.Monitor;
using AntivirusOS.Core.Signatures;
using AntivirusOS.Core.Updater;
using AntivirusOS.Core.Events;
using AntivirusOS.Core.Startup;
using AntivirusOS.Core.Integrity;
using AntivirusOS.Core.Security;
using Microsoft.Win32;
using WinForms = System.Windows.Forms;
using Win32Dialog = Microsoft.Win32;

namespace Antivirus.UI.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly IFileScanner _fileScanner;
    private readonly IQuarantineManager _quarantineManager;
    private readonly IRealTimeMonitor _realTimeMonitor;
    private readonly ISignatureUpdater _signatureUpdater;
    private readonly ISignatureDatabase _signatureDatabase;
    private readonly IScanHistory _scanHistory;
    private readonly ScheduledScanner _scheduledScanner;
    private readonly DarkWebMonitor _darkWebMonitor;
    private readonly DnsBlocker _dnsBlocker;
    private readonly NetworkMonitor _networkMonitor;
    private readonly ScanReporter _scanReporter;
    private readonly TaskSchedulerService _taskScheduler;
    private readonly ProcessMonitorService _processMonitor;
    private readonly AntivirusOS.Core.Shell.ShellContextMenuService _shellMenu;
    private readonly EventLogger _eventLogger;
    private readonly StartupManager _startupManager = new();
    private readonly FileIntegrityService _integrityService;
    private readonly WifiScanner _wifiScanner = new();
    private readonly HostsFileChecker _hostsChecker = new();
    private readonly SensitiveFileDetector _sensitiveDetector = new();
    private CancellationTokenSource? _integrityCts;
    private ScheduledScanConfig _schedConfig = new();
    private AppSettings _appSettings = new();
    private readonly string _appDataPath;

    private CancellationTokenSource? _scheduledScanCts;
    private CancellationTokenSource? _procScanCts;
    private CancellationTokenSource? _scanCts;

    [ObservableProperty]
    private string _scanStatus = "Pronto.";

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private bool _isMonitoring;

    [ObservableProperty]
    private string _monitoredPath = string.Empty;

    [ObservableProperty]
    private string _monitorLog = string.Empty;

    [ObservableProperty]
    private string _claudeApiKey = string.Empty;

    [ObservableProperty]
    private long _signatureCount;

    [ObservableProperty]
    private bool _isUpdatingSignatures;

    [ObservableProperty]
    private bool _isScheduledScanRunning;

    [ObservableProperty]
    private string _scheduledScanPath = string.Empty;

    [ObservableProperty]
    private string _scanPath = string.Empty;

    [ObservableProperty]
    private int _scannedCount;

    [ObservableProperty]
    private string _currentScanFile = string.Empty;

    [ObservableProperty]
    private DateTime? _lastScanTime;

    [ObservableProperty]
    private int _totalThreatsBlocked;

    [ObservableProperty]
    private int _monitoredFolderCount;

    // Computed from HistoryResults — updated via CollectionChanged
    [ObservableProperty]
    private int _historyTotalCount;

    [ObservableProperty]
    private int _historyThreatCount;

    public string MonitoredPathsList =>
        _realTimeMonitor.MonitoredPaths.Count == 0
            ? string.Empty
            : string.Join("\n", _realTimeMonitor.MonitoredPaths);

    // Network monitor
    [ObservableProperty]
    private bool _isRefreshingNetwork;

    [ObservableProperty]
    private string _networkStatus = string.Empty;

    public ObservableCollection<NetworkConnectionInfo> NetworkConnections { get; } = new();

    // Reports / chart
    [ObservableProperty]
    private List<DailyThreatStat> _dailyStats = new();

    [ObservableProperty]
    private ScanSummary? _reportSummary;

    // Scheduled scan
    [ObservableProperty]
    private bool _isScheduleEnabled;

    [ObservableProperty]
    private int _scheduleIntervalHours = 24;

    [ObservableProperty]
    private string _scheduleStatus = string.Empty;

    [ObservableProperty]
    private string _scheduleNextRun = string.Empty;

    public bool IsTaskSchedulerRegistered => _taskScheduler.IsRegistered();

    // DNS blocking
    [ObservableProperty]
    private bool _isDnsBlocking;

    [ObservableProperty]
    private string _dnsBlockStatus = string.Empty;

    public bool IsAdmin => new DnsBlocker().IsAdministrator();

    // Dark web monitoring
    [ObservableProperty]
    private string _darkWebEmail = string.Empty;

    [ObservableProperty]
    private bool _isDarkWebChecking;

    [ObservableProperty]
    private string _darkWebStatus = string.Empty;

    public ObservableCollection<BreachInfo> DarkWebBreaches { get; } = new();

    // Process monitor
    [ObservableProperty]
    private bool _isScanningProcesses;

    [ObservableProperty]
    private string _processStatus = string.Empty;

    public ObservableCollection<ProcessEntry> ProcessEntries { get; } = new();

    // Dashboard / uptime
    [ObservableProperty] private string _uptimeDisplay    = "0s";
    [ObservableProperty] private int    _threatsTodayCount;
    [ObservableProperty] private int    _filesScannedToday;
    [ObservableProperty] private string _monitorStatusDisplay = "Inativo";
    [ObservableProperty] private string _lastScanDisplay      = "—";
    [ObservableProperty] private string _quarantineCountDisplay = "—";

    private readonly DateTime _startTime = DateTime.Now;
    private System.Timers.Timer? _uptimeTimer;

    // Settings
    [ObservableProperty]
    private bool _autoQuarantine = true;

    [ObservableProperty]
    private bool _notifyOnThreat = true;

    [ObservableProperty]
    private bool _notifyOnScheduledScan = true;

    [ObservableProperty]
    private bool _scanArchives;

    [ObservableProperty]
    private bool _scanUsbOnInsert = true;

    [ObservableProperty]
    private int _maxFileSizeMB = 50;

    [ObservableProperty]
    private string _newExclusionPath = string.Empty;

    [ObservableProperty]
    private string _settingsStatus = string.Empty;

    public ObservableCollection<string> ExclusionPaths { get; } = new();

    // ---- Event log ----
    public ObservableCollection<AvdonEvent> EventLog { get; } = new();

    [ObservableProperty] private int _eventsTodayCount;
    [ObservableProperty] private string _sigDbVersion = "—";
    [ObservableProperty] private string _sigLastUpdated = "—";

    public ObservableCollection<ScanResult> ScanResults { get; } = new();
    public ObservableCollection<QuarantineEntry> QuarantineEntries { get; } = new();
    public ObservableCollection<ScanResult> HistoryResults { get; } = new();

    public int CleanCount    => ScanResults.Count(r => r.Level == ThreatLevel.Clean);
    public int ThreatCount   => ScanResults.Count(r => r.Level != ThreatLevel.Clean);
    public bool IsApiKeySet  => !string.IsNullOrWhiteSpace(ClaudeApiKey);

    // ---- Start with Windows (Registry) ----
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string AppName = "AVDON";

    public bool StartWithWindows
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey);
            return key?.GetValue(AppName) != null;
        }
        set
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey, writable: true);
            if (key == null) return;
            if (value)
            {
                var exe = Environment.ProcessPath ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;
                key.SetValue(AppName, $"\"{exe}\"");
            }
            else
            {
                key.DeleteValue(AppName, throwOnMissingValue: false);
            }
            OnPropertyChanged();
        }
    }

    public MainViewModel(
        IFileScanner fileScanner,
        IQuarantineManager quarantineManager,
        IRealTimeMonitor realTimeMonitor,
        ISignatureUpdater signatureUpdater,
        ISignatureDatabase signatureDatabase,
        IScanHistory scanHistory,
        ScheduledScanner scheduledScanner,
        DarkWebMonitor darkWebMonitor,
        DnsBlocker dnsBlocker,
        NetworkMonitor networkMonitor,
        ScanReporter scanReporter,
        TaskSchedulerService taskScheduler,
        ProcessMonitorService processMonitor,
        AntivirusOS.Core.Shell.ShellContextMenuService shellMenu,
        EventLogger eventLogger)
    {
        _fileScanner = fileScanner;
        _quarantineManager = quarantineManager;
        _realTimeMonitor = realTimeMonitor;
        _signatureUpdater = signatureUpdater;
        _signatureDatabase = signatureDatabase;
        _scanHistory = scanHistory;
        _scheduledScanner = scheduledScanner;
        _darkWebMonitor = darkWebMonitor;
        _dnsBlocker = dnsBlocker;
        _networkMonitor = networkMonitor;
        _scanReporter = scanReporter;
        _taskScheduler = taskScheduler;
        _processMonitor = processMonitor;
        _shellMenu = shellMenu;
        _eventLogger = eventLogger;
        _appDataPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AVDON");
        _integrityService = new FileIntegrityService(_appDataPath);
        _hasIntegritySnapshot = _integrityService.HasSnapshot();
        _schedConfig = ScheduledScanConfig.Load(_appDataPath);
        _isScheduleEnabled = _schedConfig.Enabled;
        _scheduleIntervalHours = _schedConfig.IntervalHours;
        RefreshScheduleDisplay();

        _appSettings = AppSettings.Load(_appDataPath);
        _autoQuarantine          = _appSettings.AutoQuarantine;
        _notifyOnThreat          = _appSettings.NotifyOnThreat;
        _notifyOnScheduledScan   = _appSettings.NotifyOnScheduledScan;
        _scanArchives            = _appSettings.ScanArchives;
        _scanUsbOnInsert         = _appSettings.ScanUsbOnInsert;
        _maxFileSizeMB           = _appSettings.MaxFileSizeMB;
        foreach (var p in _appSettings.ExclusionPaths)
            ExclusionPaths.Add(p);

        _realTimeMonitor.ThreatDetected += OnThreatDetected;

        ScanResults.CollectionChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(CleanCount));
            OnPropertyChanged(nameof(ThreatCount));
        };

        HistoryResults.CollectionChanged += (_, _) =>
        {
            HistoryTotalCount = HistoryResults.Count;
            HistoryThreatCount = HistoryResults.Count(r => r.Level != ThreatLevel.Clean);
        };

        PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ClaudeApiKey))
                OnPropertyChanged(nameof(IsApiKeySet));
        };

        ClaudeApiKey = Antivirus.UI.Properties.Settings.Default.ClaudeApiKey ?? string.Empty;

        RefreshShellMenuState();
        LoadEvents();

        // Uptime ticker — fires every second
        _uptimeTimer = new System.Timers.Timer(1000);
        _uptimeTimer.Elapsed += (_, _) => RefreshDashboard();
        _uptimeTimer.Start();
    }

    partial void OnIsMonitoringChanged(bool value)
    {
        MonitoredFolderCount = value ? _realTimeMonitor.MonitoredPaths.Count : 0;
        OnPropertyChanged(nameof(MonitoredPathsList));
    }

    private void OnThreatDetected(object? sender, FileDetectedEventArgs e)
    {
        AvdonLogger.Instance.Warn("RealTimeMonitor",
            $"Ameaça detectada: {e.Result.FilePath} [{e.Result.Level}]");
        _eventLogger.Log(EventKind.ThreatDetected,
            $"Ameaça: {Path.GetFileName(e.Result.FilePath)} [{e.Result.Level}]",
            e.Result.FilePath);
        Application.Current.Dispatcher.Invoke(() =>
        {
            MonitorLog += $"[{DateTime.Now:HH:mm:ss}] AMEAÇA: {e.Result.FilePath} — {e.Result.Level}\n";
            ScanResults.Insert(0, e.Result);
            ThreatsTodayCount++;
            LoadEvents();
        });
    }

    private void RefreshDashboard()
    {
        var elapsed = DateTime.Now - _startTime;
        UptimeDisplay = elapsed.TotalHours >= 1
            ? $"{(int)elapsed.TotalHours}h {elapsed.Minutes:D2}m {elapsed.Seconds:D2}s"
            : elapsed.TotalMinutes >= 1
                ? $"{elapsed.Minutes}m {elapsed.Seconds:D2}s"
                : $"{elapsed.Seconds}s";

        MonitorStatusDisplay = IsMonitoring ? "Ativo" : "Inativo";
        LastScanDisplay      = LastScanTime.HasValue ? LastScanTime.Value.ToString("dd/MM HH:mm") : "—";
        FilesScannedToday    = ScannedCount;

        // Quarantine count refresh (fire-and-forget, non-blocking)
        _ = RefreshQuarantineCountAsync();
    }

    private async Task RefreshQuarantineCountAsync()
    {
        try
        {
            var entries = await _quarantineManager.ListAsync();
            QuarantineCountDisplay = entries.Count.ToString();
        }
        catch { }
    }

    [RelayCommand]
    private void CancelScan()
    {
        _scanCts?.Cancel();
        ScanStatus = "Scan cancelado.";
    }

    [RelayCommand]
    private async Task QuickScanAsync()
    {
        var quickPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.InternetCache),
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Windows\Start Menu\Programs\Startup"),
        };

        _scanCts = new CancellationTokenSource();
        IsScanning = true;
        ScannedCount = 0;
        CurrentScanFile = string.Empty;
        ScanStatus = "Scan Rápido em andamento…";
        int total = 0, threats = 0;
        try
        {
            foreach (var folder in quickPaths.Where(Directory.Exists).Distinct())
            {
                await foreach (var result in _fileScanner.ScanDirectoryAsync(folder, recursive: false))
                {
                    _scanCts.Token.ThrowIfCancellationRequested();
                    total++;
                    ScannedCount = total;
                    CurrentScanFile = Path.GetFileName(result.FilePath);
                    ScanStatus = $"Scan Rápido — {total} arquivo(s)…";
                    if (result.Level != ThreatLevel.Clean)
                    {
                        threats++;
                        TotalThreatsBlocked++;
                        ScanResults.Insert(0, result);
                        await _scanHistory.AddAsync(result);
                    }
                }
            }
            LastScanTime = DateTime.Now;
            ScanStatus = $"Scan Rápido concluído. {total} arquivo(s), {threats} ameaça(s).";
            _eventLogger.Log(EventKind.ScanCompleted, $"Scan Rápido: {total} arquivo(s), {threats} ameaça(s)");
            LoadEvents();
        }
        catch (OperationCanceledException) { ScanStatus = "Scan cancelado."; }
        catch (Exception ex) { ScanStatus = $"Erro: {ex.Message}"; }
        finally { IsScanning = false; CurrentScanFile = string.Empty; _scanCts?.Dispose(); _scanCts = null; }
    }

    [RelayCommand]
    private async Task FullScanAsync()
    {
        _scanCts = new CancellationTokenSource();
        IsScanning = true;
        ScannedCount = 0;
        CurrentScanFile = string.Empty;
        ScanStatus = "Scan Completo em andamento — isso pode demorar…";
        int total = 0, threats = 0;
        try
        {
            var drives = DriveInfo.GetDrives()
                .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
                .Select(d => d.RootDirectory.FullName);

            foreach (var drive in drives)
            {
                await foreach (var result in _fileScanner.ScanDirectoryAsync(drive, recursive: true))
                {
                    _scanCts.Token.ThrowIfCancellationRequested();
                    total++;
                    ScannedCount = total;
                    CurrentScanFile = Path.GetFileName(result.FilePath);
                    if (total % 50 == 0)
                        ScanStatus = $"Scan Completo — {total:N0} arquivo(s)…";
                    if (result.Level != ThreatLevel.Clean)
                    {
                        threats++;
                        TotalThreatsBlocked++;
                        ScanResults.Insert(0, result);
                        await _scanHistory.AddAsync(result);
                    }
                }
            }
            LastScanTime = DateTime.Now;
            ScanStatus = $"Scan Completo concluído. {total:N0} arquivo(s), {threats} ameaça(s).";
            _eventLogger.Log(EventKind.ScanCompleted, $"Scan Completo: {total:N0} arquivo(s), {threats} ameaça(s)");
            LoadEvents();
        }
        catch (OperationCanceledException) { ScanStatus = "Scan cancelado."; }
        catch (Exception ex) { ScanStatus = $"Erro: {ex.Message}"; }
        finally { IsScanning = false; CurrentScanFile = string.Empty; _scanCts?.Dispose(); _scanCts = null; }
    }

    [RelayCommand]
    private async Task ScanFileAsync()
    {
        var dialog = new Win32Dialog.OpenFileDialog { Title = "Selecionar arquivo para escanear" };
        if (dialog.ShowDialog() != true) return;

        IsScanning = true;
        ScanStatus = $"Escaneando: {Path.GetFileName(dialog.FileName)}…";
        try
        {
            var result = await _fileScanner.ScanFileAsync(dialog.FileName);
            ScanResults.Insert(0, result);
            await _scanHistory.AddAsync(result);
            ScanStatus = result.Level == ThreatLevel.Clean
                ? $"Limpo: {Path.GetFileName(dialog.FileName)}"
                : $"AMEAÇA ({result.Level}): {Path.GetFileName(dialog.FileName)}";
        }
        catch (Exception ex)
        {
            ScanStatus = $"Erro: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }

    [RelayCommand]
    private async Task ScanFolderAsync()
    {
        var dialog = new WinForms.FolderBrowserDialog
        {
            Description = "Selecionar pasta para escanear"
        };
        if (dialog.ShowDialog() != WinForms.DialogResult.OK) return;

        IsScanning = true;
        ScanStatus = $"Escaneando pasta: {dialog.SelectedPath}…";
        int total = 0, threats = 0;
        try
        {
            await foreach (var result in _fileScanner.ScanDirectoryAsync(dialog.SelectedPath, recursive: true))
            {
                total++;
                if (result.Level != ThreatLevel.Clean) threats++;
                ScanResults.Insert(0, result);
                await _scanHistory.AddAsync(result);
            }
            ScanStatus = $"Concluído. {total} arquivos, {threats} ameaça(s).";
        }
        catch (Exception ex)
        {
            ScanStatus = $"Erro: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }

    [RelayCommand]
    private void ToggleMonitor()
    {
        if (IsMonitoring)
        {
            _realTimeMonitor.StopMonitoring();
            IsMonitoring = false;
            MonitoredPath = string.Empty;
            MonitoredFolderCount = 0;
            OnPropertyChanged(nameof(MonitoredPathsList));
            MonitorLog += $"[{DateTime.Now:HH:mm:ss}] Monitoramento parado.\n";
        }
        else
        {
            // Re-start critical folder monitoring
            var criticalPaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    @"Microsoft\Windows\Start Menu\Programs\Startup"),
            };
            _realTimeMonitor.StartMonitoring(criticalPaths);
            IsMonitoring = true;
            MonitoredPath = "Pastas críticas";
            MonitoredFolderCount = _realTimeMonitor.MonitoredPaths.Count;
            OnPropertyChanged(nameof(MonitoredPathsList));
            MonitorLog += $"[{DateTime.Now:HH:mm:ss}] Monitorando: Downloads, Área de Trabalho, Inicialização\n";
        }
    }

    [RelayCommand]
    private async Task QuarantineResultAsync(ScanResult? result)
    {
        if (result is null) return;
        try
        {
            var entry = await _quarantineManager.QuarantineAsync(result.FilePath, result.Hash);
            QuarantineEntries.Insert(0, entry);
            ScanResults.Remove(result);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Erro ao quarentenar: {ex.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [RelayCommand]
    private async Task RestoreEntryAsync(QuarantineEntry? entry)
    {
        if (entry is null) return;
        try
        {
            await _quarantineManager.RestoreAsync(entry);
            QuarantineEntries.Remove(entry);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Erro ao restaurar: {ex.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [RelayCommand]
    private async Task DeleteEntryAsync(QuarantineEntry? entry)
    {
        if (entry is null) return;
        var confirm = MessageBox.Show(
            $"Deletar permanentemente?\n{entry.OriginalPath}",
            "Confirmar", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;
        try
        {
            await _quarantineManager.DeleteAsync(entry);
            QuarantineEntries.Remove(entry);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Erro ao deletar: {ex.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // Raised when user clicks Inspecionar — View subscribes to open QuarantineDetailWindow
    public event EventHandler<QuarantineEntry>? InspectEntryRequested;

    [RelayCommand]
    private void InspectEntry(QuarantineEntry? entry)
    {
        if (entry is null) return;
        InspectEntryRequested?.Invoke(this, entry);
    }

    [RelayCommand]
    private async Task UpdateSignaturesAsync()
    {
        IsUpdatingSignatures = true;
        ScanStatus = "Atualizando assinaturas do MalwareBazaar…";
        try
        {
            var added = await _signatureUpdater.UpdateFromMalwareBazaarAsync();
            SignatureCount = await _signatureDatabase.CountAsync();
            ScanStatus = $"Assinaturas atualizadas. {added} novas. Total: {SignatureCount:N0}.";
            SigLastUpdated = DateTime.Now.ToString("dd/MM/yyyy HH:mm");
            SigDbVersion   = SignatureCount.ToString("N0");
            _eventLogger.Log(EventKind.SignaturesUpdated,
                $"Assinaturas: {added} novas. Total: {SignatureCount:N0}");
            LoadEvents();
        }
        catch (Exception ex)
        {
            ScanStatus = $"Erro ao atualizar: {ex.Message}";
        }
        finally
        {
            IsUpdatingSignatures = false;
        }
    }

    [RelayCommand]
    private async Task EnableDnsBlockingAsync()
    {
        IsDnsBlocking = true;
        DnsBlockStatus = "Aplicando bloqueio DNS…";
        try
        {
            var (success, msg) = await _dnsBlocker.ApplyBlockListAsync(AntivirusOS.Core.Network.DnsBlocker.DefaultBlockList);
            DnsBlockStatus = success ? $"✓ {msg}" : $"✗ {msg}";
        }
        catch (Exception ex) { DnsBlockStatus = $"Erro: {ex.Message}"; }
        finally { IsDnsBlocking = false; }
    }

    [RelayCommand]
    private async Task DisableDnsBlockingAsync()
    {
        IsDnsBlocking = true;
        DnsBlockStatus = "Removendo bloqueio DNS…";
        try
        {
            var (success, msg) = await _dnsBlocker.ClearBlockListAsync();
            DnsBlockStatus = success ? $"✓ {msg}" : $"✗ {msg}";
        }
        catch (Exception ex) { DnsBlockStatus = $"Erro: {ex.Message}"; }
        finally { IsDnsBlocking = false; }
    }

    [RelayCommand]
    private async Task CheckDarkWebAsync()
    {
        if (string.IsNullOrWhiteSpace(DarkWebEmail)) return;
        IsDarkWebChecking = true;
        DarkWebStatus = "Verificando vazamentos de dados…";
        DarkWebBreaches.Clear();
        try
        {
            var breaches = await _darkWebMonitor.CheckEmailAsync(DarkWebEmail);
            if (breaches.Count == 0)
            {
                DarkWebStatus = $"Nenhum vazamento encontrado para {DarkWebEmail}";
            }
            else
            {
                foreach (var b in breaches)
                    DarkWebBreaches.Add(b);
                DarkWebStatus = $"⚠ {breaches.Count} vazamento(s) encontrado(s) para {DarkWebEmail}";
            }
        }
        catch (Exception ex)
        {
            DarkWebStatus = $"Erro: {ex.Message}";
        }
        finally
        {
            IsDarkWebChecking = false;
        }
    }

    [RelayCommand]
    private async Task SaveApiKeyAsync()
    {
        Antivirus.UI.Properties.Settings.Default.ClaudeApiKey = ClaudeApiKey;
        Antivirus.UI.Properties.Settings.Default.Save();
        SignatureCount = await _signatureDatabase.CountAsync();
        MessageBox.Show("Configurações salvas. Reinicie o aplicativo para aplicar a nova API key do Claude.", "AntivirusOS", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    [RelayCommand]
    private async Task LoadQuarantineAsync()
    {
        try
        {
            var entries = await _quarantineManager.ListAsync();
            QuarantineEntries.Clear();
            foreach (var e in entries)
                QuarantineEntries.Add(e);
        }
        catch { /* silent */ }
    }

    [RelayCommand]
    private async Task LoadHistoryAsync()
    {
        try
        {
            var items = await _scanHistory.GetRecentAsync(100);
            HistoryResults.Clear();
            foreach (var item in items)
                HistoryResults.Add(item);
        }
        catch (Exception ex)
        {
            ScanStatus = $"Erro ao carregar histórico: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task ToggleScheduledScanAsync()
    {
        if (IsScheduledScanRunning)
        {
            _scheduledScanCts?.Cancel();
            _scheduledScanner.Stop();
            IsScheduledScanRunning = false;
            ScanStatus = "Scan agendado parado.";
        }
        else
        {
            if (string.IsNullOrWhiteSpace(ScheduledScanPath))
            {
                var dialog = new WinForms.FolderBrowserDialog
                {
                    Description = "Selecionar pasta para scan agendado"
                };
                if (dialog.ShowDialog() != WinForms.DialogResult.OK) return;
                ScheduledScanPath = dialog.SelectedPath;
            }
            _scheduledScanCts = new CancellationTokenSource();
            IsScheduledScanRunning = true;
            ScanStatus = $"Scan agendado iniciado: {ScheduledScanPath}";
            var path = ScheduledScanPath;
            var token = _scheduledScanCts.Token;
            _ = _scheduledScanner.StartAsync(path, TimeSpan.FromHours(24), token);
        }
        await Task.CompletedTask;
    }

    [RelayCommand]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private async Task RefreshNetworkAsync()
    {
        IsRefreshingNetwork = true;
        NetworkStatus = "Atualizando conexões…";
        try
        {
            var connections = await _networkMonitor.GetConnectionsAsync();
            NetworkConnections.Clear();
            foreach (var c in connections.OrderByDescending(c => c.IsSuspicious))
                NetworkConnections.Add(c);
            var suspicious = connections.Count(c => c.IsSuspicious);
            NetworkStatus = suspicious > 0
                ? $"⚠ {suspicious} conexão(ões) suspeita(s) de {connections.Count} ativas"
                : $"✓ {connections.Count} conexão(ões) ativas — sem suspeitas";
        }
        catch (Exception ex) { NetworkStatus = $"Erro: {ex.Message}"; }
        finally { IsRefreshingNetwork = false; }
    }

    [RelayCommand]
    private async Task ExportHistoryCsvAsync()
    {
        var dialog = new Win32Dialog.SaveFileDialog
        {
            Title = "Exportar histórico de scan",
            Filter = "CSV|*.csv",
            FileName = $"avdon_historico_{DateTime.Now:yyyyMMdd_HHmm}.csv"
        };
        if (dialog.ShowDialog() != true) return;
        try
        {
            await _scanReporter.ExportToCsvAsync(HistoryResults, dialog.FileName);
            ScanStatus = $"Histórico exportado: {Path.GetFileName(dialog.FileName)}";
        }
        catch (Exception ex) { ScanStatus = $"Erro ao exportar: {ex.Message}"; }
    }

    // ---- Reports ----

    [RelayCommand]
    private async Task RefreshReportAsync()
    {
        var history = await _scanHistory.GetAllAsync();
        DailyStats    = _scanReporter.GetDailyStats(history, lastDays: 30);
        ReportSummary = _scanReporter.GetSummary(history);
    }

    [RelayCommand]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private async Task ScanProcessesAsync()
    {
        if (IsScanningProcesses)
        {
            _procScanCts?.Cancel();
            return;
        }

        _procScanCts = new CancellationTokenSource();
        IsScanningProcesses = true;
        ProcessStatus = "Escaneando processos…";
        ProcessEntries.Clear();

        try
        {
            var entries = await _processMonitor.ScanAsync(_procScanCts.Token);
            foreach (var e in entries)
                ProcessEntries.Add(e);

            int threats = entries.Count(e => e.Level != AntivirusOS.Core.Models.ThreatLevel.Clean);
            ProcessStatus = threats == 0
                ? $"{entries.Count} processos verificados — sem ameaças."
                : $"⚠ {threats} processo(s) suspeito(s) em {entries.Count} verificados.";
        }
        catch (OperationCanceledException) { ProcessStatus = "Scan de processos cancelado."; }
        catch (Exception ex)               { ProcessStatus = $"Erro: {ex.Message}"; }
        finally { IsScanningProcesses = false; }
    }

    [RelayCommand]
    private async Task ExportHtmlReportAsync()
    {
        var history = await _scanHistory.GetAllAsync();
        if (!history.Any()) { ScanStatus = "Sem dados para exportar."; return; }

        var dialog = new Win32Dialog.SaveFileDialog
        {
            Title      = "Exportar Relatório HTML",
            Filter     = "Arquivo HTML|*.html",
            FileName   = $"AVDON_Relatorio_{DateTime.Now:yyyyMMdd}.html",
        };
        if (dialog.ShowDialog() != true) return;

        try
        {
            var ver = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            var verStr = ver != null ? $"{ver.Major}.{ver.Minor}.{ver.Build}" : "—";
            var gen = new AntivirusOS.Core.Reports.HtmlReportGenerator();
            await gen.GenerateAsync(history, dialog.FileName, verStr);
            ScanStatus = $"Relatório HTML exportado: {Path.GetFileName(dialog.FileName)}";

            // Open in default browser
            try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(dialog.FileName) { UseShellExecute = true }); }
            catch { }
        }
        catch (Exception ex) { ScanStatus = $"Erro ao exportar relatório: {ex.Message}"; }
    }

    // ---- App Settings ----

    // ---- Hosts file checker ----
    public ObservableCollection<HostsEntry> HostsEntries { get; } = new();
    [ObservableProperty] private bool   _isCheckingHosts;
    [ObservableProperty] private string _hostsStatus         = "Nenhuma verificação executada.";
    [ObservableProperty] private int    _hostsSuspiciousCount;

    [RelayCommand]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private async Task CheckHostsAsync()
    {
        IsCheckingHosts = true;
        HostsStatus = "Analisando arquivo hosts…";
        try
        {
            var entries = await _hostsChecker.AnalyzeAsync();
            HostsEntries.Clear();
            foreach (var e in entries) HostsEntries.Add(e);
            HostsSuspiciousCount = entries.Count(e =>
                e.Risk is HostsEntryRisk.Suspicious or HostsEntryRisk.Malicious);
            HostsStatus = HostsSuspiciousCount == 0
                ? $"✓ Hosts OK — {entries.Count} entrada(s) analisada(s)."
                : $"⚠ {HostsSuspiciousCount} entrada(s) suspeita(s) em {entries.Count} total.";
            if (HostsSuspiciousCount > 0)
                _eventLogger.Log(AntivirusOS.Core.Events.EventKind.ThreatDetected,
                    $"Hosts: {HostsSuspiciousCount} entrada(s) suspeita(s)");
        }
        catch (Exception ex) { HostsStatus = $"Erro: {ex.Message}"; }
        finally { IsCheckingHosts = false; }
    }

    // ---- Sensitive file detector ----
    public ObservableCollection<SensitiveFileResult> SensitiveFiles { get; } = new();
    [ObservableProperty] private bool   _isScanningForSensitive;
    [ObservableProperty] private string _sensitiveStatus    = "Nenhuma varredura executada.";
    [ObservableProperty] private int    _sensitiveHighCount;

    [RelayCommand]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private async Task ScanSensitiveFilesAsync()
    {
        IsScanningForSensitive = true;
        SensitiveStatus = "Procurando arquivos sensíveis…";
        try
        {
            var results = await _sensitiveDetector.ScanAsync();
            SensitiveFiles.Clear();
            foreach (var r in results.OrderByDescending(r => r.Risk)) SensitiveFiles.Add(r);
            SensitiveHighCount = results.Count(r => r.Risk == SensitiveFileRisk.High);
            SensitiveStatus = results.Count == 0
                ? "Nenhum arquivo sensível encontrado."
                : $"{results.Count} arquivo(s) encontrado(s). {SensitiveHighCount} de alto risco.";
            if (SensitiveHighCount > 0)
                _eventLogger.Log(AntivirusOS.Core.Events.EventKind.ThreatDetected,
                    $"Arquivos sensíveis: {SensitiveHighCount} de alto risco");
        }
        catch (Exception ex) { SensitiveStatus = $"Erro: {ex.Message}"; }
        finally { IsScanningForSensitive = false; }
    }

    // ---- Wi-Fi scanner ----
    public ObservableCollection<WifiNetwork> WifiNetworks { get; } = new();

    [ObservableProperty] private bool        _isScanningWifi;
    [ObservableProperty] private string      _wifiStatus       = "Nenhum scan executado.";
    [ObservableProperty] private string      _connectedSsid    = "—";
    [ObservableProperty] private string      _connectedSecurity = "—";
    [ObservableProperty] private int         _wifiInsecureCount;

    [RelayCommand]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private async Task ScanWifiAsync()
    {
        IsScanningWifi = true;
        WifiStatus = "Escaneando redes Wi-Fi…";
        try
        {
            var (connected, all) = await _wifiScanner.ScanAsync();
            WifiNetworks.Clear();
            foreach (var n in all.OrderByDescending(n => n.IsConnected).ThenByDescending(n => n.SignalPercent))
                WifiNetworks.Add(n);

            WifiInsecureCount = all.Count(n => n.IsInsecure);
            ConnectedSsid     = connected?.SSID ?? "Desconectado";
            ConnectedSecurity = connected?.Security.ToString() ?? "—";

            WifiStatus = all.Count == 0
                ? "Nenhuma rede encontrada (Wi-Fi desligado?)."
                : $"{all.Count} rede(s). {WifiInsecureCount} insegura(s).";

            if (WifiInsecureCount > 0)
                _eventLogger.Log(AntivirusOS.Core.Events.EventKind.ThreatDetected,
                    $"Wi-Fi: {WifiInsecureCount} rede(s) insegura(s) detectada(s)",
                    string.Join(", ", all.Where(n => n.IsInsecure).Select(n => n.SSID)));
        }
        catch (Exception ex) { WifiStatus = $"Erro: {ex.Message}"; }
        finally { IsScanningWifi = false; }
    }

    // ---- File integrity ----
    public ObservableCollection<IntegrityEntry> IntegrityResults { get; } = new();

    [ObservableProperty] private bool   _isCheckingIntegrity;
    [ObservableProperty] private string _integrityStatus  = "Nenhuma verificação executada ainda.";
    [ObservableProperty] private bool   _hasIntegritySnapshot;
    [ObservableProperty] private int    _integrityModifiedCount;
    [ObservableProperty] private int    _integrityMissingCount;

    [RelayCommand]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private async Task TakeIntegritySnapshotAsync()
    {
        _integrityCts?.Cancel();
        _integrityCts = new CancellationTokenSource();
        IsCheckingIntegrity = true;
        IntegrityStatus = "Calculando hashes — criando snapshot…";
        try
        {
            var entries = await _integrityService.TakeSnapshotAsync(ct: _integrityCts.Token);
            IntegrityResults.Clear();
            foreach (var e in entries) IntegrityResults.Add(e);
            HasIntegritySnapshot = true;
            IntegrityStatus = $"Snapshot criado. {entries.Count} arquivo(s) registrado(s).";
            _eventLogger.Log(AntivirusOS.Core.Events.EventKind.ScanCompleted,
                $"Integrity snapshot: {entries.Count} arquivo(s)");
        }
        catch (OperationCanceledException) { IntegrityStatus = "Cancelado."; }
        catch (Exception ex) { IntegrityStatus = $"Erro: {ex.Message}"; }
        finally { IsCheckingIntegrity = false; }
    }

    [RelayCommand]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private async Task VerifyIntegrityAsync()
    {
        _integrityCts?.Cancel();
        _integrityCts = new CancellationTokenSource();
        IsCheckingIntegrity = true;
        IntegrityStatus = "Verificando integridade dos arquivos críticos…";
        try
        {
            var entries = await _integrityService.VerifyAsync(ct: _integrityCts.Token);
            IntegrityResults.Clear();
            foreach (var e in entries) IntegrityResults.Add(e);
            IntegrityModifiedCount = entries.Count(e => e.Status == AntivirusOS.Core.Integrity.IntegrityStatus.Modified);
            IntegrityMissingCount  = entries.Count(e => e.Status == AntivirusOS.Core.Integrity.IntegrityStatus.Missing);
            var ok = IntegrityModifiedCount + IntegrityMissingCount == 0;
            IntegrityStatus = ok
                ? $"✓ Todos os {entries.Count} arquivo(s) íntegros."
                : $"⚠ {IntegrityModifiedCount} modificado(s), {IntegrityMissingCount} ausente(s) de {entries.Count}.";
            if (!ok)
                _eventLogger.Log(AntivirusOS.Core.Events.EventKind.ThreatDetected,
                    IntegrityStatus, $"Modified:{IntegrityModifiedCount} Missing:{IntegrityMissingCount}");
        }
        catch (OperationCanceledException) { IntegrityStatus = "Cancelado."; }
        catch (Exception ex) { IntegrityStatus = $"Erro: {ex.Message}"; }
        finally { IsCheckingIntegrity = false; }
    }

    // ---- Startup items ----
    public ObservableCollection<StartupItem> StartupItems { get; } = new();

    [ObservableProperty] private bool   _isLoadingStartup;
    [ObservableProperty] private string _startupStatus = string.Empty;
    [ObservableProperty] private int    _startupSuspiciousCount;

    [RelayCommand]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private async Task ScanStartupAsync()
    {
        IsLoadingStartup = true;
        StartupStatus = "Enumerando itens de inicialização…";
        try
        {
            var items = await Task.Run(() => _startupManager.Enumerate());
            StartupItems.Clear();
            foreach (var item in items)
                StartupItems.Add(item);
            StartupSuspiciousCount = items.Count(i => i.Level is StartupThreatLevel.Suspicious or StartupThreatLevel.Malicious);
            StartupStatus = $"{items.Count} item(s) encontrado(s). {StartupSuspiciousCount} suspeito(s).";
            _eventLogger.Log(AntivirusOS.Core.Events.EventKind.ScanStarted,
                $"Inicialização: {items.Count} item(s), {StartupSuspiciousCount} suspeito(s)");
        }
        catch (Exception ex) { StartupStatus = $"Erro: {ex.Message}"; }
        finally { IsLoadingStartup = false; }
    }

    [RelayCommand]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private void DisableStartupItem(StartupItem? item)
    {
        if (item is null) return;
        var (ok, msg) = _startupManager.Disable(item);
        StartupStatus = msg;
        if (ok)
        {
            StartupItems.Remove(item);
            _eventLogger.Log(AntivirusOS.Core.Events.EventKind.ScanStarted, $"Startup desabilitado: {item.Name}");
        }
    }

    // ---- Event log helpers ----

    private void LoadEvents()
    {
        var events = _eventLogger.GetRecent(200);
        EventsTodayCount = _eventLogger.CountToday();
        Application.Current?.Dispatcher.Invoke(() =>
        {
            EventLog.Clear();
            foreach (var ev in events)
                EventLog.Add(ev);
        });
    }

    [RelayCommand]
    private void RefreshEvents() => LoadEvents();

    [RelayCommand]
    private void ClearEvents()
    {
        // Just clears the in-memory list; DB rows stay for auditing
        EventLog.Clear();
    }

    [ObservableProperty]
    private bool _isShellMenuRegistered;

    [ObservableProperty]
    private string _shellMenuStatus = string.Empty;

    private void RefreshShellMenuState() =>
        IsShellMenuRegistered = _shellMenu.IsRegistered();

    [RelayCommand]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private void RegisterShellMenu()
    {
        var exe = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
                  ?? Environment.ProcessPath ?? string.Empty;
        if (string.IsNullOrEmpty(exe)) { ShellMenuStatus = "Executável não encontrado."; return; }

        var (ok, msg) = _shellMenu.Register(exe);
        ShellMenuStatus = msg;
        IsShellMenuRegistered = ok && _shellMenu.IsRegistered();
        AvdonLogger.Instance.Info("ShellMenu", msg);
    }

    [RelayCommand]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private void UnregisterShellMenu()
    {
        var (_, msg) = _shellMenu.Unregister();
        ShellMenuStatus = msg;
        IsShellMenuRegistered = _shellMenu.IsRegistered();
        AvdonLogger.Instance.Info("ShellMenu", msg);
    }

    [RelayCommand]
    private void SaveSettings()
    {
        _appSettings.AutoQuarantine        = AutoQuarantine;
        _appSettings.NotifyOnThreat        = NotifyOnThreat;
        _appSettings.NotifyOnScheduledScan = NotifyOnScheduledScan;
        _appSettings.ScanArchives          = ScanArchives;
        _appSettings.ScanUsbOnInsert       = ScanUsbOnInsert;
        _appSettings.MaxFileSizeMB         = MaxFileSizeMB;
        _appSettings.ExclusionPaths        = ExclusionPaths.ToList();
        _appSettings.Save(_appDataPath);
        SettingsStatus = "Configurações salvas.";
        AvdonLogger.Instance.Info("Settings", "Configurações salvas pelo usuário.");
    }

    [RelayCommand]
    private void AddExclusionPath()
    {
        var path = NewExclusionPath.Trim();
        if (string.IsNullOrEmpty(path) || ExclusionPaths.Contains(path)) return;
        ExclusionPaths.Add(path);
        NewExclusionPath = string.Empty;
        SettingsStatus = $"Exclusão adicionada: {path}";
    }

    [RelayCommand]
    private void RemoveExclusionPath(string path)
    {
        ExclusionPaths.Remove(path);
        SettingsStatus = $"Exclusão removida: {path}";
    }

    [RelayCommand]
    private void BrowseExclusionPath()
    {
        using var dlg = new WinForms.FolderBrowserDialog { Description = "Selecione uma pasta para excluir do scan" };
        if (dlg.ShowDialog() == WinForms.DialogResult.OK)
            NewExclusionPath = dlg.SelectedPath;
    }

    // ---- Scheduled scan via Windows Task Scheduler ----

    [RelayCommand]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private void EnableTaskSchedule()
    {
        var exe = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
                  ?? Environment.ProcessPath ?? string.Empty;
        if (string.IsNullOrEmpty(exe)) { ScheduleStatus = "Não foi possível obter o caminho do executável."; return; }

        _schedConfig.Enabled = true;
        _schedConfig.IntervalHours = ScheduleIntervalHours;
        _schedConfig.NextRun = DateTime.Now.AddHours(ScheduleIntervalHours);
        _schedConfig.Save(_appDataPath);

        var (ok, msg) = _taskScheduler.Register(exe, ScheduleIntervalHours);
        IsScheduleEnabled = ok;
        ScheduleStatus = msg;
        RefreshScheduleDisplay();
        OnPropertyChanged(nameof(IsTaskSchedulerRegistered));
    }

    [RelayCommand]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private void DisableTaskSchedule()
    {
        _schedConfig.Enabled = false;
        _schedConfig.NextRun = null;
        _schedConfig.Save(_appDataPath);

        var (_, msg) = _taskScheduler.Unregister();
        IsScheduleEnabled = false;
        ScheduleStatus = msg;
        ScheduleNextRun = string.Empty;
        OnPropertyChanged(nameof(IsTaskSchedulerRegistered));
    }

    private void RefreshScheduleDisplay()
    {
        ScheduleNextRun = _schedConfig.NextRun.HasValue
            ? _schedConfig.NextRun.Value.ToString("dd/MM/yyyy HH:mm")
            : "Não agendado";
        ScheduleStatus = _schedConfig.Enabled
            ? $"Ativo — a cada {_schedConfig.IntervalHours}h"
            : "Desativado";
    }

    public async Task InitializeAsync()
    {
        await _signatureDatabase.InitializeAsync();
        await _scanHistory.InitializeAsync();
        SignatureCount = await _signatureDatabase.CountAsync();
        await LoadQuarantineAsync();
    }
}
