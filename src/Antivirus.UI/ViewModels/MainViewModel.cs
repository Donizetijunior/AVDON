using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using AntivirusOS.Core.Models;
using AntivirusOS.Core.Scanner;
using AntivirusOS.Core.Quarantine;
using AntivirusOS.Core.Monitor;
using AntivirusOS.Core.Signatures;
using AntivirusOS.Core.Updater;
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

    private CancellationTokenSource? _scheduledScanCts;

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

    public ObservableCollection<ScanResult> ScanResults { get; } = new();
    public ObservableCollection<QuarantineEntry> QuarantineEntries { get; } = new();
    public ObservableCollection<ScanResult> HistoryResults { get; } = new();

    // ---- Start with Windows (Registry) ----
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string AppName = "AntivirusOS";

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
        ScheduledScanner scheduledScanner)
    {
        _fileScanner = fileScanner;
        _quarantineManager = quarantineManager;
        _realTimeMonitor = realTimeMonitor;
        _signatureUpdater = signatureUpdater;
        _signatureDatabase = signatureDatabase;
        _scanHistory = scanHistory;
        _scheduledScanner = scheduledScanner;

        _realTimeMonitor.ThreatDetected += OnThreatDetected;

        ClaudeApiKey = Antivirus.UI.Properties.Settings.Default.ClaudeApiKey ?? string.Empty;
    }

    private void OnThreatDetected(object? sender, FileDetectedEventArgs e)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            MonitorLog += $"[{DateTime.Now:HH:mm:ss}] AMEAÇA: {e.Result.FilePath} — {e.Result.Level}\n";
            ScanResults.Insert(0, e.Result);
        });
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
            MonitorLog += $"[{DateTime.Now:HH:mm:ss}] Monitoramento parado.\n";
        }
        else
        {
            if (string.IsNullOrWhiteSpace(MonitoredPath))
            {
                var dialog = new WinForms.FolderBrowserDialog
                {
                    Description = "Selecionar pasta para monitorar"
                };
                if (dialog.ShowDialog() != WinForms.DialogResult.OK) return;
                MonitoredPath = dialog.SelectedPath;
            }
            _realTimeMonitor.StartMonitoring(MonitoredPath);
            IsMonitoring = true;
            MonitorLog += $"[{DateTime.Now:HH:mm:ss}] Monitorando: {MonitoredPath}\n";
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

    public async Task InitializeAsync()
    {
        await _signatureDatabase.InitializeAsync();
        await _scanHistory.InitializeAsync();
        SignatureCount = await _signatureDatabase.CountAsync();
        await LoadQuarantineAsync();
    }
}
