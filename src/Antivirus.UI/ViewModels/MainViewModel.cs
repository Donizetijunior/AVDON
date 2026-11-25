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
using WinForms = System.Windows.Forms;
using Win32 = Microsoft.Win32;

namespace Antivirus.UI.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly IFileScanner _fileScanner;
    private readonly IQuarantineManager _quarantineManager;
    private readonly IRealTimeMonitor _realTimeMonitor;
    private readonly ISignatureUpdater _signatureUpdater;
    private readonly ISignatureDatabase _signatureDatabase;

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

    public ObservableCollection<ScanResult> ScanResults { get; } = new();
    public ObservableCollection<QuarantineEntry> QuarantineEntries { get; } = new();

    public MainViewModel(
        IFileScanner fileScanner,
        IQuarantineManager quarantineManager,
        IRealTimeMonitor realTimeMonitor,
        ISignatureUpdater signatureUpdater,
        ISignatureDatabase signatureDatabase)
    {
        _fileScanner = fileScanner;
        _quarantineManager = quarantineManager;
        _realTimeMonitor = realTimeMonitor;
        _signatureUpdater = signatureUpdater;
        _signatureDatabase = signatureDatabase;

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
        var dialog = new Win32.OpenFileDialog { Title = "Selecionar arquivo para escanear" };
        if (dialog.ShowDialog() != true) return;

        IsScanning = true;
        ScanStatus = $"Escaneando: {Path.GetFileName(dialog.FileName)}…";
        try
        {
            var result = await _fileScanner.ScanFileAsync(dialog.FileName);
            ScanResults.Insert(0, result);
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

    public async Task InitializeAsync()
    {
        await _signatureDatabase.InitializeAsync();
        SignatureCount = await _signatureDatabase.CountAsync();
        await LoadQuarantineAsync();
    }
}
