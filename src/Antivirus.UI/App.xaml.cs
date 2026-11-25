using System.IO;
using System.Windows;
using AntivirusOS.Core.AI;
using AntivirusOS.Core.Monitor;
using AntivirusOS.Core.Quarantine;
using AntivirusOS.Core.Scanner;
using AntivirusOS.Core.Signatures;
using AntivirusOS.Core.Updater;
using Antivirus.UI.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using UISettings = Antivirus.UI.Properties.Settings;

namespace Antivirus.UI;

public partial class App : Application
{
    private ServiceProvider? _serviceProvider;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var services = new ServiceCollection();
        ConfigureServices(services);
        _serviceProvider = services.BuildServiceProvider();

        var mainViewModel = _serviceProvider.GetRequiredService<MainViewModel>();
        await mainViewModel.InitializeAsync();

        var mainWindow = new MainWindow(mainViewModel);
        mainWindow.Show();
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        var appDataPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "AntivirusOS");
        Directory.CreateDirectory(appDataPath);

        var dbPath = Path.Combine(appDataPath, "signatures.db");
        var quarantinePath = Path.Combine(appDataPath, "quarantine");

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

        services.AddSingleton<MainViewModel>();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _serviceProvider?.Dispose();
        base.OnExit(e);
    }
}
