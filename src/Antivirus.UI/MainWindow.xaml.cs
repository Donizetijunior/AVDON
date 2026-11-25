using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Antivirus.UI.ViewModels;
using AntivirusOS.Core.Models;
using WpfDataFormats    = System.Windows.DataFormats;
using WpfDragEventArgs  = System.Windows.DragEventArgs;
using WpfDragDropEffects = System.Windows.DragDropEffects;
using AntivirusOS.Core.Quarantine;
using AntivirusOS.Core.Monitor;
using AntivirusOS.Core.Ransomware;
using AntivirusOS.Core.Network;
using AntivirusOS.Core.Scheduler;
using WpfColor      = System.Windows.Media.Color;
using WpfFontFamily = System.Windows.Media.FontFamily;
using WpfPen        = System.Windows.Media.Pen;
using WpfPoint      = System.Windows.Point;
using WpfRect       = System.Windows.Rect;

namespace Antivirus.UI;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;

    private readonly IQuarantineManager _quarantineManager;
    private readonly IRealTimeMonitor _realTimeMonitor;
    private readonly RansomwareGuard _ransomGuard;
    private readonly DnsBlocker _dnsBlocker;
    private readonly TaskSchedulerService _taskScheduler;

    public MainWindow(MainViewModel viewModel, IQuarantineManager quarantineManager,
        IRealTimeMonitor realTimeMonitor, RansomwareGuard ransomGuard,
        DnsBlocker dnsBlocker, TaskSchedulerService taskScheduler)
    {
        InitializeComponent();
        _vm = viewModel;
        _quarantineManager = quarantineManager;
        _realTimeMonitor = realTimeMonitor;
        _ransomGuard = ransomGuard;
        _dnsBlocker = dnsBlocker;
        _taskScheduler = taskScheduler;
        DataContext = viewModel;
        Icon = CreateAvdonIcon();

        viewModel.InspectEntryRequested += OnInspectEntry;

        AllowDrop = true;
        Drop      += OnWindowDrop;
        DragOver  += (_, e) =>
        {
            e.Effects = e.Data.GetDataPresent(WpfDataFormats.FileDrop)
                ? WpfDragDropEffects.Copy
                : WpfDragDropEffects.None;
            e.Handled = true;
        };
    }

    private void OnInspectEntry(object? sender, QuarantineEntry entry)
    {
        var win = new QuarantineDetailWindow(entry, _quarantineManager, () =>
        {
            _vm.LoadQuarantineCommand.Execute(null);
        });
        win.Owner = this;
        win.ShowDialog();
    }

    // ── App icon (taskbar + title bar) ───────────────────────────────────
    private static ImageSource CreateAvdonIcon()
    {
        const int size = 32;
        var dv = new DrawingVisual();
        using (var dc = dv.RenderOpen())
        {
            // Dark background
            dc.DrawRectangle(
                new SolidColorBrush(WpfColor.FromRgb(13, 17, 23)),
                null,
                new WpfRect(0, 0, size, size));

            // Shield shape
            var shield = new StreamGeometry();
            using (var ctx = shield.Open())
            {
                ctx.BeginFigure(new WpfPoint(16, 1), true, true);
                ctx.LineTo(new WpfPoint(29, 7),  true, false);
                ctx.LineTo(new WpfPoint(29, 17), true, false);
                ctx.LineTo(new WpfPoint(16, 31), true, false);
                ctx.LineTo(new WpfPoint(3,  17), true, false);
                ctx.LineTo(new WpfPoint(3,  7),  true, false);
            }
            var cyan = WpfColor.FromRgb(0, 200, 255);
            dc.DrawGeometry(
                new SolidColorBrush(WpfColor.FromArgb(45, 0, 200, 255)),
                new WpfPen(new SolidColorBrush(cyan), 1.6),
                shield);

            // "A" letter
            var ft = new FormattedText(
                "A",
                CultureInfo.CurrentCulture,
                System.Windows.FlowDirection.LeftToRight,
                new Typeface(new WpfFontFamily("Segoe UI"),
                    FontStyles.Normal, FontWeights.Bold, FontStretches.Normal),
                15,
                new SolidColorBrush(cyan),
                1.0);
            dc.DrawText(ft, new WpfPoint(10.5, 7));
        }

        var rtb = new RenderTargetBitmap(size, size, 96, 96, PixelFormats.Pbgra32);
        rtb.Render(dv);
        rtb.Freeze();
        return rtb;
    }

    // ── Custom title bar ─────────────────────────────────────────────────
    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
            WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;
        else
            DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState.Minimized;

    private void MaxRestore_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal
            : WindowState.Maximized;

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    // ── API Key panel ────────────────────────────────────────────────────
    private void ToggleApiKeyPanel_Click(object sender, RoutedEventArgs e)
    {
        var visible = ApiKeyPanel.Visibility == Visibility.Visible;
        ApiKeyPanel.Visibility = visible ? Visibility.Collapsed : Visibility.Visible;
        if (!visible) ApiKeyBox.Focus();
    }

    private void ApiKeyBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        _vm.ClaudeApiKey = ApiKeyBox.Password;
    }

    private void SaveApiKey_Click(object sender, RoutedEventArgs e)
    {
        Antivirus.UI.Properties.Settings.Default.ClaudeApiKey = ApiKeyBox.Password;
        Antivirus.UI.Properties.Settings.Default.Save();
        _vm.ClaudeApiKey = ApiKeyBox.Password;
        ApiKeyBox.Clear();
        ApiKeyPanel.Visibility = Visibility.Collapsed;
    }

    private void CancelApiKey_Click(object sender, RoutedEventArgs e)
    {
        ApiKeyBox.Clear();
        _vm.ClaudeApiKey = Antivirus.UI.Properties.Settings.Default.ClaudeApiKey ?? string.Empty;
        ApiKeyPanel.Visibility = Visibility.Collapsed;
    }

    private void OnWindowDrop(object sender, WpfDragEventArgs e)
    {
        if (!e.Data.GetDataPresent(WpfDataFormats.FileDrop)) return;
        var paths = (string[])e.Data.GetData(WpfDataFormats.FileDrop);
        if (paths == null || paths.Length == 0) return;

        // Scan the first dropped path; expand directories to their direct children
        var filesToScan = new List<string>();
        foreach (var p in paths)
        {
            if (Directory.Exists(p))
                filesToScan.Add(p);
            else if (File.Exists(p))
                filesToScan.Add(p);
        }

        if (filesToScan.Count == 0) return;

        // Reuse FullScan with the dropped path(s) via ScanPath
        _vm.ScanPath = filesToScan[0];
        _vm.FullScanCommand.Execute(null);
    }

    private void About_Click(object sender, RoutedEventArgs e)
    {
        var about = new AboutWindow(_realTimeMonitor, _ransomGuard, _dnsBlocker, _taskScheduler)
        {
            Owner = this
        };
        about.ShowDialog();
    }
}
