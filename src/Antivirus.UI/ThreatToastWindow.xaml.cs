using System.IO;
using System.Windows;
using System.Windows.Threading;
using AntivirusOS.Core.Models;
using Antivirus.UI.ViewModels;

namespace Antivirus.UI;

public partial class ThreatToastWindow : Window
{
    private readonly ScanResult _result;
    private readonly MainViewModel _vm;
    private readonly DispatcherTimer _autoClose;

    public ThreatToastWindow(ScanResult result, MainViewModel vm)
    {
        InitializeComponent();
        _result = result;
        _vm = vm;

        FileNameText.Text = $"{Path.GetFileName(result.FilePath)}  ·  {result.Level}";

        // Position bottom-right above taskbar
        var area = SystemParameters.WorkArea;
        Left = area.Right - Width - 16;
        Top  = area.Bottom - Height - 16;

        _autoClose = new DispatcherTimer { Interval = TimeSpan.FromSeconds(8) };
        _autoClose.Tick += (_, _) => FadeAndClose();
        _autoClose.Start();
    }

    private void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        _autoClose.Stop();
        _ = _vm.QuarantineResultCommand.ExecuteAsync(_result);
        FadeAndClose();
    }

    private void Dismiss_Click(object sender, RoutedEventArgs e)
    {
        _autoClose.Stop();
        FadeAndClose();
    }

    private void FadeAndClose()
    {
        var fade = new System.Windows.Media.Animation.DoubleAnimation(0, TimeSpan.FromMilliseconds(200));
        fade.Completed += (_, _) => Close();
        BeginAnimation(OpacityProperty, fade);
    }
}
