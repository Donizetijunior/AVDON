using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Antivirus.UI.ViewModels;
using WpfColor      = System.Windows.Media.Color;
using WpfFontFamily = System.Windows.Media.FontFamily;
using WpfPen        = System.Windows.Media.Pen;
using WpfPoint      = System.Windows.Point;
using WpfRect       = System.Windows.Rect;

namespace Antivirus.UI;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;

    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        _vm = viewModel;
        DataContext = viewModel;
        Icon = CreateAvdonIcon();
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
}
