using System.Collections.Generic;
using AntivirusOS.Core.Reports;
using WpfCanvas    = System.Windows.Controls.Canvas;
using WpfTextBlock = System.Windows.Controls.TextBlock;
using WpfRect      = System.Windows.Shapes.Rectangle;
using WpfLine      = System.Windows.Shapes.Line;
using WpfColor     = System.Windows.Media.Color;
using WpfBrush     = System.Windows.Media.Brush;
using WpfSolidBrush = System.Windows.Media.SolidColorBrush;
using WpfUserControl = System.Windows.Controls.UserControl;
using System.Windows;

namespace Antivirus.UI.Controls;

public partial class ThreatBarChart : WpfUserControl
{
    public static readonly DependencyProperty StatsProperty =
        DependencyProperty.Register(nameof(Stats), typeof(IList<DailyThreatStat>),
            typeof(ThreatBarChart), new PropertyMetadata(null, OnStatsChanged));

    public IList<DailyThreatStat>? Stats
    {
        get => (IList<DailyThreatStat>?)GetValue(StatsProperty);
        set => SetValue(StatsProperty, value);
    }

    private static void OnStatsChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((ThreatBarChart)d).Render();

    public ThreatBarChart() => InitializeComponent();

    private void ChartCanvas_SizeChanged(object sender, SizeChangedEventArgs e) => Render();

    private void Render()
    {
        ChartCanvas.Children.Clear();
        var stats = Stats;
        if (stats == null || stats.Count == 0) return;

        double w = ChartCanvas.ActualWidth;
        double h = ChartCanvas.ActualHeight;
        if (w <= 0 || h <= 0) return;

        int maxTotal = 1;
        foreach (var s in stats) if (s.Total > maxTotal) maxTotal = s.Total;

        const double padLeft  = 32;
        const double padRight = 8;
        const double padTop   = 12;
        const double padBot   = 28;
        double chartW = w - padLeft - padRight;
        double chartH = h - padTop - padBot;

        var gridColor  = new WpfSolidBrush(WpfColor.FromRgb(0x1E, 0x29, 0x3B));
        var labelColor = new WpfSolidBrush(WpfColor.FromRgb(0x64, 0x74, 0x8B));

        for (int i = 0; i <= 3; i++)
        {
            double y = padTop + chartH * (1.0 - (double)i / 3);
            var line = new WpfLine { X1 = padLeft, X2 = w - padRight, Y1 = y, Y2 = y, Stroke = gridColor, StrokeThickness = 1 };
            ChartCanvas.Children.Add(line);

            int labelVal = (int)Math.Round(maxTotal * i / 3.0);
            var lbl = new WpfTextBlock { Text = labelVal.ToString(), Foreground = labelColor, FontSize = 9 };
            WpfCanvas.SetLeft(lbl, 2);
            WpfCanvas.SetTop(lbl, y - 7);
            ChartCanvas.Children.Add(lbl);
        }

        int    n    = stats.Count;
        double gap  = 2;
        double barW = Math.Max(1, (chartW - gap * (n - 1)) / n);

        var cleanBrush = new WpfSolidBrush(WpfColor.FromRgb(0x22, 0xC5, 0x5E));
        var suspBrush  = new WpfSolidBrush(WpfColor.FromRgb(0xF5, 0x9E, 0x0B));
        var malBrush   = new WpfSolidBrush(WpfColor.FromRgb(0xEF, 0x44, 0x44));

        for (int i = 0; i < n; i++)
        {
            var s = stats[i];
            double x       = padLeft + i * (barW + gap);
            double bottomY = padTop + chartH;
            double cleanH  = chartH * s.Clean      / maxTotal;
            double suspH   = chartH * s.Suspicious / maxTotal;
            double malH    = chartH * s.Malicious  / maxTotal;

            void AddBar(double bh, double yTop, WpfBrush brush, bool round)
            {
                if (bh <= 0) return;
                var r = new WpfRect { Width = barW, Height = bh, Fill = brush };
                if (round) { r.RadiusX = 2; r.RadiusY = 2; }
                WpfCanvas.SetLeft(r, x);
                WpfCanvas.SetTop(r, yTop);
                ChartCanvas.Children.Add(r);
            }

            AddBar(cleanH, bottomY - cleanH,                    cleanBrush, true);
            AddBar(suspH,  bottomY - cleanH - suspH,            suspBrush,  false);
            AddBar(malH,   bottomY - cleanH - suspH - malH,     malBrush,   true);

            if (i % 7 == 0)
            {
                var lbl = new WpfTextBlock
                {
                    Text = s.Date.ToString("dd/MM"),
                    Foreground = labelColor,
                    FontSize = 9,
                };
                WpfCanvas.SetLeft(lbl, x - 2);
                WpfCanvas.SetTop(lbl, padTop + chartH + 4);
                ChartCanvas.Children.Add(lbl);
            }
        }
    }
}
