using System.Text;
using AntivirusOS.Core.Models;

namespace AntivirusOS.Core.Reports;

/// <summary>
/// Generates a self-contained HTML report (no external dependencies).
/// Includes summary cards, 30-day SVG bar chart, and full scan history table.
/// </summary>
public sealed class HtmlReportGenerator
{
    public async Task GenerateAsync(
        IEnumerable<ScanResult> results,
        string outputPath,
        string appVersion = "—")
    {
        var reporter = new ScanReporter();
        var list     = results.ToList();
        var summary  = reporter.GetSummary(list);
        var daily    = reporter.GetDailyStats(list, 30);

        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"pt-BR\"><head><meta charset=\"UTF-8\">");
        sb.AppendLine($"<title>AVDON — Relatório {DateTime.Now:dd/MM/yyyy}</title>");
        sb.AppendLine(Styles());
        sb.AppendLine("</head><body>");

        // Header
        sb.AppendLine($"""
            <div class="header">
              <h1>AVDON <span class="accent">Relatório de Segurança</span></h1>
              <p>Gerado em {DateTime.Now:dd/MM/yyyy HH:mm} &nbsp;|&nbsp; Versão {appVersion}</p>
            </div>
            """);

        // Summary cards
        sb.AppendLine("<div class=\"cards\">");
        Card(sb, "Total Escaneados", summary.Total.ToString(), "#F1F5F9");
        Card(sb, "Limpos",           summary.Clean.ToString(),     "#22C55E");
        Card(sb, "Suspeitos",        summary.Suspicious.ToString(), "#F59E0B");
        Card(sb, "Maliciosos",       summary.Malicious.ToString(),  "#EF4444");
        sb.AppendLine("</div>");

        if (!string.IsNullOrEmpty(summary.MostCommonThreat))
            sb.AppendLine($"<p class=\"most-common\">Ameaça mais frequente: <strong>{Esc(summary.MostCommonThreat)}</strong></p>");

        // SVG chart
        sb.AppendLine("<div class=\"section\">");
        sb.AppendLine("<h2>Ameaças — Últimos 30 dias</h2>");
        sb.AppendLine(BuildSvgChart(daily));
        sb.AppendLine("</div>");

        // History table (last 500)
        sb.AppendLine("<div class=\"section\">");
        sb.AppendLine("<h2>Histórico de Scans</h2>");
        sb.AppendLine("<table><thead><tr><th>Arquivo</th><th>Nível</th><th>Hash</th><th>Data</th></tr></thead><tbody>");
        foreach (var r in list.OrderByDescending(r => r.ScannedAt).Take(500))
        {
            var cls = r.Level switch
            {
                ThreatLevel.Malicious  => "row-mal",
                ThreatLevel.Suspicious => "row-sus",
                _                      => ""
            };
            sb.AppendLine($"<tr class=\"{cls}\"><td>{Esc(r.FilePath)}</td><td>{r.Level}</td><td class=\"mono\">{Esc(r.Hash[..Math.Min(16, r.Hash.Length)])}…</td><td>{r.ScannedAt:dd/MM/yy HH:mm}</td></tr>");
        }
        sb.AppendLine("</tbody></table>");
        sb.AppendLine("</div>");

        sb.AppendLine("<p class=\"footer\">AVDON — Antivírus para Windows &copy; 2025</p>");
        sb.AppendLine("</body></html>");

        await File.WriteAllTextAsync(outputPath, sb.ToString(), Encoding.UTF8);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static void Card(StringBuilder sb, string label, string value, string color)
    {
        sb.AppendLine($"<div class=\"card\"><div class=\"card-label\">{Esc(label)}</div><div class=\"card-value\" style=\"color:{color}\">{Esc(value)}</div></div>");
    }

    private static string BuildSvgChart(List<DailyThreatStat> daily)
    {
        const int W = 760, H = 160, padL = 30, padB = 24, padT = 8, padR = 8;
        int chartW = W - padL - padR;
        int chartH = H - padB - padT;
        int n      = daily.Count;
        int max    = Math.Max(1, daily.Max(d => d.Total));
        double barW = Math.Max(1.0, (double)(chartW - (n - 1) * 2) / n);

        var svg = new StringBuilder();
        svg.AppendLine($"<svg viewBox=\"0 0 {W} {H}\" xmlns=\"http://www.w3.org/2000/svg\" style=\"width:100%;height:auto;display:block\">");

        // Grid
        for (int i = 0; i <= 3; i++)
        {
            int y = padT + (int)(chartH * (1.0 - (double)i / 3));
            svg.AppendLine($"<line x1=\"{padL}\" x2=\"{W - padR}\" y1=\"{y}\" y2=\"{y}\" stroke=\"#1E293B\" stroke-width=\"1\"/>");
            svg.AppendLine($"<text x=\"{padL - 4}\" y=\"{y + 4}\" text-anchor=\"end\" fill=\"#64748B\" font-size=\"9\">{(int)Math.Round(max * i / 3.0)}</text>");
        }

        for (int i = 0; i < n; i++)
        {
            var s  = daily[i];
            double x = padL + i * (barW + 2);
            double bY = padT + chartH;

            double cleanH = chartH * s.Clean      / max;
            double suspH  = chartH * s.Suspicious / max;
            double malH   = chartH * s.Malicious  / max;

            if (s.Clean > 0)      svg.AppendLine($"<rect x=\"{x:F1}\" y=\"{(bY - cleanH):F1}\" width=\"{barW:F1}\" height=\"{cleanH:F1}\" fill=\"#22C55E\" rx=\"1\"/>");
            if (s.Suspicious > 0) svg.AppendLine($"<rect x=\"{x:F1}\" y=\"{(bY - cleanH - suspH):F1}\" width=\"{barW:F1}\" height=\"{suspH:F1}\" fill=\"#F59E0B\"/>");
            if (s.Malicious > 0)  svg.AppendLine($"<rect x=\"{x:F1}\" y=\"{(bY - cleanH - suspH - malH):F1}\" width=\"{barW:F1}\" height=\"{malH:F1}\" fill=\"#EF4444\" rx=\"1\"/>");

            if (i % 7 == 0)
                svg.AppendLine($"<text x=\"{(x + barW / 2):F1}\" y=\"{H - 6}\" text-anchor=\"middle\" fill=\"#64748B\" font-size=\"9\">{s.Date:dd/MM}</text>");
        }

        svg.AppendLine("</svg>");
        return svg.ToString();
    }

    private static string Esc(string s) =>
        s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");

    private static string Styles() => """
        <style>
        :root { color-scheme: dark; }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0F172A; color: #F1F5F9; font-family: 'Segoe UI', system-ui, sans-serif; padding: 32px; }
        .header { margin-bottom: 24px; }
        .header h1 { font-size: 28px; font-weight: 700; }
        .accent { color: #00C8FF; }
        .header p { color: #64748B; font-size: 13px; margin-top: 4px; }
        .cards { display: flex; gap: 12px; margin-bottom: 20px; }
        .card { flex: 1; background: #1E293B; border-radius: 8px; padding: 16px; }
        .card-label { font-size: 11px; font-weight: 700; color: #64748B; letter-spacing: 0.05em; }
        .card-value { font-size: 32px; font-weight: 700; margin-top: 4px; }
        .most-common { color: #94A3B8; font-size: 13px; margin-bottom: 20px; }
        .section { background: #1E293B; border-radius: 8px; padding: 16px; margin-bottom: 20px; }
        .section h2 { font-size: 13px; font-weight: 700; color: #64748B; margin-bottom: 12px; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        th { text-align: left; color: #64748B; font-size: 11px; font-weight: 600; border-bottom: 1px solid #334155; padding: 6px 8px; }
        td { padding: 5px 8px; border-bottom: 1px solid #1E293B; color: #CBD5E1; word-break: break-all; }
        .row-mal td { color: #FCA5A5; }
        .row-sus td { color: #FCD34D; }
        .mono { font-family: 'Cascadia Code', Consolas, monospace; }
        .footer { text-align: center; color: #334155; font-size: 11px; margin-top: 20px; }
        </style>
        """;
}
