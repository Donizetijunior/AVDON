using System.Windows;
using AntivirusOS.Core.Models;
using AntivirusOS.Core.Quarantine;

namespace Antivirus.UI;

public partial class QuarantineDetailWindow : Window
{
    private readonly QuarantineEntry _entry;
    private readonly IQuarantineManager _manager;
    private readonly Action _onChanged;

    public QuarantineDetailWindow(QuarantineEntry entry, IQuarantineManager manager, Action onChanged)
    {
        InitializeComponent();
        _entry     = entry;
        _manager   = manager;
        _onChanged = onChanged;

        var inspector = new QuarantineInspector();
        var info      = inspector.Inspect(entry);

        TxtOriginalPath.Text = entry.OriginalPath;
        TxtHash.Text         = entry.Hash;
        TxtSize.Text         = info.FileSizeDisplay;
        TxtEntropy.Text      = info.EntropyDisplay;
        TxtHex.Text          = string.IsNullOrEmpty(info.HexPreview)
                                ? "(sem dados)"
                                : info.HexPreview;

        if (!string.IsNullOrEmpty(info.Note))
        {
            TxtNote.Text       = "⚠ " + info.Note;
            TxtNote.Visibility = Visibility.Visible;
        }
    }

    private async void BtnRestore_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            await _manager.RestoreAsync(_entry);
            _onChanged();
            Close();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Erro ao restaurar: {ex.Message}", "AVDON", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void BtnDelete_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "Apagar permanentemente este arquivo? Esta ação não pode ser desfeita.",
            "AVDON — Confirmar exclusão",
            MessageBoxButton.YesNo, MessageBoxImage.Warning);

        if (result != MessageBoxResult.Yes) return;

        try
        {
            await _manager.DeleteAsync(_entry);
            _onChanged();
            Close();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Erro ao apagar: {ex.Message}", "AVDON", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void BtnClose_Click(object sender, RoutedEventArgs e) => Close();
}
