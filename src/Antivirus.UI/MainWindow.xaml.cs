using System.Windows;
using Antivirus.UI.ViewModels;

namespace Antivirus.UI;

public partial class MainWindow : Window
{
    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
