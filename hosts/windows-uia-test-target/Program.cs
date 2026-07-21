using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;

namespace Ergaxiom.WindowsUiaTestTarget;

public static class Program
{
  [STAThread]
  public static int Main(string[] args)
  {
    var readyFile = ParseReadyFile(args);
    var application = new Application
    {
      ShutdownMode = ShutdownMode.OnMainWindowClose,
    };
    var window = BuildWindow(readyFile);
    application.MainWindow = window;
    application.Run(window);
    return 0;
  }

  private static Window BuildWindow(string? readyFile)
  {
    var copyField = new TextBox
    {
      Text = "BEFORE",
      Width = 360,
      Height = 40,
      FontSize = 20,
      HorizontalContentAlignment = HorizontalAlignment.Left,
      VerticalContentAlignment = VerticalAlignment.Center,
    };
    AutomationProperties.SetAutomationId(copyField, "copy-field");
    AutomationProperties.SetName(copyField, "Approved copy");

    var status = new TextBlock
    {
      Text = "Controlled Ergaxiom UI Automation target",
      Margin = new Thickness(0, 0, 0, 12),
      FontSize = 16,
    };
    AutomationProperties.SetAutomationId(status, "status-label");

    var panel = new StackPanel
    {
      Margin = new Thickness(24),
    };
    panel.Children.Add(status);
    panel.Children.Add(copyField);

    var window = new Window
    {
      Title = "Ergaxiom Windows UIA Test Target",
      Width = 440,
      Height = 180,
      WindowStartupLocation = WindowStartupLocation.CenterScreen,
      ResizeMode = ResizeMode.NoResize,
      Content = panel,
      ShowInTaskbar = true,
    };
    window.ContentRendered += (_, _) => SignalReady(readyFile);
    return window;
  }

  private static string? ParseReadyFile(string[] args)
  {
    if (args.Length == 0)
    {
      return null;
    }

    if (args.Length == 2
        && StringComparer.Ordinal.Equals(args[0], "--ready-file")
        && !string.IsNullOrWhiteSpace(args[1]))
    {
      return Path.GetFullPath(args[1]);
    }

    throw new ArgumentException(
        "Usage: Ergaxiom.WindowsUiaTestTarget [--ready-file <absolute-or-relative-path>]");
  }

  private static void SignalReady(string? readyFile)
  {
    if (readyFile is null)
    {
      return;
    }

    var directory = Path.GetDirectoryName(readyFile);
    if (!string.IsNullOrEmpty(directory))
    {
      Directory.CreateDirectory(directory);
    }

    File.WriteAllText(
        readyFile,
        $"ready:{Environment.ProcessId}",
        new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
  }
}
