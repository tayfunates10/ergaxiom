namespace Ergaxiom.WindowsUiaHost;

public static class Program
{
  private const int UsageError = 64;
  private const int SoftwareError = 70;

  [STAThread]
  public static int Main(string[] args)
  {
    try
    {
      if (args.Length == 1 && StringComparer.Ordinal.Equals(args[0], "--self-test"))
      {
        HostSelfTests.Run();
        return 0;
      }

      var server = new HostServer(new UiaAdapter(HostJson.Options));
      if (args.Length == 0 || (args.Length == 1 && StringComparer.Ordinal.Equals(args[0], "--stdio")))
      {
        return server.RunStdio();
      }

      if (args.Length == 2 && StringComparer.Ordinal.Equals(args[0], "--pipe"))
      {
        return server.RunNamedPipe(args[1]);
      }

      WriteUsage();
      return UsageError;
    }
    catch (HostProtocolException exception)
    {
      Console.Error.WriteLine($"{exception.Code}: {exception.Message}");
      return SoftwareError;
    }
    catch (Exception exception)
    {
      Console.Error.WriteLine($"UNHANDLED_HOST_ERROR: {exception}");
      return SoftwareError;
    }
  }

  private static void WriteUsage()
  {
    Console.Error.WriteLine(
        "Usage: Ergaxiom.WindowsUiaHost [--stdio | --pipe <name> | --self-test]");
  }
}
