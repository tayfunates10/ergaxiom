using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace Ergaxiom.WindowsUiaHost;

public sealed class HostServer
{
  private readonly UiaAdapter _adapter;

  public HostServer(UiaAdapter adapter)
  {
    _adapter = adapter;
  }

  public int RunStdio()
  {
    using var input = new StreamReader(
        Console.OpenStandardInput(),
        new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
        detectEncodingFromByteOrderMarks: false,
        bufferSize: 4096,
        leaveOpen: false);
    using var output = new StreamWriter(
        Console.OpenStandardOutput(),
        new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
        bufferSize: 4096,
        leaveOpen: false)
    {
      AutoFlush = true,
    };
    ProcessLines(input, output);
    return 0;
  }

  public int RunNamedPipe(string pipeName)
  {
    ValidatePipeName(pipeName);
    using var pipe = new NamedPipeServerStream(
        pipeName,
        PipeDirection.InOut,
        maxNumberOfServerInstances: 1,
        PipeTransmissionMode.Byte,
        PipeOptions.CurrentUserOnly);
    pipe.WaitForConnection();
    using var input = new StreamReader(
        pipe,
        new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
        detectEncodingFromByteOrderMarks: false,
        bufferSize: 4096,
        leaveOpen: true);
    using var output = new StreamWriter(
        pipe,
        new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
        bufferSize: 4096,
        leaveOpen: true)
    {
      AutoFlush = true,
    };
    ProcessLines(input, output);
    return 0;
  }

  private void ProcessLines(TextReader input, TextWriter output)
  {
    string? line;
    while ((line = input.ReadLine()) is not null)
    {
      if (string.IsNullOrWhiteSpace(line))
      {
        continue;
      }

      var response = ProcessLine(line);
      output.WriteLine(JsonSerializer.Serialize(response, HostJson.Options));
    }
  }

  private HostResponse ProcessLine(string line)
  {
    string kind = "unknown";
    try
    {
      var command = JsonSerializer.Deserialize<HostCommand>(line, HostJson.Options)
          ?? throw new HostProtocolException("INVALID_COMMAND", "Command JSON decoded to null.");
      kind = command.Kind;
      return command.Kind switch
      {
        "observe" => HostResponse.Observed(_adapter.Observe(command.Request)),
        "execute" => HostResponse.Executed(
            _adapter.Execute(
                command.Request,
                command.ExpectedPreStateDigest
                    ?? throw new HostProtocolException(
                        "EXPECTED_PRE_STATE_REQUIRED",
                        "Execute command is missing expected_pre_state_digest."))),
        _ => HostResponse.Failed(
            command.Kind,
            "UNSUPPORTED_COMMAND",
            $"Unsupported command kind: {command.Kind}"),
      };
    }
    catch (HostProtocolException exception)
    {
      return HostResponse.Failed(kind, exception.Code, exception.Message);
    }
    catch (JsonException exception)
    {
      return HostResponse.Failed(kind, "INVALID_JSON", exception.Message);
    }
    catch (UnauthorizedAccessException exception)
    {
      return HostResponse.Failed(kind, "ACCESS_DENIED", exception.Message);
    }
    catch (InvalidOperationException exception)
    {
      return HostResponse.Failed(kind, "INVALID_OPERATION", exception.Message);
    }
    catch (System.ComponentModel.Win32Exception exception)
    {
      return HostResponse.Failed(kind, "WINDOWS_API_ERROR", exception.Message);
    }
  }

  private static void ValidatePipeName(string pipeName)
  {
    if (string.IsNullOrWhiteSpace(pipeName)
        || pipeName.Length > 128
        || pipeName.IndexOfAny(['\\', '/', ':']) >= 0)
    {
      throw new HostProtocolException(
          "INVALID_PIPE_NAME",
          "Pipe name must be 1-128 characters and cannot contain path separators or a colon.");
    }
  }
}
