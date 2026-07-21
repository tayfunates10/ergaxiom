using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows.Automation;

namespace Ergaxiom.WindowsUiaHost;

public sealed class UiaAdapter
{
    private const int MaximumCachedObservations = 128;

    private readonly JsonSerializerOptions _jsonOptions;
    private readonly string _hostExecutableDigest;
    private readonly object _observationLock = new();
    private readonly Dictionary<string, ObservedWindowsStateDto> _observations =
        new(StringComparer.Ordinal);
    private readonly Queue<string> _observationOrder = new();

    public UiaAdapter(JsonSerializerOptions jsonOptions)
    {
        _jsonOptions = jsonOptions;
        var hostPath = Environment.ProcessPath
            ?? throw new HostProtocolException(
                "HOST_IDENTITY_UNAVAILABLE",
                "Host executable path is unavailable.");
        _hostExecutableDigest = HashFile(hostPath);
    }

    public ObservedWindowsStateDto Observe(WindowsBridgeRequestDto request)
    {
        ValidateRequestEnvelope(request);
        var target = ResolveTarget(request);
        var state = ObserveTarget(target);
        CacheObservation(state);
        return state;
    }

    public WindowsAdapterTransitionDto Execute(
        WindowsBridgeRequestDto request,
        string expectedPreStateDigest)
    {
        ValidateRequestEnvelope(request);
        if (string.IsNullOrWhiteSpace(expectedPreStateDigest))
        {
            throw new HostProtocolException(
                "EXPECTED_PRE_STATE_REQUIRED",
                "Execute requires a non-empty expected pre-state digest.");
        }

        var expectedState = ConsumeObservation(expectedPreStateDigest);
        var target = ResolveTarget(request);
        var currentState = ObserveTarget(target);
        if (!SemanticStateEquals(expectedState, currentState))
        {
            throw new HostProtocolException(
                "TOCTOU_MISMATCH",
                "Observed UI Automation state changed before the action boundary.");
        }

        ApplyAction(request, target.Element);
        var eventValue = JsonSerializer.SerializeToElement(
            new Dictionary<string, object?>
            {
                ["action"] = request.Action,
                ["consumed_pre_state_digest"] = expectedState.StateDigest,
                ["host_executable_digest"] = _hostExecutableDigest,
                ["request_id"] = request.RequestId,
                ["target_stable_id"] = target.StableId,
            },
            _jsonOptions);

        return new WindowsAdapterTransitionDto(
            expectedState.StateDigest,
            CanonicalJson.Sha256(eventValue));
    }

    private void CacheObservation(ObservedWindowsStateDto state)
    {
        lock (_observationLock)
        {
            _observations[state.StateDigest] = state;
            _observationOrder.Enqueue(state.StateDigest);
            while (_observationOrder.Count > MaximumCachedObservations)
            {
                var expiredDigest = _observationOrder.Dequeue();
                _observations.Remove(expiredDigest);
            }
        }
    }

    private ObservedWindowsStateDto ConsumeObservation(string expectedPreStateDigest)
    {
        lock (_observationLock)
        {
            if (!_observations.Remove(expectedPreStateDigest, out var state))
            {
                throw new HostProtocolException(
                    "PRE_STATE_NOT_OBSERVED_BY_HOST",
                    "Expected pre-state digest is unknown, expired or already consumed.");
            }

            return state;
        }
    }

    private static bool SemanticStateEquals(
        ObservedWindowsStateDto expected,
        ObservedWindowsStateDto current)
    {
        return expected.Application == current.Application
            && StringComparer.Ordinal.Equals(expected.TargetStableId, current.TargetStableId)
            && expected.Properties.SequenceEqual(current.Properties)
            && expected.ArtifactDigests.SequenceEqual(current.ArtifactDigests);
    }

    private static void ValidateRequestEnvelope(WindowsBridgeRequestDto request)
    {
        if (!StringComparer.Ordinal.Equals(request.SchemaVersion, "0.1.0"))
        {
            throw new HostProtocolException(
                "UNSUPPORTED_SCHEMA",
                $"Unsupported request schema: {request.SchemaVersion}");
        }

        if (!StringComparer.Ordinal.Equals(request.ControlMethod, "UI_AUTOMATION"))
        {
            throw new HostProtocolException(
                "UNSUPPORTED_CONTROL_METHOD",
                "This host supports only UI_AUTOMATION requests.");
        }

        if (!request.Selector.TryGetProperty("selector", out var selectorKind)
            || !StringComparer.Ordinal.Equals(selectorKind.GetString(), "UI_AUTOMATION"))
        {
            throw new HostProtocolException(
                "SELECTOR_METHOD_MISMATCH",
                "UI_AUTOMATION control requires a UI_AUTOMATION selector.");
        }
    }

    private static TargetContext ResolveTarget(WindowsBridgeRequestDto request)
    {
        var processId = ParseProcessId(request.Application.InstanceId);
        Process process;
        try
        {
            process = Process.GetProcessById(processId);
        }
        catch (ArgumentException exception)
        {
            throw new HostProtocolException(
                "PROCESS_NOT_FOUND",
                $"Target process {processId} does not exist: {exception.Message}");
        }

        using (process)
        {
            var executablePath = process.MainModule?.FileName
                ?? throw new HostProtocolException(
                    "EXECUTABLE_PATH_UNAVAILABLE",
                    "Target process executable path is unavailable.");
            var actualIdentity = new WindowsApplicationIdentityDto(
                process.ProcessName,
                ReadFileVersion(executablePath),
                HashFile(executablePath),
                request.Application.InstanceId);
            if (actualIdentity != request.Application)
            {
                throw new HostProtocolException(
                    "APPLICATION_IDENTITY_MISMATCH",
                    "Target process name, version, executable digest or instance ID does not match the request.");
            }

            if (process.MainWindowHandle == IntPtr.Zero)
            {
                throw new HostProtocolException(
                    "MAIN_WINDOW_UNAVAILABLE",
                    "Target process does not expose a main window handle.");
            }

            var automationId = RequiredSelectorString(request.Selector, "automation_id");
            var controlTypeName = RequiredSelectorString(request.Selector, "control_type");
            var controlType = ResolveControlType(controlTypeName);
            var root = AutomationElement.FromHandle(process.MainWindowHandle)
                ?? throw new HostProtocolException(
                    "AUTOMATION_ROOT_UNAVAILABLE",
                    "UI Automation could not resolve the target window root.");
            var condition = new AndCondition(
                new PropertyCondition(AutomationElement.AutomationIdProperty, automationId),
                new PropertyCondition(AutomationElement.ControlTypeProperty, controlType));
            var element = root.FindFirst(TreeScope.Descendants, condition)
                ?? throw new HostProtocolException(
                    "TARGET_NOT_FOUND",
                    $"UI Automation target {controlTypeName}/{automationId} was not found.");

            return new TargetContext(
                actualIdentity,
                element,
                $"{controlTypeName}/{automationId}");
        }
    }

    private static ObservedWindowsStateDto ObserveTarget(TargetContext target)
    {
        var current = target.Element.Current;
        var properties = new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            ["automation_id"] = current.AutomationId ?? string.Empty,
            ["control_type"] = NormalizeControlType(current.ControlType),
            ["is_enabled"] = current.IsEnabled ? "true" : "false",
            ["is_offscreen"] = current.IsOffscreen ? "true" : "false",
            ["name"] = current.Name ?? string.Empty,
        };

        if (target.Element.TryGetCurrentPattern(ValuePattern.Pattern, out var valuePatternObject)
            && valuePatternObject is ValuePattern valuePattern)
        {
            properties["is_read_only"] = valuePattern.Current.IsReadOnly ? "true" : "false";
            properties["value"] = valuePattern.Current.Value ?? string.Empty;
        }

        if (target.Element.TryGetCurrentPattern(TogglePattern.Pattern, out var togglePatternObject)
            && togglePatternObject is TogglePattern togglePattern)
        {
            properties["toggle_state"] = togglePattern.Current.ToggleState.ToString();
        }

        if (target.Element.TryGetCurrentPattern(SelectionItemPattern.Pattern, out var selectionObject)
            && selectionObject is SelectionItemPattern selectionItemPattern)
        {
            properties["is_selected"] = selectionItemPattern.Current.IsSelected ? "true" : "false";
        }

        var withoutDigest = new
        {
            application = target.Application,
            target_stable_id = target.StableId,
            properties,
            artifact_digests = new SortedDictionary<string, string>(StringComparer.Ordinal),
            observed_at_epoch_ms = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        };
        var observed = JsonSerializer.SerializeToElement(withoutDigest, HostJson.Options);
        var digest = CanonicalJson.Sha256(observed);
        return new ObservedWindowsStateDto(
            target.Application,
            target.StableId,
            properties,
            new SortedDictionary<string, string>(StringComparer.Ordinal),
            withoutDigest.observed_at_epoch_ms,
            digest);
    }

    private static void ApplyAction(WindowsBridgeRequestDto request, AutomationElement element)
    {
        var action = RequiredActionKind(request.Action);
        switch (action)
        {
            case "SET_VALUE":
                var value = RequiredActionString(request.Action, "value");
                if (!element.TryGetCurrentPattern(ValuePattern.Pattern, out var valuePatternObject)
                    || valuePatternObject is not ValuePattern valuePattern)
                {
                    throw new HostProtocolException(
                        "VALUE_PATTERN_UNAVAILABLE",
                        "Target does not support ValuePattern.");
                }

                if (valuePattern.Current.IsReadOnly)
                {
                    throw new HostProtocolException(
                        "TARGET_READ_ONLY",
                        "Target ValuePattern is read-only.");
                }

                valuePattern.SetValue(value);
                break;
            case "INVOKE":
                if (!element.TryGetCurrentPattern(InvokePattern.Pattern, out var invokePatternObject)
                    || invokePatternObject is not InvokePattern invokePattern)
                {
                    throw new HostProtocolException(
                        "INVOKE_PATTERN_UNAVAILABLE",
                        "Target does not support InvokePattern.");
                }

                invokePattern.Invoke();
                break;
            case "SELECT":
                var optionId = RequiredActionString(request.Action, "option_id");
                if (!StringComparer.Ordinal.Equals(optionId, element.Current.AutomationId))
                {
                    throw new HostProtocolException(
                        "OPTION_ID_MISMATCH",
                        "SELECT option_id must match the selected UI Automation element ID.");
                }

                if (!element.TryGetCurrentPattern(
                        SelectionItemPattern.Pattern,
                        out var selectionPatternObject)
                    || selectionPatternObject is not SelectionItemPattern selectionPattern)
                {
                    throw new HostProtocolException(
                        "SELECTION_PATTERN_UNAVAILABLE",
                        "Target does not support SelectionItemPattern.");
                }

                selectionPattern.Select();
                break;
            default:
                throw new HostProtocolException(
                    "UNSUPPORTED_ACTION",
                    $"UI Automation host does not support action {action}.");
        }
    }

    private static int ParseProcessId(string instanceId)
    {
        const string prefix = "pid:";
        if (!instanceId.StartsWith(prefix, StringComparison.Ordinal)
            || !int.TryParse(
                instanceId.AsSpan(prefix.Length),
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var processId)
            || processId <= 0)
        {
            throw new HostProtocolException(
                "INVALID_INSTANCE_ID",
                "application.instance_id must use the form pid:<positive integer>.");
        }

        return processId;
    }

    private static string RequiredSelectorString(JsonElement selector, string propertyName)
    {
        if (!selector.TryGetProperty(propertyName, out var property)
            || property.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(property.GetString()))
        {
            throw new HostProtocolException(
                "INVALID_SELECTOR",
                $"Selector property {propertyName} is required.");
        }

        return property.GetString()!;
    }

    private static string RequiredActionKind(JsonElement action) =>
        RequiredActionString(action, "action");

    private static string RequiredActionString(JsonElement action, string propertyName)
    {
        if (!action.TryGetProperty(propertyName, out var property)
            || property.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(property.GetString()))
        {
            throw new HostProtocolException(
                "INVALID_ACTION",
                $"Action property {propertyName} is required.");
        }

        return property.GetString()!;
    }

    private static ControlType ResolveControlType(string name) => name switch
    {
        "Button" => ControlType.Button,
        "CheckBox" => ControlType.CheckBox,
        "ComboBox" => ControlType.ComboBox,
        "Edit" => ControlType.Edit,
        "Hyperlink" => ControlType.Hyperlink,
        "List" => ControlType.List,
        "ListItem" => ControlType.ListItem,
        "MenuItem" => ControlType.MenuItem,
        "RadioButton" => ControlType.RadioButton,
        "TabItem" => ControlType.TabItem,
        "Text" => ControlType.Text,
        "TreeItem" => ControlType.TreeItem,
        "Window" => ControlType.Window,
        _ => throw new HostProtocolException(
            "UNSUPPORTED_CONTROL_TYPE",
            $"Unsupported UI Automation control type: {name}"),
    };

    private static string NormalizeControlType(ControlType controlType)
    {
        const string prefix = "ControlType.";
        var name = controlType.ProgrammaticName;
        return name.StartsWith(prefix, StringComparison.Ordinal) ? name[prefix.Length..] : name;
    }

    private static string ReadFileVersion(string executablePath)
    {
        var versionInfo = FileVersionInfo.GetVersionInfo(executablePath);
        return versionInfo.FileVersion
            ?? versionInfo.ProductVersion
            ?? throw new HostProtocolException(
                "APPLICATION_VERSION_UNAVAILABLE",
                "Target executable version metadata is unavailable.");
    }

    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private sealed record TargetContext(
        WindowsApplicationIdentityDto Application,
        AutomationElement Element,
        string StableId);
}
