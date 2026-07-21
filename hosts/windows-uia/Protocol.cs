using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ergaxiom.WindowsUiaHost;

public sealed record HostCommand(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("request")] WindowsBridgeRequestDto Request,
    [property: JsonPropertyName("expected_pre_state_digest")] string? ExpectedPreStateDigest);

public sealed record WindowsBridgeRequestDto(
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("request_id")] string RequestId,
    [property: JsonPropertyName("bridge_id")] string BridgeId,
    [property: JsonPropertyName("plan_id")] string PlanId,
    [property: JsonPropertyName("plan_digest")] string PlanDigest,
    [property: JsonPropertyName("step_id")] string StepId,
    [property: JsonPropertyName("operator_id")] string OperatorId,
    [property: JsonPropertyName("executor_id")] string ExecutorId,
    [property: JsonPropertyName("device_id")] string? DeviceId,
    [property: JsonPropertyName("control_method")] string ControlMethod,
    [property: JsonPropertyName("application")] WindowsApplicationIdentityDto Application,
    [property: JsonPropertyName("selector")] JsonElement Selector,
    [property: JsonPropertyName("action")] JsonElement Action,
    [property: JsonPropertyName("required_grant")] JsonElement RequiredGrant,
    [property: JsonPropertyName("expected_pre_state_digest")] string ExpectedPreStateDigest,
    [property: JsonPropertyName("postconditions")] IReadOnlyList<JsonElement> Postconditions,
    [property: JsonPropertyName("authorization_receipt_digest")] string AuthorizationReceiptDigest);

public sealed record WindowsApplicationIdentityDto(
    [property: JsonPropertyName("application_id")] string ApplicationId,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("executable_digest")] string ExecutableDigest,
    [property: JsonPropertyName("instance_id")] string InstanceId);

public sealed record ObservedWindowsStateDto(
    [property: JsonPropertyName("application")] WindowsApplicationIdentityDto Application,
    [property: JsonPropertyName("target_stable_id")] string TargetStableId,
    [property: JsonPropertyName("properties")] SortedDictionary<string, string> Properties,
    [property: JsonPropertyName("artifact_digests")] SortedDictionary<string, string> ArtifactDigests,
    [property: JsonPropertyName("observed_at_epoch_ms")] long ObservedAtEpochMs,
    [property: JsonPropertyName("state_digest")] string StateDigest);

public sealed record WindowsAdapterTransitionDto(
    [property: JsonPropertyName("consumed_pre_state_digest")] string ConsumedPreStateDigest,
    [property: JsonPropertyName("adapter_event_digest")] string AdapterEventDigest);

public sealed record HostResponse(
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("state")] ObservedWindowsStateDto? State,
    [property: JsonPropertyName("transition")] WindowsAdapterTransitionDto? Transition,
    [property: JsonPropertyName("error")] HostError? Error)
{
  public static HostResponse Observed(ObservedWindowsStateDto state) =>
      new(true, "observe", state, null, null);

  public static HostResponse Executed(WindowsAdapterTransitionDto transition) =>
      new(true, "execute", null, transition, null);

  public static HostResponse Failed(string kind, string code, string message) =>
      new(false, kind, null, null, new HostError(code, message));
}

public sealed record HostError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message);

public sealed class HostProtocolException : Exception
{
  public HostProtocolException(string code, string message) : base(message)
  {
    Code = code;
  }

  public string Code { get; }
}
