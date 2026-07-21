using System.Text;
using System.Text.Json;

namespace Ergaxiom.WindowsUiaHost;

public static class HostSelfTests
{
    private const string CanonicalVector =
        "{\"array\":[3,1,{\"z\":\"son\",\"a\":\"baş\"}],\"bool\":true,\"null\":null,\"object\":{\"b\":2,\"a\":\"ç\"},\"text\":\"Ergaxiom\"}";
    private const string ExpectedCanonicalJson =
        "{\"array\":[3,1,{\"a\":\"baş\",\"z\":\"son\"}],\"bool\":true,\"null\":null,\"object\":{\"a\":\"ç\",\"b\":2},\"text\":\"Ergaxiom\"}";
    private const string ExpectedCanonicalDigest =
        "3c5b3896803debb32597ec4d330e4f439a724d7022648bffc6029e25943a5aee";

    public static void Run()
    {
        VerifyCanonicalJsonVector();
        VerifyProtocolRoundTrip();
        VerifyResponseEnvelope();
        Console.Error.WriteLine("Windows UI Automation host self-tests passed.");
    }

    private static void VerifyCanonicalJsonVector()
    {
        using var document = JsonDocument.Parse(CanonicalVector);
        var canonicalBytes = CanonicalJson.Serialize(document.RootElement);
        var canonicalText = Encoding.UTF8.GetString(canonicalBytes);
        AssertEqual(ExpectedCanonicalJson, canonicalText, "canonical JSON bytes");
        AssertEqual(
            ExpectedCanonicalDigest,
            CanonicalJson.Sha256(document.RootElement),
            "canonical JSON digest");
    }

    private static void VerifyProtocolRoundTrip()
    {
        const string commandJson =
            "{\"kind\":\"unsupported\",\"request\":{\"schema_version\":\"0.1.0\",\"request_id\":\"request.self-test\",\"bridge_id\":\"bridge.self-test\",\"plan_id\":\"plan.self-test\",\"plan_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"step_id\":\"step.self-test\",\"operator_id\":\"design.compose_text\",\"executor_id\":\"executor.self-test\",\"device_id\":null,\"control_method\":\"UI_AUTOMATION\",\"application\":{\"application_id\":\"editor\",\"version\":\"1.0.0\",\"executable_digest\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"instance_id\":\"pid:1\"},\"selector\":{\"selector\":\"UI_AUTOMATION\",\"automation_id\":\"copy\",\"control_type\":\"Edit\"},\"action\":{\"action\":\"SET_VALUE\",\"value\":\"APPROVED\"},\"required_grant\":{\"capability\":\"design-editor\",\"resource\":\"isolated-workspace\",\"access\":\"control\",\"constraints\":{\"network\":false}},\"expected_pre_state_digest\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"postconditions\":[],\"authorization_receipt_digest\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"},\"expected_pre_state_digest\":null}";
        var command = JsonSerializer.Deserialize<HostCommand>(commandJson, HostJson.Options)
            ?? throw new InvalidOperationException("Protocol command decoded to null.");
        AssertEqual("unsupported", command.Kind, "command kind");
        AssertEqual("request.self-test", command.Request.RequestId, "request ID");
        AssertEqual("UI_AUTOMATION", command.Request.ControlMethod, "control method");
    }

    private static void VerifyResponseEnvelope()
    {
        var response = HostResponse.Failed("unsupported", "UNSUPPORTED_COMMAND", "not supported");
        var json = JsonSerializer.Serialize(response, HostJson.Options);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        AssertEqual(false, root.GetProperty("ok").GetBoolean(), "response ok");
        AssertEqual("unsupported", root.GetProperty("kind").GetString(), "response kind");
        AssertEqual(
            "UNSUPPORTED_COMMAND",
            root.GetProperty("error").GetProperty("code").GetString(),
            "response error code");
    }

    private static void AssertEqual<T>(T expected, T actual, string label)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException(
                $"Self-test failed for {label}. Expected '{expected}', observed '{actual}'.");
        }
    }
}
