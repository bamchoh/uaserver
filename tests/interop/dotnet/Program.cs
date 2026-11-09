// Interop test: drives the Go server with the official OPC Foundation .NET client stack.
// Usage: dotnet run -- opc.tcp://localhost:48400
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;

string url = args.Length > 0 ? args[0] : "opc.tcp://localhost:48400";
ITelemetryContext telemetry = DefaultTelemetry.Create(l => l.AddConsole().SetMinimumLevel(LogLevel.Critical));
string pki = Path.Combine(AppContext.BaseDirectory, "pki");

var config = new ApplicationConfiguration(telemetry)
{
    ApplicationName = "InteropClient",
    ApplicationUri = "urn:localhost:opcuasrv:InteropClient",
    ApplicationType = ApplicationType.Client,
    SecurityConfiguration = new SecurityConfiguration
    {
        ApplicationCertificate = new CertificateIdentifier
        {
            StoreType = CertificateStoreType.Directory,
            StorePath = Path.Combine(pki, "own"),
            SubjectName = "CN=InteropClient, O=opcuasrv"
        },
        TrustedIssuerCertificates = new CertificateTrustList { StoreType = CertificateStoreType.Directory, StorePath = Path.Combine(pki, "issuer") },
        TrustedPeerCertificates = new CertificateTrustList { StoreType = CertificateStoreType.Directory, StorePath = Path.Combine(pki, "trusted") },
        RejectedCertificateStore = new CertificateTrustList { StoreType = CertificateStoreType.Directory, StorePath = Path.Combine(pki, "rejected") },
        AutoAcceptUntrustedCertificates = true
    },
    TransportQuotas = new TransportQuotas { MaxMessageSize = 8 * 1024 * 1024 },
    ClientConfiguration = new ClientConfiguration(),
    ServerConfiguration = new ServerConfiguration()
};
await config.ValidateAsync(ApplicationType.Client, CancellationToken.None);
var app = new ApplicationInstance(config, telemetry);
await app.CheckApplicationInstanceCertificatesAsync(true, ct: CancellationToken.None);
config.CertificateManager ??= CertificateManagerFactory.Create(config.SecurityConfiguration, telemetry);
config.CertificateManager.AcceptError = static (_, _) => true;

const string None = SecurityPolicies.None;
const string B256 = SecurityPolicies.Basic256Sha256;
const string A128 = SecurityPolicies.Aes128_Sha256_RsaOaep;
const string A256 = SecurityPolicies.Aes256_Sha256_RsaPss;
var anon = new UserIdentity(new AnonymousIdentityToken());
IUserIdentity User(string u, string p) => new UserIdentity(u, System.Text.Encoding.UTF8.GetBytes(p));

var cases = new (string Policy, MessageSecurityMode Mode, IUserIdentity User, bool ExpectOk)[]
{
    (None, MessageSecurityMode.None, anon, true),
    (None, MessageSecurityMode.None, User("user1", "password1"), true),
    (B256, MessageSecurityMode.Sign, anon, true),
    (B256, MessageSecurityMode.SignAndEncrypt, User("user1", "password1"), true),
    (A128, MessageSecurityMode.Sign, anon, true),
    (A128, MessageSecurityMode.SignAndEncrypt, anon, true),
    (A256, MessageSecurityMode.Sign, User("user1", "password1"), true),
    (A256, MessageSecurityMode.SignAndEncrypt, anon, true),
    (B256, MessageSecurityMode.SignAndEncrypt, User("user1", "wrong"), false),
};

int failures = 0;
foreach (var c in cases)
{
    string name = $"{c.Policy.Split('#')[1]}/{c.Mode}/{(c.User.TokenType == UserTokenType.Anonymous ? "anon" : c.User.DisplayName)}";
    try
    {
        using var cts = new CancellationTokenSource(c.ExpectOk ? TimeSpan.FromMinutes(2) : TimeSpan.FromSeconds(8));
        await RunCase(c.Policy, c.Mode, c.User, cts.Token);
        if (c.ExpectOk) Console.WriteLine($"PASS {name}");
        else { Console.WriteLine($"FAIL {name}: expected connection to be rejected"); failures++; }
    }
    catch (Exception ex)
    {
        if (!c.ExpectOk) Console.WriteLine($"PASS {name} (rejected: {(ex as ServiceResultException)?.StatusCode.ToString() ?? ex.Message})");
        else { Console.WriteLine($"FAIL {name}: {ex}"); failures++; }
    }
}
// Security token renewal: request a short token lifetime and keep the channel busy.
try
{
    config.TransportQuotas.SecurityTokenLifetime = 10000;
    using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1));
    await using ManagedSession s = await new ManagedSessionBuilder(config, telemetry)
        .UseEndpoint(url, MessageSecurityMode.SignAndEncrypt, B256)
        .WithSessionName("interop renewal").WithUserIdentity(anon).ConnectAsync(cts.Token);
    for (int i = 0; i < 25; i++)
    {
        var r = await s.ReadAsync(null, 0, TimestampsToReturn.Both, new[] {
            new ReadValueId { NodeId = VariableIds.Server_ServerStatus_CurrentTime, AttributeId = Attributes.Value } }, cts.Token);
        Check(StatusCode.IsGood(r.Results[0].StatusCode), "read during renewal");
        await Task.Delay(1000, cts.Token);
    }
    await s.CloseAsync(cts.Token);
    Console.WriteLine("PASS token renewal (25s with 10s token lifetime)");
}
catch (Exception ex)
{
    Console.WriteLine($"FAIL token renewal: {ex}");
    failures++;
}

Console.WriteLine(failures == 0 ? "ALL PASSED" : $"{failures} FAILED");
return failures == 0 ? 0 : 1;

async Task RunCase(string policy, MessageSecurityMode mode, IUserIdentity user, CancellationToken ct)
{

    await using ManagedSession session = await new ManagedSessionBuilder(config, telemetry)
        .UseEndpoint(url, mode, policy)
        .WithSessionName("interop " + policy.Split('#')[1] + " " + mode)
        .WithSessionTimeout(TimeSpan.FromSeconds(30))
        .WithUserIdentity(user)
        .ConnectAsync(ct);

    ushort ns = (ushort)session.NamespaceUris.GetIndex("urn:opcuasrv:demo");
    Check(ns > 1, "demo namespace registered");

    // Browse Objects.
    var br = await session.BrowseAsync(null, null, 0, new[] { new BrowseDescription {
        NodeId = ObjectIds.ObjectsFolder, BrowseDirection = BrowseDirection.Forward,
        ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences, IncludeSubtypes = true,
        NodeClassMask = 0, ResultMask = (uint)BrowseResultMask.All } }, ct);
    var names = br.Results[0].References.ToArray().Select(r => r.BrowseName.Name).ToList();
    Check(names.Contains("Server") && names.Contains("Demo"), "browse Objects: " + string.Join(",", names));

    // Translate browse path.
    var tr = await session.TranslateBrowsePathsToNodeIdsAsync(null, new[] { new BrowsePath {
        StartingNode = ObjectIds.ObjectsFolder,
        RelativePath = RelativePath.Parse($"/{ns}:Demo/{ns}:Static/{ns}:Int32", session.TypeTree) } }, ct);
    Check(StatusCode.IsGood(tr.Results[0].StatusCode), "translate path");
    var int32Id = ExpandedNodeId.ToNodeId(tr.Results[0].Targets[0].TargetId, session.NamespaceUris);

    // Read.
    var rr = await session.ReadAsync(null, 0, TimestampsToReturn.Both, new[] {
        new ReadValueId { NodeId = VariableIds.Server_ServerStatus, AttributeId = Attributes.Value },
        new ReadValueId { NodeId = VariableIds.Server_NamespaceArray, AttributeId = Attributes.Value },
        new ReadValueId { NodeId = new NodeId("Demo.Static.String", ns), AttributeId = Attributes.Value },
        new ReadValueId { NodeId = new NodeId("Demo.Static.Int32Array", ns), AttributeId = Attributes.Value, IndexRange = "1:2" },
        new ReadValueId { NodeId = new NodeId("Demo.Static.LocalizedText", ns), AttributeId = Attributes.Value },
        new ReadValueId { NodeId = DataTypeIds.BuildInfo, AttributeId = Attributes.DataTypeDefinition },
        new ReadValueId { NodeId = new NodeId("NoSuchNode", ns), AttributeId = Attributes.Value },
    }, ct);
    var res = rr.Results.ToArray();
    Check(res[0].WrappedValue.TryGetStructure(out ServerStatusDataType? status) || res[0].Value is ExtensionObject, "read ServerStatus: " + res[0].WrappedValue);
    Check(res[2].WrappedValue.ToString() == "Hello OPC UA", "read string: " + res[2].WrappedValue);
    Check(res[3].WrappedValue.ToString().Contains('2') && res[3].WrappedValue.ToString().Contains('3'), "read index range: " + res[3].WrappedValue);
    Check(res[4].WrappedValue.ToString().Contains("こんにちは"), "read localized text: " + res[4].WrappedValue);
    Check(StatusCode.IsGood(res[5].StatusCode), "read DataTypeDefinition: " + res[5].StatusCode);
    Check(res[6].StatusCode == StatusCodes.BadNodeIdUnknown, "unknown node: " + res[6].StatusCode);

    // Write and read back.
    var wr = await session.WriteAsync(null, new[] {
        new WriteValue { NodeId = int32Id, AttributeId = Attributes.Value, Value = new DataValue(new Variant(1234)) },
        new WriteValue { NodeId = int32Id, AttributeId = Attributes.Value, Value = new DataValue(new Variant("wrong type")) },
        new WriteValue { NodeId = VariableIds.Server_ServerStatus_State, AttributeId = Attributes.Value, Value = new DataValue(new Variant(1)) },
    }, ct);
    var wres = wr.Results.ToArray();
    Check(StatusCode.IsGood(wres[0]), "write int32: " + wres[0]);
    Check(wres[1] == StatusCodes.BadTypeMismatch, "write wrong type: " + wres[1]);
    Check(wres[2] == StatusCodes.BadNotWritable, "write read-only: " + wres[2]);
    var back = await session.ReadAsync(null, 0, TimestampsToReturn.Neither, new[] { new ReadValueId { NodeId = int32Id, AttributeId = Attributes.Value } }, ct);
    Check(back.Results[0].WrappedValue.ToString() == "1234", "read back: " + back.Results[0].WrappedValue);

    // Call method.
    var cr = await session.CallAsync(null, new[] { new CallMethodRequest {
        ObjectId = new NodeId("Demo.Methods", ns), MethodId = new NodeId("Demo.Methods.Add", ns),
        InputArguments = new[] { new Variant(2.0), new Variant(3.5) } } }, ct);
    Check(StatusCode.IsGood(cr.Results[0].StatusCode), "call: " + cr.Results[0].StatusCode);
    Check(cr.Results[0].OutputArguments[0].ToString() == "5.5", "call result: " + cr.Results[0].OutputArguments[0]);

    // Large request/response (multi-chunk in both directions).
    var many = Enumerable.Range(0, 4000).Select(i => new ReadValueId { NodeId = new NodeId((uint)(i % 2000 + 1)), AttributeId = Attributes.DisplayName }).ToArray();
    var big = await session.ReadAsync(null, 0, TimestampsToReturn.Both, many, ct);
    Check(big.Results.Count == 4000, "large read");

    // Subscription with raw service calls.
    var cs = await session.CreateSubscriptionAsync(null, 100, 100, 10, 0, true, 0, ct);
    var mi = await session.CreateMonitoredItemsAsync(null, cs.SubscriptionId, TimestampsToReturn.Both, new[] {
        new MonitoredItemCreateRequest {
            ItemToMonitor = new ReadValueId { NodeId = new NodeId("Demo.Dynamic.Counter", ns), AttributeId = Attributes.Value },
            MonitoringMode = MonitoringMode.Reporting,
            RequestedParameters = new MonitoringParameters { ClientHandle = 42, SamplingInterval = 100, QueueSize = 10, DiscardOldest = true } } }, ct);
    Check(StatusCode.IsGood(mi.Results[0].StatusCode), "create monitored item: " + mi.Results[0].StatusCode);
    int changes = 0;
    var acks = new List<SubscriptionAcknowledgement>();
    for (int i = 0; i < 20 && changes < 3; i++)
    {
        var pr = await session.PublishAsync(new RequestHeader { TimeoutHint = 10000 }, acks.ToArray(), ct);
        acks.Clear();
        foreach (var eo in pr.NotificationMessage.NotificationData)
        {
            if (eo.TryGetValue(out DataChangeNotification? dcn))
            {
                foreach (var n in dcn.MonitoredItems) { Check(n.ClientHandle == 42, "client handle"); changes++; }
            }
        }
        if (pr.NotificationMessage.NotificationData.Count > 0)
            acks.Add(new SubscriptionAcknowledgement { SubscriptionId = pr.SubscriptionId, SequenceNumber = pr.NotificationMessage.SequenceNumber });
    }
    Check(changes >= 3, "data change notifications: " + changes);
    var ds = await session.DeleteSubscriptionsAsync(null, new[] { cs.SubscriptionId }, ct);
    Check(StatusCode.IsGood(ds.Results[0]), "delete subscription");

    await session.CloseAsync(ct);
}

static void Check(bool ok, string what)
{
    if (!ok) throw new Exception("check failed: " + what);
}
