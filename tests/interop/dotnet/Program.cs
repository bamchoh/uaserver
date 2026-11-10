// Interop test: drives the Go server with the official OPC Foundation .NET client stack.
// Usage: dotnet run -- opc.tcp://localhost:48400
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;
using Opc.Ua.Security.Certificates;

string url = args.Length > 0 ? args[0] : "opc.tcp://localhost:48400";
// Optional second argument: run only the cases whose name contains this text.
string? only = args.Length > 1 ? args[1] : null;
ITelemetryContext telemetry = DefaultTelemetry.Create(l => l.AddConsole().SetMinimumLevel(Environment.GetEnvironmentVariable("INTEROP_VERBOSE") != null ? LogLevel.Information : LogLevel.Critical));
string pki = Path.Combine(AppContext.BaseDirectory, "pki");

var config = new ApplicationConfiguration(telemetry)
{
    ApplicationName = "InteropClient",
    ApplicationUri = "urn:localhost:opcuasrv:InteropClient",
    ApplicationType = ApplicationType.Client,
    SecurityConfiguration = new SecurityConfiguration
    {
        // One application certificate per key type: RSA for the RSA policies,
        // NIST P-256 / P-384 for the ECC policies.
        ApplicationCertificates =
        [
            new CertificateIdentifier { StoreType = CertificateStoreType.Directory, StorePath = Path.Combine(pki, "own"),
                SubjectName = "CN=InteropClient, O=opcuasrv", CertificateType = ObjectTypeIds.RsaSha256ApplicationCertificateType },
            new CertificateIdentifier { StoreType = CertificateStoreType.Directory, StorePath = Path.Combine(pki, "own"),
                SubjectName = "CN=InteropClient, O=opcuasrv", CertificateType = ObjectTypeIds.EccNistP256ApplicationCertificateType },
            new CertificateIdentifier { StoreType = CertificateStoreType.Directory, StorePath = Path.Combine(pki, "own"),
                SubjectName = "CN=InteropClient, O=opcuasrv", CertificateType = ObjectTypeIds.EccNistP384ApplicationCertificateType },
        ],
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
const string E256 = SecurityPolicies.ECC_nistP256;
const string E384 = SecurityPolicies.ECC_nistP384;
var anon = new UserIdentity(new AnonymousIdentityToken());
IUserIdentity User(string u, string p) => new UserIdentity(u, System.Text.Encoding.UTF8.GetBytes(p));

// X509 user: a dedicated user certificate (no application URI, unlike the
// application instance certificate) stored in its own directory store.
var userCertId = new CertificateIdentifier
{
    StoreType = CertificateStoreType.Directory,
    StorePath = Path.Combine(pki, "user"),
    SubjectName = "CN=InteropUser, O=opcuasrv"
};
using (ICertificateStore store = new CertificateStoreIdentifier(userCertId.StorePath, false).OpenStore(telemetry))
{
    if ((await store.EnumerateAsync(CancellationToken.None)).Count == 0)
    {
        using var userCert = CertificateBuilder.Create(userCertId.SubjectName).SetLifeTime(12).CreateForRSA();
        await store.AddAsync(userCert, null, CancellationToken.None);
    }
}
var x509 = new UserIdentity(new X509IdentityTokenHandler(userCertId, new CertificatePasswordProvider(), config.CertificateManager.CertificateProvider, null));

// ECC endpoints only accept user tokens of the same key family, so the X509
// user for ECC endpoints has a NIST P-256 certificate.
var userEccCertId = new CertificateIdentifier
{
    StoreType = CertificateStoreType.Directory,
    StorePath = Path.Combine(pki, "user_ecc"),
    SubjectName = "CN=InteropEccUser, O=opcuasrv",
    CertificateType = ObjectTypeIds.EccNistP256ApplicationCertificateType
};
using (ICertificateStore store = new CertificateStoreIdentifier(userEccCertId.StorePath, false).OpenStore(telemetry))
{
    if ((await store.EnumerateAsync(CancellationToken.None)).Count == 0)
    {
        using var userCert = CertificateBuilder.Create(userEccCertId.SubjectName).SetLifeTime(12)
            .SetECCurve(System.Security.Cryptography.ECCurve.NamedCurves.nistP256).CreateForECDsa();
        await store.AddAsync(userCert, null, CancellationToken.None);
    }
}
var x509Ecc = new UserIdentity(new X509IdentityTokenHandler(userEccCertId, new CertificatePasswordProvider(), config.CertificateManager.CertificateProvider, null));

var cases = new (string Policy, MessageSecurityMode Mode, IUserIdentity User, bool ExpectOk)[]
{
    (None, MessageSecurityMode.None, x509, true),
    (B256, MessageSecurityMode.SignAndEncrypt, x509, true),
    (A256, MessageSecurityMode.Sign, x509, true),
    (E256, MessageSecurityMode.Sign, anon, true),
    (E256, MessageSecurityMode.SignAndEncrypt, anon, true),
    (E384, MessageSecurityMode.Sign, anon, true),
    (E384, MessageSecurityMode.SignAndEncrypt, anon, true),
    (E256, MessageSecurityMode.SignAndEncrypt, x509Ecc, true),
    (None, MessageSecurityMode.None, anon, true),
    (None, MessageSecurityMode.None, User("user1", "password1"), true),
    (B256, MessageSecurityMode.Sign, anon, true),
    (B256, MessageSecurityMode.SignAndEncrypt, User("user1", "password1"), true),
    (A128, MessageSecurityMode.Sign, anon, true),
    (A128, MessageSecurityMode.SignAndEncrypt, anon, true),
    (A256, MessageSecurityMode.Sign, User("user1", "password1"), true),
    (A256, MessageSecurityMode.SignAndEncrypt, anon, true),
    (B256, MessageSecurityMode.SignAndEncrypt, User("user1", "wrong"), false),
    (E256, MessageSecurityMode.Sign, User("user1", "password1"), true),
    (E256, MessageSecurityMode.SignAndEncrypt, User("user1", "password1"), true),
    (E384, MessageSecurityMode.SignAndEncrypt, User("user1", "password1"), true),
    (E384, MessageSecurityMode.Sign, User("user1", "wrong"), false),
};

int failures = 0;
foreach (var c in cases)
{
    string name = $"{c.Policy.Split('#')[1]}/{c.Mode}/{(c.User.TokenType == UserTokenType.Anonymous ? "anon" : c.User.DisplayName)}";
    if (only != null && !name.Contains(only)) continue;
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
// RSA renews with new random nonces, ECC with new ephemeral keys.
config.TransportQuotas.SecurityTokenLifetime = 10000;
foreach (string policy in only == null ? new[] { B256, E256 } : Array.Empty<string>())
{
    string name = policy.Split('#')[1];
    try
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1));
        await using ManagedSession s = await new ManagedSessionBuilder(config, telemetry)
            .UseEndpoint(url, MessageSecurityMode.SignAndEncrypt, policy)
            .WithSessionName("interop renewal " + name).WithUserIdentity(anon).ConnectAsync(cts.Token);
        for (int i = 0; i < 25; i++)
        {
            var r = await s.ReadAsync(null, 0, TimestampsToReturn.Both, new[] {
                new ReadValueId { NodeId = VariableIds.Server_ServerStatus_CurrentTime, AttributeId = Attributes.Value } }, cts.Token);
            Check(StatusCode.IsGood(r.Results[0].StatusCode), "read during renewal");
            await Task.Delay(1000, cts.Token);
        }
        await s.CloseAsync(cts.Token);
        Console.WriteLine($"PASS token renewal {name} (25s with 10s token lifetime)");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"FAIL token renewal {name}: {ex}");
        failures++;
    }
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
        new ReadValueId { NodeId = new NodeId("Demo.Arrays.Int32Array", ns), AttributeId = Attributes.Value, IndexRange = "1:2" },
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

    // Every demo variable must be readable and decodable.
    foreach (string folder in new[] { "Static", "Arrays", "Matrices", "Structures" })
    {
        var fb = await session.BrowseAsync(null, null, 0, new[] { new BrowseDescription {
            NodeId = new NodeId("Demo." + folder, ns), BrowseDirection = BrowseDirection.Forward,
            ReferenceTypeId = ReferenceTypeIds.Organizes, IncludeSubtypes = true,
            NodeClassMask = (uint)NodeClass.Variable, ResultMask = (uint)BrowseResultMask.All } }, ct);
        var vars = fb.Results[0].References.ToArray();
        Check(vars.Length > 0, "browse Demo." + folder);
        var all = await session.ReadAsync(null, 0, TimestampsToReturn.Neither, vars.Select(r => new ReadValueId {
            NodeId = ExpandedNodeId.ToNodeId(r.NodeId, session.NamespaceUris), AttributeId = Attributes.Value }).ToArray(), ct);
        var allRes = all.Results.ToArray();
        for (int i = 0; i < vars.Length; i++)
            Check(StatusCode.IsGood(allRes[i].StatusCode) && !allRes[i].WrappedValue.IsNull,
                $"read Demo.{folder}.{vars[i].BrowseName.Name}: {allRes[i].StatusCode}");
    }

    // Byte array, matrices and structures.
    NodeId Demo(string path) => new NodeId("Demo." + path, ns);
    var mr = await session.ReadAsync(null, 0, TimestampsToReturn.Neither, new[] {
        new ReadValueId { NodeId = Demo("Arrays.ByteArray"), AttributeId = Attributes.Value },
        new ReadValueId { NodeId = Demo("Matrices.Int32Matrix3D"), AttributeId = Attributes.Value },
        new ReadValueId { NodeId = Demo("Matrices.Int32Matrix3D"), AttributeId = Attributes.ValueRank },
        new ReadValueId { NodeId = Demo("Matrices.Int32Matrix3D"), AttributeId = Attributes.ArrayDimensions },
        new ReadValueId { NodeId = Demo("Matrices.ByteMatrix2D"), AttributeId = Attributes.Value },
        new ReadValueId { NodeId = Demo("Structures.Range"), AttributeId = Attributes.Value },
    }, ct);
    var m = mr.Results.ToArray();
    var byteArray = m[0].WrappedValue;
    Check(byteArray.TypeInfo.BuiltInType == BuiltInType.Byte && byteArray.TypeInfo.IsArray,
        "ByteArray is Byte[] (not ByteString): " + byteArray.TypeInfo);
    var cube = (int[,,])m[1].WrappedValue.GetInt32Matrix(default);
    Check(cube.GetLength(0) == 2 && cube.GetLength(1) == 3 && cube.GetLength(2) == 4 && cube[1, 2, 3] == 23,
        "Int32Matrix3D [2,3,4] row-major");
    Check(m[2].WrappedValue.ToString() == "3", "Int32Matrix3D ValueRank: " + m[2].WrappedValue);
    Check(m[3].WrappedValue.ToString().Contains('2') && m[3].WrappedValue.ToString().Contains('4'),
        "Int32Matrix3D ArrayDimensions: " + m[3].WrappedValue);
    var bm = (byte[,])m[4].WrappedValue.GetByteMatrix(default);
    Check(bm.GetLength(0) == 4 && bm[3, 2] == 14, "ByteMatrix2D [4,4]");
    Check(m[5].WrappedValue.TryGetStructure(out Opc.Ua.Range? range) && range!.High == 100, "Range structure: " + m[5].WrappedValue);

    // Write a matrix and read it back; a matrix larger than ArrayDimensions is rejected.
    var newMatrix = new int[3, 4];
    for (int i = 0; i < 3; i++) for (int j = 0; j < 4; j++) newMatrix[i, j] = 100 + i * 4 + j;
    var mw = await session.WriteAsync(null, new[] {
        new WriteValue { NodeId = Demo("Matrices.Int32Matrix2D"), AttributeId = Attributes.Value,
            Value = new DataValue(new Variant(MatrixOf.From<int>(newMatrix))) },
        new WriteValue { NodeId = Demo("Matrices.Int32Matrix2D"), AttributeId = Attributes.Value,
            Value = new DataValue(new Variant(MatrixOf.From<int>(new int[5, 5]))) },
    }, ct);
    var mwr = mw.Results.ToArray();
    Check(StatusCode.IsGood(mwr[0]), "write matrix: " + mwr[0]);
    Check(mwr[1] == StatusCodes.BadTypeMismatch, "write oversized matrix: " + mwr[1]);
    var mb = await session.ReadAsync(null, 0, TimestampsToReturn.Neither, new[] {
        new ReadValueId { NodeId = Demo("Matrices.Int32Matrix2D"), AttributeId = Attributes.Value } }, ct);
    var back2 = (int[,])mb.Results[0].WrappedValue.GetInt32Matrix(default);
    Check(back2[2, 3] == 111, "matrix read back");

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
