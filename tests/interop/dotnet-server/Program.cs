// Reference server built on the official OPC Foundation .NET stack, used to
// test the Go client (tests/interop/goclient) against another implementation.
// Usage: dotnet run -- [port]   (default 48600). Prints READY when listening.
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Configuration;
using Opc.Ua.Server;

var level = Environment.GetEnvironmentVariable("SRV_LOG") switch { "debug" => LogLevel.Debug, "trace" => LogLevel.Trace, _ => LogLevel.Information };
ITelemetryContext telemetry = DefaultTelemetry.Create(l => l.AddSimpleConsole(o => o.SingleLine = true).SetMinimumLevel(level));
string pki = Path.Combine(AppContext.BaseDirectory, "pki");
string Url = $"opc.tcp://localhost:{(args.Length > 0 ? args[0] : "48600")}";

var policies = new List<ServerSecurityPolicy> { new ServerSecurityPolicy { SecurityMode = MessageSecurityMode.None, SecurityPolicyUri = SecurityPolicies.None } };
foreach (var p in new[] { SecurityPolicies.Basic256Sha256, SecurityPolicies.Aes128_Sha256_RsaOaep, SecurityPolicies.Aes256_Sha256_RsaPss, SecurityPolicies.ECC_nistP256, SecurityPolicies.ECC_nistP384 })
    foreach (var m in new[] { MessageSecurityMode.Sign, MessageSecurityMode.SignAndEncrypt })
        policies.Add(new ServerSecurityPolicy { SecurityMode = m, SecurityPolicyUri = p });

var config = new ApplicationConfiguration(telemetry)
{
    ApplicationName = "DotnetInteropServer",
    ApplicationUri = "urn:localhost:opcuasrv:DotnetInteropServer",
    ApplicationType = ApplicationType.Server,
    SecurityConfiguration = new SecurityConfiguration
    {
        ApplicationCertificates =
        [
            new CertificateIdentifier { StoreType = CertificateStoreType.Directory, StorePath = Path.Combine(pki, "own"),
                SubjectName = "CN=DotnetInteropServer, O=opcuasrv", CertificateType = ObjectTypeIds.RsaSha256ApplicationCertificateType },
            new CertificateIdentifier { StoreType = CertificateStoreType.Directory, StorePath = Path.Combine(pki, "own"),
                SubjectName = "CN=DotnetInteropServer, O=opcuasrv", CertificateType = ObjectTypeIds.EccNistP256ApplicationCertificateType },
            new CertificateIdentifier { StoreType = CertificateStoreType.Directory, StorePath = Path.Combine(pki, "own"),
                SubjectName = "CN=DotnetInteropServer, O=opcuasrv", CertificateType = ObjectTypeIds.EccNistP384ApplicationCertificateType },
        ],
        TrustedIssuerCertificates = new CertificateTrustList { StoreType = CertificateStoreType.Directory, StorePath = Path.Combine(pki, "issuer") },
        TrustedPeerCertificates = new CertificateTrustList { StoreType = CertificateStoreType.Directory, StorePath = Path.Combine(pki, "trusted") },
        RejectedCertificateStore = new CertificateTrustList { StoreType = CertificateStoreType.Directory, StorePath = Path.Combine(pki, "rejected") },
        AutoAcceptUntrustedCertificates = true
    },
    TransportQuotas = new TransportQuotas { MaxMessageSize = 8 * 1024 * 1024 },
    ServerConfiguration = new ServerConfiguration
    {
        BaseAddresses = [Url],
        SecurityPolicies = [.. policies],
        UserTokenPolicies =
        [
            new UserTokenPolicy(UserTokenType.Anonymous),
            new UserTokenPolicy(UserTokenType.UserName),
            new UserTokenPolicy(UserTokenType.Certificate),
        ],
    },
};
await config.ValidateAsync(ApplicationType.Server, CancellationToken.None);
var app = new ApplicationInstance(config, telemetry);
await app.CheckApplicationInstanceCertificatesAsync(true, ct: CancellationToken.None);
config.CertificateManager ??= CertificateManagerFactory.Create(config.SecurityConfiguration, telemetry);
config.CertificateManager.AcceptError = static (_, _) => true;

var server = new InteropServer(telemetry);
await app.StartAsync(server, CancellationToken.None);
foreach (var ep in server.GetEndpoints())
    Console.WriteLine($"endpoint {ep.EndpointUrl} {ep.SecurityPolicyUri} {ep.SecurityMode} tokens={string.Join(",", ep.UserIdentityTokens.ToArray().Select(t => t.TokenType + ":" + t.SecurityPolicyUri))}");
Console.WriteLine("writable Int32 node: ns=2;s=Int");
Console.WriteLine("READY");
var done = new TaskCompletionSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; done.TrySetResult(); };
await done.Task;
await server.StopAsync(CancellationToken.None);

class InteropServer(ITelemetryContext telemetry) : StandardServer(telemetry)
{
    protected override MasterNodeManager CreateMasterNodeManager(IServerInternal server, ApplicationConfiguration configuration)
        => new MasterNodeManager(server, configuration, null, new INodeManager[] { new InteropNodeManager(server, configuration) });

    protected override void OnServerStarted(IServerInternal server)
    {
        base.OnServerStarted(server);
        server.SessionManager.ImpersonateUser += (session, args) =>
        {
            if (args.UserIdentityTokenHandler is UserNameIdentityTokenHandler u)
            {
                string pw = System.Text.Encoding.UTF8.GetString(u.DecryptedPassword.ToArray());
                Console.WriteLine($"ImpersonateUser: user={u.UserName} pwlen={pw.Length} policy={args.UserTokenPolicy?.SecurityPolicyUri}");
                if (u.UserName == "user1" && pw == "password1")
                    args.Identity = new UserIdentity(u);
                else
                    args.IdentityValidationError = new ServiceResult(StatusCodes.BadUserAccessDenied);
            }
            else if (args.UserIdentityTokenHandler is X509IdentityTokenHandler x)
            {
                // The stack has verified the token signature; any user certificate is accepted.
                Console.WriteLine($"ImpersonateUser: certificate policy={args.UserTokenPolicy?.SecurityPolicyUri}");
                args.Identity = new UserIdentity(x);
            }
        };
    }
}

class InteropNodeManager(IServerInternal server, ApplicationConfiguration config) : CustomNodeManager2(server, config, "urn:opcuasrv:dotnet-interop")
{
    public override void CreateAddressSpace(IDictionary<NodeId, IList<IReference>> externalReferences)
    {
        lock (Lock)
        {
            base.CreateAddressSpace(externalReferences);
            var v = new BaseDataVariableState(null)
            {
                NodeId = new NodeId("Int", NamespaceIndex),
                BrowseName = new QualifiedName("Int", NamespaceIndex),
                DisplayName = new LocalizedText("Int"),
                TypeDefinitionId = VariableTypeIds.BaseDataVariableType,
                DataType = DataTypeIds.Int32,
                ValueRank = ValueRanks.Scalar,
                AccessLevel = AccessLevels.CurrentReadOrWrite,
                UserAccessLevel = AccessLevels.CurrentReadOrWrite,
                Value = new Variant(0),
                StatusCode = StatusCodes.Good,
                Timestamp = DateTime.UtcNow,
            };
            if (!externalReferences.TryGetValue(ObjectIds.ObjectsFolder, out var refs))
                externalReferences[ObjectIds.ObjectsFolder] = refs = new List<IReference>();
            v.AddReference(ReferenceTypeIds.Organizes, true, ObjectIds.ObjectsFolder);
            refs.Add(new NodeStateReference(ReferenceTypeIds.Organizes, false, v.NodeId));
            AddPredefinedNode(SystemContext, v);
        }
    }
}
