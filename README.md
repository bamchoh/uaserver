# uastack

[![Go Reference](https://pkg.go.dev/badge/github.com/bamchoh/uastack.svg)](https://pkg.go.dev/github.com/bamchoh/uastack) [![CI](https://github.com/bamchoh/uastack/actions/workflows/ci.yml/badge.svg)](https://github.com/bamchoh/uastack/actions/workflows/ci.yml)

English | [日本語](README.ja-JP.md)

An OPC UA stack for Go with a server and a client. The server is ported from the server side of [OPC UA .NET Standard](https://github.com/OPCFoundation/UA-.NETStandard);
the client shares its encoding, security and certificate code.
It has no dependencies beyond the Go standard library.

## Features

| Area | Support |
|---|---|
| Transport | opc.tcp (UA-CP: Hello/Ack/Error), message chunking in both directions |
| Encoding | UA Binary (all 25 built-in types; 345 structures generated from `Opc.Ua.Types.bsd`) |
| Security policies | None, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss, ECC_nistP256, ECC_nistP384 (each with Sign and SignAndEncrypt) |
| Secure channel | OPN (asymmetric encryption and signing), MSG (symmetric encryption and HMAC), token renewal, sequence number checks |
| Certificates | Self-signed certificates created automatically (RSA and ECC P-256 / P-384), a `pki/{own,trusted,issuer,rejected}` store with the same layout as the .NET stack, CA chain validation |
| User authentication | Anonymous, UserName (passwords are RSA encrypted, also on None endpoints; on ECC endpoints they are sent as an EccEncryptedSecret), X509 certificates (ECC user certificates on ECC endpoints) |
| Address space | The official `Opc.Ua.NodeSet2.xml` (namespace 0) is embedded and loaded; custom NodeSet2 files can be loaded with `LoadNodeSet` |
| Client | The same security policies, modes and user authentication as the server; GetEndpoints, FindServers, Browse / BrowseNext, TranslateBrowsePathsToNodeIds, Register/UnregisterNodes, Read, Write, Call and subscriptions with monitored items; token renewal, session keep-alive and automatic reconnect; any other service through `Client.Send` |
| Services | GetEndpoints, FindServers, CreateSession / ActivateSession / CloseSession, Browse / BrowseNext, TranslateBrowsePathsToNodeIds, Register/UnregisterNodes, Read, Write (with IndexRange and type checks), Call, all Subscription services (Create / Modify / SetPublishingMode / Publish / Republish / Transfer / Delete), all MonitoredItem services (data change notifications, absolute deadband) |

## Not supported

- Events and alarms (EventFilter), history (HistoryRead/Update), Query, NodeManagement (AddNodes etc.)
- PercentDeadband, SetTriggering, aggregate filters
- The AesGcm / ChaChaPoly variants of the ECC policies, brainpool, curve25519 / curve448, and the deprecated Basic128Rsa15 / Basic256
- HTTPS / WebSocket transports, PubSub, GDS, reverse connect
- CRL (certificate revocation list) checks

## Comparison with gopcua

[gopcua/opcua](https://github.com/gopcua/opcua) is the most widely used OPC UA library for Go.
gopcua focuses on the client and is used in many production environments; uastack focuses on the server, and its client is new.

The comparison below is based on reading the source of gopcua's main branch (commit `79fa869`, as of 2026-11-09),
not on the table in gopcua's README (a service that only returns `BadServiceUnsupported` is marked "No").
gopcua is actively developed, so check gopcua itself for its current state.

**Legend**: Yes = supported, No = not supported, Partial = partly supported (see the notes)

### Overview

| | uastack | gopcua |
|---|---|---|
| Main use | Server | Client (the server is in development) |
| Client | Yes (new, see [Client](#client)) | Yes (widely used in production) |
| Dependencies | Go standard library only | google/uuid, golang.org/x/exp, golang.org/x/term and others |
| Origin | Port of UA-.NETStandard | Independent implementation |
| Standard address space (namespace 0) | Yes, official NodeSet2 embedded | Yes, official NodeSet2 embedded |
| Loading custom NodeSet2 files | Yes | Yes |
| Interoperability testing | Server: interop tests against the official .NET client run in CI. Client: interop tests against the official .NET server run in CI; also checked by hand against the gopcua server | — |

### Security

| | uastack server | gopcua server | uastack client | gopcua client |
|---|---|---|---|---|
| None | Yes | Yes | Yes | Yes |
| Basic128Rsa15 (deprecated) | No | Partial, untested *1 | No | Yes |
| Basic256 (deprecated) | No | Partial, untested *1 | No | Yes |
| Basic256Sha256 | Yes | Partial, untested *1 | Yes | Yes |
| Aes128_Sha256_RsaOaep | Yes | Partial, untested *1 | Yes | Yes |
| Aes256_Sha256_RsaPss | Yes | Partial, untested *1 | Yes | Yes |
| ECC_nistP256 / ECC_nistP384 | Yes | No | Yes | No |
| Anonymous authentication | Yes | Yes | Yes | Yes |
| UserName authentication | Yes, passwords are checked | Partial *2 | Yes | Yes |
| X509 user authentication | Yes, signature and trust list are checked | Partial *2 | Yes | Yes |
| Peer certificate trust list (trusted / rejected) | Yes | No | Yes | No *3 |
| Self-signed certificate creation | Yes | No, the library takes a certificate and key (the examples contain generation code) | Yes | No |

*1 Marked "Untested" in gopcua's README.
*2 The token types can be offered, but ActivateSession does not check user tokens (passwords or certificates).
*3 The server certificate can be checked against a certificate pool given by the application.

### Services (server)

| Service set | Service | uastack | gopcua server |
|---|---|---|---|
| Discovery | FindServers / GetEndpoints | Yes | Yes |
| | FindServersOnNetwork | Partial, returns an empty list | No |
| | RegisterServer / RegisterServer2 | No | No |
| Session | CreateSession / ActivateSession / CloseSession | Yes | Yes |
| | Cancel | Partial, responds but cancels nothing | No |
| View | Browse / BrowseNext | Yes | Yes |
| | TranslateBrowsePathsToNodeIds | Yes | No |
| | RegisterNodes / UnregisterNodes | Yes | Yes |
| Attribute | Read / Write | Yes | Yes |
| | HistoryRead / HistoryUpdate | No | No |
| Method | Call | Yes | No |
| MonitoredItem | CreateMonitoredItems / DeleteMonitoredItems / SetMonitoringMode | Yes | Yes |
| | ModifyMonitoredItems | Yes | No |
| | SetTriggering | No | No |
| Subscription | CreateSubscription / DeleteSubscriptions / Publish | Yes | Yes |
| | ModifySubscription / SetPublishingMode | Yes | No |
| | Republish / TransferSubscriptions | Yes | No |
| NodeManagement | AddNodes etc. | No | No |
| Query | QueryFirst / QueryNext | No | No |

### Performance

The same client (gopcua v0.9.1) sent the same operations to uastack and to the gopcua v0.9.1 server.
Both servers hold the same 1000 Int32 variables in the same namespace.
The benchmark code is in [`bench/`](bench); it is a separate module, so uastack itself does not depend on gopcua.

Environment: Windows 11 / amd64, Intel Core i7-11800H (16 logical cores), Go 1.25.6, server and client on the same machine (localhost).
Each benchmark was run three times; every result stayed within a few percent, and one run is shown.

| | uastack | gopcua | Difference |
|---|---|---|---|
| Connect and disconnect (None) | 1.75 ms | 1.91 ms | uastack about 10% faster |
| Connect and disconnect (Basic256Sha256 / SignAndEncrypt) | 12.0 ms | 11.7 ms | About the same (dominated by RSA) |
| Read 1 node (None) | 72 µs (13,954/s) | 106 µs (9,428/s) | uastack about 1.5x |
| Read 1 node (Basic256Sha256 / SignAndEncrypt) | 83 µs (12,061/s) | 118 µs (8,469/s) | uastack about 1.4x |
| Read 1000 nodes in one request (None) | 1.99 ms (500k nodes/s) | 3.73 ms (270k nodes/s) | uastack about 1.9x |
| Read 1 node, 8 parallel clients (None) | 34,086/s | 23,755/s | uastack about 1.4x |
| Write 1 node (None) | 72 µs (13,850/s) | 100 µs (9,996/s) | uastack about 1.4x |
| Browse (folder with 1000 references) | 2.18 ms | 17.6 ms | uastack about 8x |
| Write to data change notification (a write every 50 ms) | under 1 ms * | 9.4 ms | uastack notifies as soon as the value changes |
| Write to data change notification (next write right after each notification) | 10.0 ms | 10.0 ms | Same (limited by the 10 ms publishing interval) |
| Memory: Go heap (idle) | 14.4 MB | 22.3 MB | |
| Memory: Go heap (20 connected sessions) | 14.6 MB | 24.2 MB | |

All times are averages per operation, computed from the wall clock time of the whole measurement loop divided by the number of operations.
On Windows, Go's clock resolution is only about 0.1 to 0.5 ms, so timing single fast operations is not reliable.
The times include the client's own processing, so the difference between the servers alone is larger than shown.

\* The notification latency can only be timed one write at a time; the three runs measured 14 to 39 µs. This is below the clock resolution, so it is shown as "under 1 ms".

**Notes on the results**

- **Data change notifications**: when a value changes through `SetValue` or a client Write, uastack creates the notification right away and sends it as soon as the publishing interval allows. gopcua waits for the next publishing cycle, so it is one publishing interval (10 ms here) late. When values are written back to back, both are limited by the publishing interval the client requested (one message per 10 ms). Variables that return their value from `OnRead` cannot report changes, so uastack polls them every `Config.MinSamplingInterval` (50 ms by default).
- **The Write comparison favors gopcua**: the gopcua server does not check the type or array shape of written values; uastack does.
- **Only Basic256Sha256 / SignAndEncrypt is compared with security**: the other combinations are not implemented or not tested in the gopcua server.

**Encoding and decoding**

The `ua` packages of both libraries were compared with `go test -bench` on the same messages.
A test first checks that both produce exactly the same bytes.

| Operation (1000 elements) | uastack | gopcua | Difference |
|---|---|---|---|
| Encode ReadResponse | 54 µs, 113 KB, 15 allocations | 343 µs, 257 KB, 6,786 allocations | about 6x |
| Decode ReadResponse | 62 µs, 126 KB, 747 allocations | 316 µs, 229 KB, 5,506 allocations | about 5x |
| Encode ReadRequest | 34 µs, 113 KB, 15 allocations | 1,067 µs, 628 KB, 17,792 allocations | about 31x |
| Decode ReadRequest | 48 µs, 94 KB, 1,003 allocations | 990 µs, 503 KB, 11,764 allocations | about 21x |

The main reason is the design: uastack uses code generated from the schema, while gopcua uses reflection.

### Client performance

The uastack client and the gopcua v0.9.1 client ran the same operations against the same server, the uastack benchmark server in a separate process.
The code is in [`bench/cmd/clients`](bench/cmd/clients). The environment is the same as above; each benchmark was run three times, and one run is shown.

| | uastack client | gopcua client | Difference |
|---|---|---|---|
| Connect and disconnect (None) | 1.53 ms | 1.78 ms | uastack about 1.2x * |
| Connect and disconnect (Basic256Sha256 / SignAndEncrypt) | 10.9 ms | 11.4 ms | About the same (dominated by RSA) |
| Read 1 node (None) | 49 µs, 15 allocations / 2.2 KB | 73 µs, 131 allocations / 68 KB | uastack about 1.5x |
| Read 1 node (Basic256Sha256 / SignAndEncrypt) | 54 µs, 32 allocations / 5.6 KB | 80 µs, 151 allocations / 72 KB | uastack about 1.5x |
| Read 1000 nodes in one request (None) | 497 µs (2.0M nodes/s), 782 allocations / 581 KB | 1.92 ms (522k nodes/s), 26,370 allocations / 1.1 MB | uastack about 3.9x |
| Read 1000 nodes in one request (Basic256Sha256 / SignAndEncrypt) | 630 µs | 2.06 ms | uastack about 3.3x |
| Read 1 node, 8 parallel requests on one client (None) | 73,705/s | 23,417/s | uastack about 3.1x |
| Write 1 node (None) | 46 µs, 17 allocations / 2.1 KB | 73 µs, 121 allocations / 68 KB | uastack about 1.6x |
| Browse (folder with 1000 references) | 525 µs | 2.19 ms | uastack about 4.2x |
| Write to data change notification | 10.0 ms | 10.0 ms | Same (limited by the 10 ms publishing interval) |
| Client heap growth with 20 connected sessions | 1.2 MB | 5.5 MB | |

Allocations are per operation in the client process.
With the gopcua server instead, the uastack client was about 1.3x faster for single reads and writes and about 1.7x for 1000 nodes; the server is then the larger part of the time.

\* One of the three runs measured 4.6 ms for the uastack client; the other two measured 1.53 and 1.54 ms.
The uastack client skips GetEndpoints for the None policy and takes the endpoint from the CreateSession response.

**Reproducing**

```sh
cd bench
go run ./cmd/runner           # server comparison (takes a few minutes)
go run ./cmd/clients          # client comparison (-server gopcua to use the gopcua server)
go test -bench . -benchmem    # encoding / decoding comparison
```

Results vary between machines and operating systems; use the ratios rather than the absolute numbers.

### Which one to use

- **To connect to OPC UA servers and read or write values** (a client): gopcua is the proven choice and supports the deprecated policies.
  uastack's client is new; it adds the ECC policies, a trust list for server certificates and notifications delivered in order,
  and it is faster and allocates less (see [Client performance](#client-performance)).
- **To build an OPC UA server in Go**: uastack covers more, including authentication, certificate trust management, method calls and the full set of subscription services.
- **To connect to old devices that only support the deprecated policies (Basic128Rsa15 / Basic256)**: uastack does not support them.

## Usage

```sh
go run ./cmd/opcuasrv -addr :4840
```

Main options:

| Option | Description |
|---|---|
| `-addr` | Listen address (default `:4840`) |
| `-url` | Advertised endpoint URL (default `opc.tcp://<hostname>:<port>`) |
| `-pki` | Certificate store directory (default `pki`) |
| `-users` | Comma separated `user:password` list (default `user1:password1`) |
| `-autoaccept` | Trust all client certificates (for testing only) |
| `-secure-only` | Do not offer the None security policy |

On the first secure connection, the client certificate is stored in `pki/rejected/certs` and the connection is rejected.
Move that file to `pki/trusted/certs` and the client can connect, without restarting the server.

### Demo address space

`Objects/Demo` contains variables for testing (namespace `urn:opcuasrv:demo`, NodeIds `s=Demo.<folder>.<name>`).
All variables except those in Dynamic and Methods are writable.

| Folder | Contents |
|---|---|
| `Static` | Scalars of every built-in type (Boolean to UInt64, Float, Double, String, DateTime, Guid, ByteString, XmlElement, LocalizedText, QualifiedName, NodeId, ExpandedNodeId, StatusCode) |
| `Arrays` | One dimensional arrays of every built-in type. `ByteArray` is an array of Byte, not a ByteString |
| `Matrices` | Two dimensional arrays (Byte 4x4, Int32 3x4, Double 2x3, Boolean 2x2, String 2x3) and three dimensional arrays (Byte 2x2x3, Int32 2x3x4, Float 2x2x2) |
| `Structures` | Structures (Range, an array of Range, EUInformation, TimeZoneDataType) and an enumeration (NodeClass) |
| `Dynamic` | Counter and Sine, which change every 0.5 seconds, and Time, which returns the current time on every read |
| `Methods` | An `Add(a, b)` method |

Matrix elements are stored row-major (the last index changes fastest) and numbered from 0, so element `[i][j]` of a 3x4 matrix is `i*4+j`.
A written matrix may not be larger than the variable's ArrayDimensions.

### Using the library

```sh
go get github.com/bamchoh/uastack/server
```

The packages are `github.com/bamchoh/uastack/server` (the server), `.../ua` (types and encoding) and `.../uasc` (security policies).

```go
srv, _ := server.New(server.Config{
    ApplicationName: "My Server",
    ListenAddr:      ":4840",
    Security: []server.SecurityConfig{
        {PolicyURI: uasc.SecurityPolicyBasic256Sha256,
         Modes: []ua.MessageSecurityMode{ua.MessageSecurityModeSignAndEncrypt}},
    },
})
as := srv.AddressSpace()
ns := as.RegisterNamespace("urn:example")
as.AddVariable(server.ObjectsFolder, ua.NewStringNodeId(ns, "Temp"),
    ua.NewQualifiedName(ns, "Temp"), ua.NewVariant(21.5), server.VariableOptions{})
go srv.ListenAndServe()
as.SetValue(ua.NewStringNodeId(ns, "Temp"), ua.NewVariant(22.0)) // subscribed clients are notified
```

`Node.OnRead` / `Node.OnWrite` customize how values are read and written, and `AddMethod` adds methods.

## Client

`cmd/opcuacli` is a small command line client:

```sh
go run ./cmd/opcuacli endpoints opc.tcp://localhost:4840
go run ./cmd/opcuacli browse    opc.tcp://localhost:4840 "ns=2;s=Demo"
go run ./cmd/opcuacli -policy Basic256Sha256 -user user1 -password password1 \
    read opc.tcp://localhost:4840 "ns=2;s=Demo.Static.Int32"
go run ./cmd/opcuacli write     opc.tcp://localhost:4840 "ns=2;s=Demo.Static.Int32" 42
go run ./cmd/opcuacli subscribe opc.tcp://localhost:4840 "ns=2;s=Demo.Dynamic.Counter"
```

`-policy best` picks the most secure endpoint and `-mode Sign` selects signing only (the default is SignAndEncrypt).
With a secure policy, the first connection fails and the server certificate is stored in `pki-client/rejected/certs`;
move it to `pki-client/trusted/certs` to trust the server (or pass `-autoaccept` for testing).
The client certificate is created in `pki-client/own`, and the server must trust it in the same way.

### Using the client library

```go
c, err := client.Dial(ctx, "opc.tcp://localhost:4840", client.Config{
    SecurityPolicy: uasc.SecurityPolicyBasic256Sha256, // default None
    PKIDir:         "pki-client",                      // own certificate and trusted servers
    Identity:       client.UserName("user1", "password1"),
})
if err != nil { ... }
defer c.Close(ctx)

id := ua.NewStringNodeId(2, "Demo.Static.Int32")
dv, err := c.ReadValue(ctx, id)
err = c.WriteValue(ctx, id, ua.NewVariant(int32(42)))
refs, err := c.BrowseChildren(ctx, ua.NewNumericNodeId(0, uaid.ObjectsFolder))
out, err := c.CallMethod(ctx, objectID, methodID, ua.NewVariant(1.0), ua.NewVariant(2.0))

sub, err := c.CreateSubscription(ctx, client.SubscriptionParams{PublishingInterval: 100 * time.Millisecond})
items, err := sub.MonitorValues(ctx, id)
for n := range sub.Notifications() { // in sequence number order
    for _, dc := range n.DataChanges {
        fmt.Println(dc.ClientHandle, dc.Value.Value)
    }
}
```

- Errors wrap the OPC UA status code: `errors.Is(err, ua.StatusBadNodeIdUnknown)` works for service results, and for the result of the single operation in `ReadValue`, `WriteValue` and `CallMethod`.
- `Read`, `Write`, `Browse`, `Call` and the other methods named after a service take the full request; `Client.Send` sends any request.
- `client.X509(cert, key)` logs in with a user certificate. `GetEndpoints`, `SelectEndpoint` and `DialEndpoint` choose an endpoint explicitly.
- Without `PKIDir` the client certificate is created in memory, and the server certificate must be accepted by `VerifyServerCertificate` or `AutoAcceptUntrustedCertificates`.
- The session is kept alive while idle, and the security token is renewed before it expires.
- With `AutoReconnect`, a lost connection is restored with backoff: the session is activated on a new secure channel, and notifications sent on the lost channel are fetched again with Republish.
  If the server has dropped the session, a new one is created and the subscriptions are transferred, or created again with the same monitored items and client handles.
  Requests made while reconnecting wait until the connection is back or their context ends; requests that were in flight when the connection broke fail and are not resent.
  `OnStateChange` reports the changes (`StateConnected`, `StateReconnecting`, `StateClosed`).
- Without `AutoReconnect`, `Done()` is closed when the connection is lost, and each subscription's channel receives a notification with `Err` set and is then closed.

## Package layout

| Package | Counterpart in the .NET stack |
|---|---|
| `ua` | Built-in types of Opc.Ua.Core, BinaryEncoder/Decoder, generated types (`types_gen.go`, `id/ids_gen.go`, `status_gen.go`) |
| `uacp` | TcpMessageSocket / Hello and Acknowledge handling (server and client side) |
| `uasc` | UaSCBinaryChannel (channel, chunks, tokens) and SecurityPolicies (server and client side) |
| `uacert` | CertificateValidator, CertificateFactory and the directory certificate stores |
| `server` | Opc.Ua.Server (StandardServer, SessionManager, SubscriptionManager, MasterNodeManager) |
| `client` | Opc.Ua.Client (Session, Subscription), written for Go rather than ported |
| `internal/gen` | Code generation from the schema files (`go generate ./ua`) |

## Testing

```sh
go test ./...
```

The client tests connect the client to the server over TCP on every endpoint (each policy and mode) with anonymous, user name and X509 identities.
They also cover browsing with continuation points, multi-chunk messages, subscriptions, token renewal, session keep-alive and certificate trust.

Interoperability tests with the official .NET client (OPCFoundation.NetStandard.Opc.Ua.Client 2.0.1):

```sh
go run ./cmd/opcuasrv -addr :48400 -url opc.tcp://localhost:48400 -autoaccept
cd tests/interop/dotnet && dotnet run -- opc.tcp://localhost:48400
```

They cover every security policy (including ECC) and mode, anonymous, user name and X509 (RSA and ECC) authentication,
Browse / Translate / Read / Write / Call, reading 4000 nodes at once (multiple chunks), Subscription and Publish, and token renewal (RSA and ECC).

Interoperability tests of the client with a server built on the official .NET stack (OPCFoundation.NetStandard.Opc.Ua.Server 2.0.1):

```sh
cd tests/interop/dotnet-server && dotnet run -- 48600      # prints READY when listening
go run ./tests/interop/goclient opc.tcp://localhost:48600   # from the repository root
```

They connect to every endpoint (each policy and mode, including ECC) with anonymous, user name (including a wrong password) and X509 (RSA and ECC) identities,
and read, browse, write and receive data change notifications on each. Both interop tests run in CI.

## License

MIT License. See [LICENSE](LICENSE).
Parts of uastack come from the OPC Foundation under the OPC Foundation MIT License; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
