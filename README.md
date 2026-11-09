# uaserver

English | [日本語](README.ja-JP.md)

An OPC UA server library for Go, ported from the server side of [OPC UA .NET Standard](https://github.com/OPCFoundation/UA-.NETStandard).
It has no dependencies beyond the Go standard library.

## Features

| Area | Support |
|---|---|
| Transport | opc.tcp (UA-CP: Hello/Ack/Error), message chunking in both directions |
| Encoding | UA Binary (all 25 built-in types; 345 structures generated from `Opc.Ua.Types.bsd`) |
| Security policies | None, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss, ECC_nistP256, ECC_nistP384 (each with Sign and SignAndEncrypt) |
| Secure channel | OPN (asymmetric encryption and signing), MSG (symmetric encryption and HMAC), token renewal, sequence number checks |
| Certificates | Self-signed certificates created automatically (RSA and ECC P-256 / P-384), a `pki/{own,trusted,issuer,rejected}` store with the same layout as the .NET stack, CA chain validation |
| User authentication | Anonymous, UserName (passwords are RSA encrypted, also on None endpoints), X509 certificates (ECC user certificates on ECC endpoints) |
| Address space | The official `Opc.Ua.NodeSet2.xml` (namespace 0) is embedded and loaded; custom NodeSet2 files can be loaded with `LoadNodeSet` |
| Services | GetEndpoints, FindServers, CreateSession / ActivateSession / CloseSession, Browse / BrowseNext, TranslateBrowsePathsToNodeIds, Register/UnregisterNodes, Read, Write (with IndexRange and type checks), Call, all Subscription services (Create / Modify / SetPublishingMode / Publish / Republish / Transfer / Delete), all MonitoredItem services (data change notifications, absolute deadband) |

## Not supported

- Events and alarms (EventFilter), history (HistoryRead/Update), Query, NodeManagement (AddNodes etc.)
- PercentDeadband, SetTriggering, aggregate filters
- UserName authentication on ECC endpoints (the EccEncryptedSecret password format is not implemented, so user name tokens are not offered on ECC endpoints)
- The AesGcm / ChaChaPoly variants of the ECC policies, brainpool, curve25519 / curve448, and the deprecated Basic128Rsa15 / Basic256
- HTTPS / WebSocket transports, PubSub, GDS, reverse connect
- CRL (certificate revocation list) checks

## Comparison with gopcua

[gopcua/opcua](https://github.com/gopcua/opcua) is the most widely used OPC UA library for Go.
gopcua focuses on the client and is used in many production environments; uaserver focuses on the server.

The comparison below is based on reading the source of gopcua's main branch (commit `79fa869`, as of 2026-11-09),
not on the table in gopcua's README (a service that only returns `BadServiceUnsupported` is marked "No").
gopcua is actively developed, so check gopcua itself for its current state.

**Legend**: Yes = supported, No = not supported, Partial = partly supported (see the notes)

### Overview

| | uaserver | gopcua |
|---|---|---|
| Main use | Server | Client (the server is in development) |
| Client | No | Yes (widely used in production) |
| Dependencies | Go standard library only | google/uuid, golang.org/x/exp, golang.org/x/term and others |
| Origin | Port of UA-.NETStandard | Independent implementation |
| Standard address space (namespace 0) | Yes, official NodeSet2 embedded | Yes, official NodeSet2 embedded |
| Loading custom NodeSet2 files | Yes | Yes |
| Interoperability testing | Interop tests against the official .NET client run in CI | — |

### Security (server)

| | uaserver | gopcua server | gopcua client |
|---|---|---|---|
| None | Yes | Yes | Yes |
| Basic128Rsa15 (deprecated) | No | Partial, untested *1 | Yes |
| Basic256 (deprecated) | No | Partial, untested *1 | Yes |
| Basic256Sha256 | Yes | Partial, untested *1 | Yes |
| Aes128_Sha256_RsaOaep | Yes | Partial, untested *1 | Yes |
| Aes256_Sha256_RsaPss | Yes | Partial, untested *1 | Yes |
| ECC_nistP256 / ECC_nistP384 | Yes | No | No |
| Anonymous authentication | Yes | Yes | Yes |
| UserName authentication | Yes, passwords are checked | Partial *2 | Yes |
| X509 user authentication | Yes, signature and trust list are checked | Partial *2 | Yes |
| Client certificate trust list (trusted / rejected) | Yes | No | — |
| Self-signed certificate creation | Yes | No, the library takes a certificate and key (the examples contain generation code) | — |

*1 Marked "Untested" in gopcua's README.
*2 The token types can be offered, but ActivateSession does not check user tokens (passwords or certificates).

### Services (server)

| Service set | Service | uaserver | gopcua server |
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

The same client (gopcua v0.9.1) sent the same operations to uaserver and to the gopcua v0.9.1 server.
Both servers hold the same 1000 Int32 variables in the same namespace.
The benchmark code is in [`bench/`](bench); it is a separate module, so uaserver itself does not depend on gopcua.

Environment: Windows 11 / amd64, Intel Core i7-11800H (16 logical cores), Go 1.25.6, server and client on the same machine (localhost).
Each benchmark was run three times; every result stayed within a few percent, and one run is shown.

| | uaserver | gopcua | Difference |
|---|---|---|---|
| Connect and disconnect (None) | 1.75 ms | 1.91 ms | uaserver about 10% faster |
| Connect and disconnect (Basic256Sha256 / SignAndEncrypt) | 12.0 ms | 11.7 ms | About the same (dominated by RSA) |
| Read 1 node (None) | 72 µs (13,954/s) | 106 µs (9,428/s) | uaserver about 1.5x |
| Read 1 node (Basic256Sha256 / SignAndEncrypt) | 83 µs (12,061/s) | 118 µs (8,469/s) | uaserver about 1.4x |
| Read 1000 nodes in one request (None) | 1.99 ms (500k nodes/s) | 3.73 ms (270k nodes/s) | uaserver about 1.9x |
| Read 1 node, 8 parallel clients (None) | 34,086/s | 23,755/s | uaserver about 1.4x |
| Write 1 node (None) | 72 µs (13,850/s) | 100 µs (9,996/s) | uaserver about 1.4x |
| Browse (folder with 1000 references) | 2.18 ms | 17.6 ms | uaserver about 8x |
| Write to data change notification (a write every 50 ms) | under 1 ms * | 9.4 ms | uaserver notifies as soon as the value changes |
| Write to data change notification (next write right after each notification) | 10.0 ms | 10.0 ms | Same (limited by the 10 ms publishing interval) |
| Memory: Go heap (idle) | 14.4 MB | 22.3 MB | |
| Memory: Go heap (20 connected sessions) | 14.6 MB | 24.2 MB | |

All times are averages per operation, computed from the wall clock time of the whole measurement loop divided by the number of operations.
On Windows, Go's clock resolution is only about 0.1 to 0.5 ms, so timing single fast operations is not reliable.
The times include the client's own processing, so the difference between the servers alone is larger than shown.

\* The notification latency can only be timed one write at a time; the three runs measured 14 to 39 µs. This is below the clock resolution, so it is shown as "under 1 ms".

**Notes on the results**

- **Data change notifications**: when a value changes through `SetValue` or a client Write, uaserver creates the notification right away and sends it as soon as the publishing interval allows. gopcua waits for the next publishing cycle, so it is one publishing interval (10 ms here) late. When values are written back to back, both are limited by the publishing interval the client requested (one message per 10 ms). Variables that return their value from `OnRead` cannot report changes, so uaserver polls them every `Config.MinSamplingInterval` (50 ms by default).
- **The Write comparison favors gopcua**: the gopcua server does not check the type or array shape of written values; uaserver does.
- **Only Basic256Sha256 / SignAndEncrypt is compared with security**: the other combinations are not implemented or not tested in the gopcua server.

**Encoding and decoding**

The `ua` packages of both libraries were compared with `go test -bench` on the same messages.
A test first checks that both produce exactly the same bytes.

| Operation (1000 elements) | uaserver | gopcua | Difference |
|---|---|---|---|
| Encode ReadResponse | 54 µs, 113 KB, 15 allocations | 343 µs, 257 KB, 6,786 allocations | about 6x |
| Decode ReadResponse | 62 µs, 126 KB, 747 allocations | 316 µs, 229 KB, 5,506 allocations | about 5x |
| Encode ReadRequest | 34 µs, 113 KB, 15 allocations | 1,067 µs, 628 KB, 17,792 allocations | about 31x |
| Decode ReadRequest | 48 µs, 94 KB, 1,003 allocations | 990 µs, 503 KB, 11,764 allocations | about 21x |

The main reason is the design: uaserver uses code generated from the schema, while gopcua uses reflection.

**Reproducing**

```sh
cd bench
go run ./cmd/runner           # server comparison (takes a few minutes)
go test -bench . -benchmem    # encoding / decoding comparison
```

Results vary between machines and operating systems; use the ratios rather than the absolute numbers.

### Which one to use

- **To connect to OPC UA servers and read or write values** (a client): use gopcua. uaserver has no client.
- **To build an OPC UA server in Go**: uaserver covers more, including authentication, certificate trust management, method calls and the full set of subscription services.
- **To connect to old devices that only support the deprecated policies (Basic128Rsa15 / Basic256)**: uaserver does not support them.

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
go get github.com/bamchoh/uaserver/server
```

The packages are `github.com/bamchoh/uaserver/server` (the server), `.../ua` (types and encoding) and `.../uasc` (security policies).

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

## Package layout

| Package | Counterpart in the .NET stack |
|---|---|
| `ua` | Built-in types of Opc.Ua.Core, BinaryEncoder/Decoder, generated types (`types_gen.go`, `id/ids_gen.go`, `status_gen.go`) |
| `uacp` | TcpMessageSocket / Hello and Acknowledge handling |
| `uasc` | UaSCBinaryChannel (channel, chunks, tokens) and SecurityPolicies |
| `server` | Opc.Ua.Server (StandardServer, SessionManager, SubscriptionManager, MasterNodeManager, CertificateValidator) |
| `internal/gen` | Code generation from the schema files (`go generate ./ua`) |

## Testing

```sh
go test ./...
```

Interoperability tests with the official .NET client (OPCFoundation.NetStandard.Opc.Ua.Client 2.0.1):

```sh
go run ./cmd/opcuasrv -addr :48400 -url opc.tcp://localhost:48400 -autoaccept
cd tests/interop/dotnet && dotnet run -- opc.tcp://localhost:48400
```

They cover every security policy (including ECC) and mode, anonymous, user name and X509 (RSA and ECC) authentication,
Browse / Translate / Read / Write / Call, reading 4000 nodes at once (multiple chunks), Subscription and Publish, and token renewal (RSA and ECC).
