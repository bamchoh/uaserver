# opcuasrv

[OPC UA .NET Standard](https://github.com/OPCFoundation/UA-.NETStandard) のサーバー機能を Go に移植したものです。
外部ライブラリには依存せず、標準ライブラリだけで書いています。

## できること

| 分類 | 内容 |
|---|---|
| トランスポート | opc.tcp (UA-CP: Hello/Ack/Error)、チャンク分割（送受信の両方） |
| エンコーディング | UA Binary（25 の組み込み型すべて、構造体 345 種は `Opc.Ua.Types.bsd` から自動生成） |
| セキュリティポリシー | None, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss（それぞれ Sign / SignAndEncrypt） |
| セキュアチャネル | OPN（非対称暗号＋署名）、MSG（対称暗号＋HMAC）、トークンの Renew、シーケンス番号の検査 |
| 証明書 | 自己署名証明書の自動生成、`pki/{own,trusted,issuer,rejected}` ストア（.NET 版と同じ構成）、CA チェーンの検証 |
| ユーザー認証 | Anonymous、UserName（パスワードは RSA で暗号化、None エンドポイントでも暗号化）、X509 証明書 |
| アドレス空間 | 公式 `Opc.Ua.NodeSet2.xml`（名前空間 0）を埋め込んで読み込み。独自の NodeSet2 も `LoadNodeSet` で読み込み可能 |
| サービス | GetEndpoints, FindServers, CreateSession / ActivateSession / CloseSession, Browse / BrowseNext, TranslateBrowsePathsToNodeIds, Register/UnregisterNodes, Read, Write（IndexRange・型チェック付き）, Call, Subscription 系一式（Create / Modify / SetPublishingMode / Publish / Republish / Transfer / Delete）, MonitoredItem 系一式（データ変化通知、絶対値デッドバンド） |

## 対応していないもの

- イベント / アラーム（EventFilter）、履歴（HistoryRead/Update）、Query、NodeManagement（AddNodes など）
- PercentDeadband、SetTriggering、集計（Aggregate）フィルター
- ECC 系のセキュリティポリシー、廃止された Basic128Rsa15 / Basic256
- HTTPS / WebSocket トランスポート、PubSub、GDS、リバースコネクト
- CRL（証明書失効リスト）の検査

## 使い方

```sh
go run ./cmd/opcuasrv -addr :4840
```

主なオプション:

| オプション | 説明 |
|---|---|
| `-addr` | 待ち受けアドレス（既定 `:4840`） |
| `-url` | 公開するエンドポイント URL（既定 `opc.tcp://<ホスト名>:<ポート>`） |
| `-pki` | 証明書ストアのディレクトリ（既定 `pki`） |
| `-users` | `user:password` をカンマ区切りで指定（既定 `user1:password1`） |
| `-autoaccept` | すべてのクライアント証明書を信頼する（テスト用） |
| `-secure-only` | None ポリシーを提供しない |

セキュアな接続をすると、初回はクライアント証明書が `pki/rejected/certs` に保存されて拒否されます。
そのファイルを `pki/trusted/certs` に移すと、再起動なしで接続できるようになります。

### ライブラリとして使う

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
as.SetValue(ua.NewStringNodeId(ns, "Temp"), ua.NewVariant(22.0)) // 購読中のクライアントに通知されます
```

`Node.OnRead` / `Node.OnWrite` で値の読み書きを独自処理にでき、`AddMethod` でメソッドを追加できます。

## 構成

| パッケージ | .NET 版で対応する部分 |
|---|---|
| `ua` | Opc.Ua.Core の組み込み型、BinaryEncoder/Decoder、自動生成の型（`types_gen.go`、`id/ids_gen.go`、`status_gen.go`） |
| `uacp` | TcpMessageSocket / Hello・Ack の処理 |
| `uasc` | UaSCBinaryChannel（チャネル、チャンク、トークン）と SecurityPolicies |
| `server` | Opc.Ua.Server（StandardServer、SessionManager、SubscriptionManager、MasterNodeManager、CertificateValidator） |
| `internal/gen` | スキーマからのコード生成（`go generate ./ua`） |

## テスト

```sh
go test ./...
```

.NET 公式クライアント（OPCFoundation.NetStandard.Opc.Ua.Client 2.0.1）との相互接続テスト:

```sh
go run ./cmd/opcuasrv -addr :48400 -url opc.tcp://localhost:48400 -autoaccept
cd tests/interop/dotnet && dotnet run -- opc.tcp://localhost:48400
```

全ポリシーとモードの組み合わせ、匿名とユーザー名の認証、Browse / Translate / Read / Write / Call、
4000 ノードの一括読み出し（マルチチャンク）、Subscription と Publish、トークンの Renew を確認します。
