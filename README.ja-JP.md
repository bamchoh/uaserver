# uaserver

[English](README.md) | 日本語

[OPC UA .NET Standard](https://github.com/OPCFoundation/UA-.NETStandard) のサーバー機能を Go に移植したものです。
エンコーディングとセキュリティのコードを共有するクライアントも入っています。
外部ライブラリには依存せず、標準ライブラリだけで書いています。

## できること

| 分類 | 内容 |
|---|---|
| トランスポート | opc.tcp (UA-CP: Hello/Ack/Error)、チャンク分割（送受信の両方） |
| エンコーディング | UA Binary（25 の組み込み型すべて、構造体 345 種は `Opc.Ua.Types.bsd` から自動生成） |
| セキュリティポリシー | None, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss, ECC_nistP256, ECC_nistP384（それぞれ Sign / SignAndEncrypt） |
| セキュアチャネル | OPN（非対称暗号＋署名）、MSG（対称暗号＋HMAC）、トークンの Renew、シーケンス番号の検査 |
| 証明書 | 自己署名証明書の自動生成（RSA と ECC P-256 / P-384）、`pki/{own,trusted,issuer,rejected}` ストア（.NET 版と同じ構成）、CA チェーンの検証 |
| ユーザー認証 | Anonymous、UserName（パスワードは RSA で暗号化、None エンドポイントでも暗号化。ECC エンドポイントでは EccEncryptedSecret 形式）、X509 証明書（ECC エンドポイントでは ECC のユーザー証明書） |
| アドレス空間 | 公式 `Opc.Ua.NodeSet2.xml`（名前空間 0）を埋め込んで読み込み。独自の NodeSet2 も `LoadNodeSet` で読み込み可能 |
| クライアント | サーバーと同じセキュリティポリシー・モード・ユーザー認証。GetEndpoints, FindServers, Browse / BrowseNext, TranslateBrowsePathsToNodeIds, Register/UnregisterNodes, Read, Write, Call、MonitoredItem 付きのサブスクリプション。トークンの Renew、セッションのキープアライブ、自動再接続。その他のサービスは `Client.Send` で送信可能 |
| サービス | GetEndpoints, FindServers, CreateSession / ActivateSession / CloseSession, Browse / BrowseNext, TranslateBrowsePathsToNodeIds, Register/UnregisterNodes, Read, Write（IndexRange・型チェック付き）, Call, Subscription 系一式（Create / Modify / SetPublishingMode / Publish / Republish / Transfer / Delete）, MonitoredItem 系一式（データ変化通知、絶対値デッドバンド） |

## 対応していないもの

- イベント / アラーム（EventFilter）、履歴（HistoryRead/Update）、Query、NodeManagement（AddNodes など）
- PercentDeadband、SetTriggering、集計（Aggregate）フィルター
- ECC の AesGcm / ChaChaPoly 版、brainpool、curve25519 / curve448、廃止された Basic128Rsa15 / Basic256
- HTTPS / WebSocket トランスポート、PubSub、GDS、リバースコネクト
- CRL（証明書失効リスト）の検査

## gopcua との比較

Go の OPC UA ライブラリとしては [gopcua/opcua](https://github.com/gopcua/opcua) が広く使われています。
gopcua はクライアントが中心で、多くの本番環境で使われています。uaserver はサーバーが中心で、クライアントは新しく追加したものです。

以下は gopcua の main ブランチ（コミット `79fa869`、2026-11-09 時点）のソースを読んで比較したものです。
gopcua の README の表ではなく、コードの実装状況を基準にしています（`BadServiceUnsupported` を返すだけのサービスは「×」）。
gopcua は活発に開発されているので、最新の状況は gopcua 側で確認してください。

**凡例**：○ 対応　× 非対応　△ 一部対応（備考を参照）

### 全体

| 項目 | uaserver | gopcua |
|---|---|---|
| 主な用途 | サーバー | クライアント（サーバーは開発中） |
| クライアント | ○（新規。[クライアント](#クライアント) を参照） | ○（本番での利用実績が多い） |
| 依存ライブラリ | Go 標準ライブラリのみ | google/uuid、golang.org/x/exp、golang.org/x/term など |
| 成り立ち | UA-.NETStandard の移植 | 独自実装 |
| 標準アドレス空間（名前空間 0） | ○ 公式 NodeSet2 を埋め込み | ○ 公式 NodeSet2 を埋め込み |
| 独自 NodeSet2 の読み込み | ○ | ○ |
| 相互接続の検証 | サーバー：.NET 公式クライアントとの相互接続テストを CI で実行。クライアント：.NET 公式サーバーとの相互接続テストを CI で実行。gopcua サーバーとも手動で確認 | — |

### セキュリティ

| 項目 | uaserver サーバー | gopcua サーバー | uaserver クライアント | gopcua クライアント |
|---|---|---|---|---|
| None | ○ | ○ | ○ | ○ |
| Basic128Rsa15（廃止） | × | △ 未検証 ※1 | × | ○ |
| Basic256（廃止） | × | △ 未検証 ※1 | × | ○ |
| Basic256Sha256 | ○ | △ 未検証 ※1 | ○ | ○ |
| Aes128_Sha256_RsaOaep | ○ | △ 未検証 ※1 | ○ | ○ |
| Aes256_Sha256_RsaPss | ○ | △ 未検証 ※1 | ○ | ○ |
| ECC_nistP256 / ECC_nistP384 | ○ | × | ○ | × |
| Anonymous 認証 | ○ | ○ | ○ | ○ |
| UserName 認証 | ○ パスワードを検証 | △ ※2 | ○ | ○ |
| X509 ユーザー認証 | ○ 署名と信頼リストを検証 | △ ※2 | ○ | ○ |
| 相手の証明書の信頼リスト（trusted / rejected） | ○ | × | ○ | × ※3 |
| 自己署名証明書の自動生成 | ○ | × ライブラリは証明書と鍵を受け取る（生成コードはサンプルにあり） | ○ | × |

※1 gopcua の README で「Untested」とされているもの。
※2 ポリシーとして提示できますが、ActivateSession でユーザートークン（パスワードや証明書）を検証していません。
※3 アプリケーションが渡した証明書プールでサーバー証明書を検証できます。

### サービス（サーバー）

| サービスセット | サービス | uaserver | gopcua サーバー |
|---|---|---|---|
| Discovery | FindServers / GetEndpoints | ○ | ○ |
| | FindServersOnNetwork | △ 空の一覧を返す | × |
| | RegisterServer / RegisterServer2 | × | × |
| Session | CreateSession / ActivateSession / CloseSession | ○ | ○ |
| | Cancel | △ 応答のみ（取り消しはしない） | × |
| View | Browse / BrowseNext | ○ | ○ |
| | TranslateBrowsePathsToNodeIds | ○ | × |
| | RegisterNodes / UnregisterNodes | ○ | ○ |
| Attribute | Read / Write | ○ | ○ |
| | HistoryRead / HistoryUpdate | × | × |
| Method | Call | ○ | × |
| MonitoredItem | CreateMonitoredItems / DeleteMonitoredItems / SetMonitoringMode | ○ | ○ |
| | ModifyMonitoredItems | ○ | × |
| | SetTriggering | × | × |
| Subscription | CreateSubscription / DeleteSubscriptions / Publish | ○ | ○ |
| | ModifySubscription / SetPublishingMode | ○ | × |
| | Republish / TransferSubscriptions | ○ | × |
| NodeManagement | AddNodes など | × | × |
| Query | QueryFirst / QueryNext | × | × |

### パフォーマンス

同じクライアント（gopcua v0.9.1）から、uaserver と gopcua v0.9.1 のサーバーに同じ操作を投げて測りました。
両サーバーには、同じ名前空間に同じ 1000 個の Int32 変数を置いています。
測定コードは [`bench/`](bench) にあり、本体とは別のモジュールなので、uaserver 本体は gopcua に依存しません。

測定環境：Windows 11 / amd64、Intel Core i7-11800H（16 論理コア）、Go 1.25.6、サーバーとクライアントは同じマシン（localhost）。
3 回測り、どの項目も数 % 以内に収まったので、そのうち 1 回分を載せています。

| 項目 | uaserver | gopcua | 差 |
|---|---|---|---|
| 接続の確立と切断（None） | 1.75 ms | 1.91 ms | uaserver が約 10% 速い |
| 接続の確立と切断（Basic256Sha256 / SignAndEncrypt） | 12.0 ms | 11.7 ms | ほぼ同じ（RSA の処理が大半） |
| Read 1 ノード（None） | 72 µs（13,954 回/秒） | 106 µs（9,428 回/秒） | uaserver が約 1.5 倍 |
| Read 1 ノード（Basic256Sha256 / SignAndEncrypt） | 83 µs（12,061 回/秒） | 118 µs（8,469 回/秒） | uaserver が約 1.4 倍 |
| Read 1000 ノードを 1 回で（None） | 1.99 ms（50 万ノード/秒） | 3.73 ms（27 万ノード/秒） | uaserver が約 1.9 倍 |
| Read 1 ノード、8 クライアント並列（None） | 34,086 回/秒 | 23,755 回/秒 | uaserver が約 1.4 倍 |
| Write 1 ノード（None） | 72 µs（13,850 回/秒） | 100 µs（9,996 回/秒） | uaserver が約 1.4 倍 |
| Browse（1000 参照のフォルダ） | 2.18 ms | 17.6 ms | uaserver が約 8 倍 |
| Write してからデータ変化通知が届くまで（50 ms おきに書き込み） | 1 ms 未満 ※ | 9.4 ms | uaserver は変化した瞬間に通知 |
| Write してからデータ変化通知が届くまで（通知を受けたらすぐ次を書き込み） | 10.0 ms | 10.0 ms | 同じ（送信間隔 10 ms の上限） |
| メモリ：Go ヒープ（起動直後） | 14.4 MB | 22.3 MB | |
| メモリ：Go ヒープ（20 セッション接続中） | 14.6 MB | 24.2 MB | |

時間はすべて 1 回あたりの平均で、測定ループ全体の経過時間を回数で割って求めています。
Windows では Go の時計の分解能が 0.1〜0.5 ms 程度しかなく、1 回ずつ測った値は速い操作では当てにならないためです。
クライアントの処理時間も含むので、サーバー単体の差はこの表より大きくなります。

※ 通知の待ち時間は書き込みの合間に 1 回ずつ測るしかなく、3 回の測定で 14〜39 µs でした。時計の分解能より短いので「1 ms 未満」と表記しています。

**結果を読むときの注意**

- **データ変化通知**：uaserver は、`SetValue` やクライアントの Write で値が変わると、その場で通知を作り、送信間隔（Publishing Interval）を守れる範囲ですぐ送ります。gopcua は次の送信周期を待って送るので、送信間隔ぶん（ここでは 10 ms）遅れます。値を立て続けに書き込む場合は、どちらもクライアントが要求した送信間隔（10 ms に 1 通）が上限になります。`OnRead` で値を返す変数は変化を検知できないので、uaserver は `Config.MinSamplingInterval`（既定 50 ms）ごとに見回って通知します。
- **Write の比較は gopcua に有利**：gopcua のサーバーは、書き込む値の型や配列の形を検査しません。uaserver は検査しています。
- **暗号化ありの比較は Basic256Sha256 / SignAndEncrypt だけ**：gopcua のサーバーでは、ほかの組み合わせが未実装または未検証のためです。

**エンコード / デコード**

両ライブラリの `ua` パッケージで、同じメッセージを変換する速さを `go test -bench` で比べました。
まず、両者がまったく同じバイト列を出力することをテストで確認しています。

| 処理（1000 要素） | uaserver | gopcua | 差 |
|---|---|---|---|
| ReadResponse のエンコード | 54 µs、113 KB、15 回の割り当て | 343 µs、257 KB、6,786 回 | 約 6 倍 |
| ReadResponse のデコード | 62 µs、126 KB、747 回 | 316 µs、229 KB、5,506 回 | 約 5 倍 |
| ReadRequest のエンコード | 34 µs、113 KB、15 回 | 1,067 µs、628 KB、17,792 回 | 約 31 倍 |
| ReadRequest のデコード | 48 µs、94 KB、1,003 回 | 990 µs、503 KB、11,764 回 | 約 21 倍 |

差の主な理由は作りの違いです。uaserver はスキーマから生成した専用のコードで変換し、gopcua はリフレクションで汎用的に変換しています。

### クライアントの性能

uaserver のクライアントと gopcua v0.9.1 のクライアントで、同じサーバー（別プロセスで動かした uaserver のベンチマーク用サーバー）に同じ操作をして測りました。
コードは [`bench/cmd/clients`](bench/cmd/clients) にあります。測定環境は上と同じで、3 回ずつ測ったうちの 1 回を載せています。

| 項目 | uaserver クライアント | gopcua クライアント | 差 |
|---|---|---|---|
| 接続と切断（None） | 1.53 ms | 1.78 ms | uaserver が約 1.2 倍 ※ |
| 接続と切断（Basic256Sha256 / SignAndEncrypt） | 10.9 ms | 11.4 ms | ほぼ同じ（RSA の処理が大半） |
| Read 1 ノード（None） | 49 µs、割り当て 15 回 / 2.2 KB | 73 µs、割り当て 131 回 / 68 KB | uaserver が約 1.5 倍 |
| Read 1 ノード（Basic256Sha256 / SignAndEncrypt） | 54 µs、割り当て 32 回 / 5.6 KB | 80 µs、割り当て 151 回 / 72 KB | uaserver が約 1.5 倍 |
| Read 1000 ノードを 1 回で（None） | 497 µs（200 万ノード/秒）、割り当て 782 回 / 581 KB | 1.92 ms（52 万ノード/秒）、割り当て 26,370 回 / 1.1 MB | uaserver が約 3.9 倍 |
| Read 1000 ノードを 1 回で（Basic256Sha256 / SignAndEncrypt） | 630 µs | 2.06 ms | uaserver が約 3.3 倍 |
| Read 1 ノード、1 クライアントから 8 並列（None） | 73,705 回/秒 | 23,417 回/秒 | uaserver が約 3.1 倍 |
| Write 1 ノード（None） | 46 µs、割り当て 17 回 / 2.1 KB | 73 µs、割り当て 121 回 / 68 KB | uaserver が約 1.6 倍 |
| Browse（1000 参照のフォルダ） | 525 µs | 2.19 ms | uaserver が約 4.2 倍 |
| Write からデータ変化通知まで | 10.0 ms | 10.0 ms | 同じ（10 ms の送信間隔が上限） |
| 20 セッション接続中のクライアントのヒープ増分 | 1.2 MB | 5.5 MB | |

割り当ては、クライアントのプロセスでの 1 操作あたりの値です。
サーバーを gopcua に替えた場合は、1 ノードの Read / Write で約 1.3 倍、1000 ノードで約 1.7 倍でした。その場合は時間の大半がサーバー側になります。

※ 3 回のうち 1 回だけ uaserver クライアントが 4.6 ms になりました。ほかの 2 回は 1.53 ms と 1.54 ms です。
uaserver クライアントは None ポリシーでは GetEndpoints を省き、CreateSession の応答からエンドポイントを取ります。

**再現方法**

```sh
cd bench
go run ./cmd/runner           # サーバー同士の比較（数分かかります）
go run ./cmd/clients          # クライアント同士の比較（-server gopcua で gopcua のサーバーを使用）
go test -bench . -benchmem    # エンコード / デコードの比較
```

結果はマシンや OS で変わります。数字そのものより、両者の比を目安にしてください。

### どちらを選ぶか

- **OPC UA サーバーに接続して値を読み書きしたい**（クライアント）：実績があり、廃止されたポリシーにも対応している gopcua が無難です。
  uaserver のクライアントは新しいものですが、ECC ポリシー、サーバー証明書の信頼リスト、順序どおりの通知配信に対応しており、
  速度と割り当て量でも上回っています（[クライアントの性能](#クライアントの性能) を参照）。
- **Go で OPC UA サーバーを作りたい**：uaserver のほうが、認証、証明書の信頼管理、メソッド呼び出し、サブスクリプション系のサービスまで揃っています。
- **廃止されたポリシー（Basic128Rsa15 / Basic256）しか使えない古い機器とつなぎたい**：uaserver は非対応です。

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

### デモのアドレス空間

`Objects/Demo` 以下に、動作確認用の変数があります（名前空間 `urn:opcuasrv:demo`、NodeId は `s=Demo.<フォルダ>.<名前>`）。
Dynamic と Methods 以外の変数は書き込みもできます。

| フォルダ | 内容 |
|---|---|
| `Static` | 全組み込み型のスカラー（Boolean〜UInt64、Float、Double、String、DateTime、Guid、ByteString、XmlElement、LocalizedText、QualifiedName、NodeId、ExpandedNodeId、StatusCode） |
| `Arrays` | 全組み込み型の 1 次元配列。`ByteArray` は ByteString ではなく Byte の配列 |
| `Matrices` | 2 次元配列（Byte 4×4、Int32 3×4、Double 2×3、Boolean 2×2、String 2×3）と 3 次元配列（Byte 2×2×3、Int32 2×3×4、Float 2×2×2） |
| `Structures` | 構造体（Range、Range の配列、EUInformation、TimeZoneDataType）と列挙型（NodeClass） |
| `Dynamic` | 0.5 秒ごとに変わる Counter と Sine、読むたびに現在時刻を返す Time |
| `Methods` | `Add(a, b)` メソッド |

多次元配列の要素は行優先（最後の添字が最も速く変わる）で 0 から番号を振っているので、3×4 の行列の `[i][j]` は `i*4+j` です。
書き込める行列の大きさは ArrayDimensions（宣言時の大きさ）以下です。

### ライブラリとして使う

```sh
go get github.com/bamchoh/uaserver/server
```

パッケージは `github.com/bamchoh/uaserver/server`（サーバー）、`.../ua`（型とエンコーディング）、`.../uasc`（セキュリティポリシー）です。

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

## クライアント

`cmd/opcuacli` は小さなコマンドラインクライアントです。

```sh
go run ./cmd/opcuacli endpoints opc.tcp://localhost:4840
go run ./cmd/opcuacli browse    opc.tcp://localhost:4840 "ns=2;s=Demo"
go run ./cmd/opcuacli -policy Basic256Sha256 -user user1 -password password1 \
    read opc.tcp://localhost:4840 "ns=2;s=Demo.Static.Int32"
go run ./cmd/opcuacli write     opc.tcp://localhost:4840 "ns=2;s=Demo.Static.Int32" 42
go run ./cmd/opcuacli subscribe opc.tcp://localhost:4840 "ns=2;s=Demo.Dynamic.Counter"
```

`-policy best` で最も安全なエンドポイントを選び、`-mode Sign` で署名のみにします（既定は SignAndEncrypt）。
セキュアなポリシーでは、初回はサーバー証明書が `pki-client/rejected/certs` に保存されて接続に失敗します。
`pki-client/trusted/certs` に移すとサーバーを信頼します（テスト用には `-autoaccept`）。
クライアント証明書は `pki-client/own` に作られるので、サーバー側でも同じように信頼してください。

### クライアントライブラリの使い方

```go
c, err := client.Dial(ctx, "opc.tcp://localhost:4840", client.Config{
    SecurityPolicy: uasc.SecurityPolicyBasic256Sha256, // 既定は None
    PKIDir:         "pki-client",                      // 自分の証明書と信頼するサーバー
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
for n := range sub.Notifications() { // シーケンス番号順に届く
    for _, dc := range n.DataChanges {
        fmt.Println(dc.ClientHandle, dc.Value.Value)
    }
}
```

- エラーは OPC UA のステータスコードを包んでいます。サービスの結果と、`ReadValue`・`WriteValue`・`CallMethod` の個々の操作の結果は `errors.Is(err, ua.StatusBadNodeIdUnknown)` で判定できます。
- `Read`・`Write`・`Browse`・`Call` などサービス名のメソッドはリクエストをそのまま受け取ります。`Client.Send` で任意のリクエストを送れます。
- `client.X509(cert, key)` でユーザー証明書でログインします。エンドポイントを明示的に選ぶには `GetEndpoints`・`SelectEndpoint`・`DialEndpoint` を使います。
- `PKIDir` を指定しないとクライアント証明書はメモリ上に作られ、サーバー証明書は `VerifyServerCertificate` か `AutoAcceptUntrustedCertificates` で受け入れる必要があります。
- アイドル中もセッションを維持し、セキュリティトークンは期限前に更新します。
- `AutoReconnect` を指定すると、接続が切れたときに間隔を延ばしながら再接続します。新しいセキュアチャネルでセッションを Activate し、切れたチャネルで送られた通知は Republish で取り直します。
  サーバーがセッションを破棄していた場合は新しいセッションを作り、サブスクリプションを移すか、同じ監視項目とクライアントハンドルで作り直します。
  再接続中に出したリクエストは、接続が戻るかコンテキストが終わるまで待ちます。切れたときに送信中だったリクエストは失敗し、再送はしません。
  状態の変化（`StateConnected`、`StateReconnecting`、`StateClosed`）は `OnStateChange` で受け取れます。
- `AutoReconnect` を指定しない場合は、接続が切れると `Done()` が閉じられ、各サブスクリプションのチャネルには `Err` 付きの通知が届いてから閉じられます。

## 構成

| パッケージ | .NET 版で対応する部分 |
|---|---|
| `ua` | Opc.Ua.Core の組み込み型、BinaryEncoder/Decoder、自動生成の型（`types_gen.go`、`id/ids_gen.go`、`status_gen.go`） |
| `uacp` | TcpMessageSocket / Hello・Ack の処理（サーバー側とクライアント側） |
| `uasc` | UaSCBinaryChannel（チャネル、チャンク、トークン）と SecurityPolicies（サーバー側とクライアント側） |
| `uacert` | CertificateValidator、CertificateFactory、ディレクトリ形式の証明書ストア |
| `server` | Opc.Ua.Server（StandardServer、SessionManager、SubscriptionManager、MasterNodeManager） |
| `client` | Opc.Ua.Client（Session、Subscription）。移植ではなく Go 向けに書いたもの |
| `internal/gen` | スキーマからのコード生成（`go generate ./ua`） |

## テスト

```sh
go test ./...
```

クライアントのテストでは、TCP でクライアントをサーバーにつなぎ、すべてのエンドポイント（各ポリシーとモード）で匿名・ユーザー名・X509 の認証を確認します。
継続ポイント付きの Browse、マルチチャンクのメッセージ、サブスクリプション、トークンの Renew、セッションのキープアライブ、証明書の信頼も確認します。

.NET 公式クライアント（OPCFoundation.NetStandard.Opc.Ua.Client 2.0.1）との相互接続テスト:

```sh
go run ./cmd/opcuasrv -addr :48400 -url opc.tcp://localhost:48400 -autoaccept
cd tests/interop/dotnet && dotnet run -- opc.tcp://localhost:48400
```

全ポリシー（ECC を含む）とモードの組み合わせ、匿名・ユーザー名・X509 証明書（RSA と ECC）の認証、Browse / Translate / Read / Write / Call、
4000 ノードの一括読み出し（マルチチャンク）、Subscription と Publish、トークンの Renew（RSA と ECC）を確認します。

.NET 公式スタック（OPCFoundation.NetStandard.Opc.Ua.Server 2.0.1）で作ったサーバーとクライアントの相互接続テスト:

```sh
cd tests/interop/dotnet-server && dotnet run -- 48600      # 待ち受けを始めると READY と表示
go run ./tests/interop/goclient opc.tcp://localhost:48600   # リポジトリのルートで実行
```

すべてのエンドポイント（各ポリシーとモード、ECC を含む）に、匿名・ユーザー名（パスワード誤りを含む）・X509（RSA と ECC）でつなぎ、
それぞれで Read・Browse・Write とデータ変化通知を確認します。どちらの相互接続テストも CI で実行します。
