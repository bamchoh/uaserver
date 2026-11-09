// Command runner benchmarks the uaserver and gopcua servers with the same
// gopcua client and prints the results as a Markdown table.
//
//	cd bench && go run ./cmd/runner
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bamchoh/uaserver/bench/internal/memstat"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
)

var (
	scale  = flag.Float64("scale", 1, "multiplier for the number of iterations")
	only   = flag.String("only", "", "run only the server with this name (uaserver or gopcua)")
	onlySc = flag.String("scenarios", "", "comma separated scenario keys to run (default: all)")
	cpu    = flag.String("cpu", "", "CPU description to print in the environment section")
	output = flag.String("o", "", "also write the Markdown report to this file")
)

type serverDef struct {
	name string
	pkg  string
	port int
}

var servers = []serverDef{
	{"uaserver", "./cmd/srv-uaserver", 48501},
	{"gopcua", "./cmd/srv-gopcua", 48502},
}

// result is one measured scenario.
type result struct {
	mean        time.Duration // wall clock time of the measured loop / iterations
	median, p99 time.Duration
	perSec      float64 // operations (or nodes) per second, 0 if not applicable
	unit        string  // unit of perSec
	note        string
	err         error
}

type scenario struct {
	key  string
	name string
	run  func(ctx context.Context, env *env) result
}

type env struct {
	endpoint string
	ns       uint16
	certDER  []byte
	key      *rsa.PrivateKey
}

func n(base int) int { return max(1, int(float64(base)**scale)) }

// timerRes is the observed resolution of time.Now (about 0.5 ms on Windows).
var timerRes = measureTimerResolution()

func measureTimerResolution() time.Duration {
	best := time.Hour
	for range 50 {
		t0 := time.Now()
		t1 := time.Now()
		for t1.Equal(t0) {
			t1 = time.Now()
		}
		best = min(best, t1.Sub(t0))
	}
	return best
}

// measure runs op warm times without timing, then iters times, timing each
// call and the whole loop. The mean is taken from the loop's wall clock time,
// which stays accurate even when single calls are shorter than timerRes.
func measure(warm, iters int, op func(i int) error) result {
	for i := range warm {
		if err := op(i); err != nil {
			return result{err: err}
		}
	}
	d := make([]time.Duration, 0, iters)
	start := time.Now()
	for i := range iters {
		t := time.Now()
		if err := op(warm + i); err != nil {
			return result{err: err}
		}
		d = append(d, time.Since(t))
	}
	wall := time.Since(start)
	r := summarize(d)
	r.mean = wall / time.Duration(iters)
	r.perSec = float64(iters) / wall.Seconds()
	return r
}

func main() {
	flag.Parse()
	log.SetFlags(0)
	tmp, err := os.MkdirTemp("", "uabench")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	certDER, key, err := clientCert()
	if err != nil {
		log.Fatal(err)
	}

	scenarios := []scenario{
		{"connect", "接続の確立（None）", scConnect(false)},
		{"connect-sec", "接続の確立（Basic256Sha256 / SignAndEncrypt）", scConnect(true)},
		{"read1", "Read 1 ノード（None）", scRead(1, false)},
		{"read1-sec", "Read 1 ノード（Basic256Sha256 / SignAndEncrypt）", scRead(1, true)},
		{"read1000", "Read 1000 ノードを 1 回で（None）", scRead(memstat.NumVars, false)},
		{"read-parallel", "Read 1 ノード、8 クライアント並列（None）", scParallelRead(8)},
		{"write1", "Write 1 ノード（None）", scWrite},
		{"browse", "Browse 1000 参照のフォルダ（None）", scBrowse},
		{"sub", "Write から データ変化通知まで、連続で書き込み（None）", scSubscription(0)},
		{"sub-sparse", "Write から データ変化通知まで、50 ms おきに書き込み（None）", scSubscription(50 * time.Millisecond)},
	}

	type serverResult struct {
		name               string
		results            map[string]result
		memIdle, memLoaded *memstat.Stats
		err                error
	}
	var all []serverResult
	for _, sd := range servers {
		if *only != "" && sd.name != *only {
			continue
		}
		log.Printf("== %s", sd.name)
		sr := serverResult{name: sd.name, results: map[string]result{}}
		proc, err := startServer(tmp, sd)
		if err != nil {
			sr.err = err
			all = append(all, sr)
			continue
		}
		sr.memIdle, _ = proc.mem()
		e := &env{endpoint: fmt.Sprintf("opc.tcp://localhost:%d", sd.port), certDER: certDER, key: key}
		if err := e.resolveNamespace(); err != nil {
			sr.err = err
		} else {
			for _, sc := range scenarios {
				if *onlySc != "" && !slices.Contains(strings.Split(*onlySc, ","), sc.key) {
					continue
				}
				log.Printf("  %s", sc.key)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				r := sc.run(ctx, e)
				cancel()
				if r.err != nil {
					log.Printf("    error: %v", r.err)
				}
				sr.results[sc.key] = r
			}
		}
		// Memory with a load still attached: 20 connected sessions.
		clients := connectMany(e, 20)
		sr.memLoaded, _ = proc.mem()
		for _, c := range clients {
			_ = c.Close(context.Background())
		}
		proc.stop()
		all = append(all, sr)
	}

	// Report.
	var b strings.Builder
	fmt.Fprintf(&b, "測定環境：%s/%s、CPU %d 論理コア", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	if *cpu != "" {
		fmt.Fprintf(&b, "（%s）", *cpu)
	}
	fmt.Fprintf(&b, "、%s、クライアントは gopcua v0.9.1、サーバーとクライアントは同じマシン（localhost）、時計の分解能 %s\n\n",
		runtime.Version(), fmtDur(timerRes))
	b.WriteString("| 項目 |")
	for _, sr := range all {
		fmt.Fprintf(&b, " %s |", sr.name)
	}
	b.WriteString("\n|---|")
	for range all {
		b.WriteString("---|")
	}
	b.WriteString("\n")
	for _, sc := range scenarios {
		if *onlySc != "" && !slices.Contains(strings.Split(*onlySc, ","), sc.key) {
			continue
		}
		// Percentiles are shown only when every server's median is well above
		// the timer resolution; otherwise single samples are mostly quantization.
		showPct := true
		for _, sr := range all {
			if r := sr.results[sc.key]; sr.err == nil && r.err == nil && r.median < 20*timerRes {
				showPct = false
			}
		}
		fmt.Fprintf(&b, "| %s |", sc.name)
		for _, sr := range all {
			b.WriteString(" " + formatResult(sr.err, sr.results[sc.key], showPct) + " |")
		}
		b.WriteString("\n")
	}
	memRow := func(label string, get func(serverResult) *memstat.Stats) {
		fmt.Fprintf(&b, "| %s |", label)
		for _, sr := range all {
			m := get(sr)
			if m == nil {
				b.WriteString(" — |")
				continue
			}
			fmt.Fprintf(&b, " ヒープ %.1f MB（OS から確保 %.1f MB） |", mb(m.HeapInuse), mb(m.Sys))
		}
		b.WriteString("\n")
	}
	memRow("メモリ（起動直後）", func(s serverResult) *memstat.Stats { return s.memIdle })
	memRow("メモリ（20 セッション接続中）", func(s serverResult) *memstat.Stats { return s.memLoaded })
	fmt.Print(b.String())
	if *output != "" {
		if err := os.WriteFile(*output, []byte(b.String()), 0o644); err != nil {
			log.Fatal(err)
		}
	}
}

func mb(v uint64) float64 { return float64(v) / (1 << 20) }

func formatResult(serverErr error, r result, showPct bool) string {
	if serverErr != nil {
		return "起動失敗"
	}
	if r.err != nil {
		return "失敗（" + shortErr(r.err) + "）"
	}
	s := "平均 " + fmtDur(r.mean)
	if showPct {
		s += fmt.Sprintf("（中央値 %s / p99 %s）", fmtDur(r.median), fmtDur(r.p99))
	}
	if r.perSec > 0 {
		s += fmt.Sprintf("<br>%s %s", fmtRate(r.perSec), r.unit)
	}
	if r.note != "" {
		s += "<br>" + r.note
	}
	return s
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 60 {
		s = s[:60] + "…"
	}
	return strings.ReplaceAll(s, "|", "/")
}

func fmtDur(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%.0f µs", float64(d)/float64(time.Microsecond))
	case d < 10*time.Millisecond:
		return fmt.Sprintf("%.2f ms", float64(d)/float64(time.Millisecond))
	default:
		return fmt.Sprintf("%.1f ms", float64(d)/float64(time.Millisecond))
	}
}

func fmtRate(v float64) string {
	if v >= 10000 {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.1f", v)
}

func summarize(d []time.Duration) result {
	if len(d) == 0 {
		return result{err: errors.New("no samples")}
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return result{median: d[len(d)/2], p99: d[min(len(d)-1, len(d)*99/100)]}
}

// --- server processes ---

type serverProc struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	mems  chan memstat.Stats
}

func startServer(tmp string, sd serverDef) (*serverProc, error) {
	bin := filepath.Join(tmp, sd.name)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, sd.pkg)
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		return nil, fmt.Errorf("build %s: %w", sd.name, err)
	}
	cmd := exec.Command(bin, "-port", fmt.Sprint(sd.port))
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &serverProc{cmd: cmd, stdin: stdin, mems: make(chan memstat.Stats, 4)}
	ready := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "READY":
				close(ready)
			case strings.HasPrefix(line, memstat.Prefix):
				var m memstat.Stats
				if json.Unmarshal([]byte(strings.TrimPrefix(line, memstat.Prefix)), &m) == nil {
					p.mems <- m
				}
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(60 * time.Second):
		p.stop()
		return nil, fmt.Errorf("%s did not start", sd.name)
	}
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", sd.port)); err == nil {
			c.Close()
			return p, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	p.stop()
	return nil, fmt.Errorf("%s is not listening", sd.name)
}

func (p *serverProc) mem() (*memstat.Stats, error) {
	if _, err := io.WriteString(p.stdin, "\n"); err != nil {
		return nil, err
	}
	select {
	case m := <-p.mems:
		return &m, nil
	case <-time.After(10 * time.Second):
		return nil, errors.New("no memory report")
	}
}

func (p *serverProc) stop() {
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
}

// --- client helpers ---

func clientCert() ([]byte, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	u, _ := url.Parse("urn:bench:client")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "bench-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return der, key, err
}

func (e *env) connect(ctx context.Context, secure bool) (*opcua.Client, error) {
	opts := []opcua.Option{opcua.AutoReconnect(false), opcua.RequestTimeout(30 * time.Second)}
	if secure {
		eps, err := opcua.GetEndpoints(ctx, e.endpoint)
		if err != nil {
			return nil, err
		}
		ep, err := opcua.SelectEndpoint(eps, ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt)
		if err != nil {
			return nil, err
		}
		opts = append(opts,
			opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
			opcua.Certificate(e.certDER), opcua.PrivateKey(e.key),
			opcua.ApplicationURI("urn:bench:client"))
	} else {
		opts = append(opts, opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.SecurityPolicy("None"), opcua.AuthAnonymous())
	}
	c, err := opcua.NewClient(e.endpoint, opts...)
	if err != nil {
		return nil, err
	}
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (e *env) resolveNamespace() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := e.connect(ctx, false)
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	nsa, err := c.NamespaceArray(ctx)
	if err != nil {
		return err
	}
	for i, u := range nsa {
		if u == memstat.NamespaceURI {
			e.ns = uint16(i)
			return nil
		}
	}
	return fmt.Errorf("namespace %s not found in %v", memstat.NamespaceURI, nsa)
}

func (e *env) varID(i int) *ua.NodeID { return ua.NewStringNodeID(e.ns, fmt.Sprintf("v%d", i)) }

func connectMany(e *env, count int) []*opcua.Client {
	var out []*opcua.Client
	for i := 0; i < count; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		c, err := e.connect(ctx, false)
		cancel()
		if err == nil {
			out = append(out, c)
		}
	}
	return out
}

func readReq(ids []*ua.NodeID) *ua.ReadRequest {
	rv := make([]*ua.ReadValueID, len(ids))
	for i, nid := range ids {
		rv[i] = &ua.ReadValueID{NodeID: nid, AttributeID: ua.AttributeIDValue}
	}
	return &ua.ReadRequest{NodesToRead: rv, TimestampsToReturn: ua.TimestampsToReturnBoth}
}

func checkRead(resp *ua.ReadResponse, want int) error {
	if len(resp.Results) != want {
		return fmt.Errorf("got %d results", len(resp.Results))
	}
	for _, r := range resp.Results {
		if r.Status != ua.StatusOK {
			return fmt.Errorf("read status %s", r.Status)
		}
	}
	return nil
}

// --- scenarios ---

func scConnect(secure bool) func(context.Context, *env) result {
	return func(ctx context.Context, e *env) result {
		iters := n(20)
		if secure {
			iters = n(10)
		}
		r := measure(2, iters, func(int) error {
			c, err := e.connect(ctx, secure)
			if err != nil {
				return err
			}
			return c.Close(ctx)
		})
		r.perSec = 0
		return r
	}
}

func scRead(count int, secure bool) func(context.Context, *env) result {
	return func(ctx context.Context, e *env) result {
		c, err := e.connect(ctx, secure)
		if err != nil {
			return result{err: err}
		}
		defer c.Close(ctx)
		ids := make([]*ua.NodeID, count)
		for i := range ids {
			ids[i] = e.varID(i)
		}
		iters := n(2000)
		if count > 1 {
			iters = n(200)
		}
		r := measure(iters/10, iters, func(int) error {
			resp, err := c.Read(ctx, readReq(ids))
			if err != nil {
				return err
			}
			return checkRead(resp, count)
		})
		if count == 1 {
			r.unit = "回/秒"
		} else {
			r.perSec, r.unit = r.perSec*float64(count), "ノード/秒"
		}
		return r
	}
}

func scParallelRead(clients int) func(context.Context, *env) result {
	return func(ctx context.Context, e *env) result {
		cs := make([]*opcua.Client, clients)
		for i := range cs {
			c, err := e.connect(ctx, false)
			if err != nil {
				return result{err: err}
			}
			defer c.Close(ctx)
			cs[i] = c
		}
		iters := n(500)
		var mu sync.Mutex
		var all []time.Duration
		var firstErr error
		var wg sync.WaitGroup
		start := time.Now()
		for ci, c := range cs {
			wg.Go(func() {
				var d []time.Duration
				for range iters {
					t := time.Now()
					resp, err := c.Read(ctx, readReq([]*ua.NodeID{e.varID(ci)}))
					if err == nil {
						err = checkRead(resp, 1)
					}
					if err != nil {
						mu.Lock()
						if firstErr == nil {
							firstErr = err
						}
						mu.Unlock()
						return
					}
					d = append(d, time.Since(t))
				}
				mu.Lock()
				all = append(all, d...)
				mu.Unlock()
			})
		}
		wg.Wait()
		wall := time.Since(start)
		if firstErr != nil {
			return result{err: firstErr}
		}
		r := summarize(all)
		// Average latency per call from the wall clock (Little's law).
		r.mean = wall * time.Duration(clients) / time.Duration(len(all))
		r.perSec, r.unit = float64(len(all))/wall.Seconds(), "回/秒（合計）"
		return r
	}
}

func writeReq(nid *ua.NodeID, v int32) *ua.WriteRequest {
	return &ua.WriteRequest{NodesToWrite: []*ua.WriteValue{{
		NodeID: nid, AttributeID: ua.AttributeIDValue,
		Value: &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(v)},
	}}}
}

func scWrite(ctx context.Context, e *env) result {
	c, err := e.connect(ctx, false)
	if err != nil {
		return result{err: err}
	}
	defer c.Close(ctx)
	iters := n(2000)
	r := measure(iters/10, iters, func(i int) error {
		resp, err := c.Write(ctx, writeReq(e.varID(1), int32(i)))
		if err != nil {
			return err
		}
		if len(resp.Results) != 1 || resp.Results[0] != ua.StatusOK {
			return fmt.Errorf("write status %v", resp.Results)
		}
		return nil
	})
	r.unit = "回/秒"
	return r
}

func scBrowse(ctx context.Context, e *env) result {
	c, err := e.connect(ctx, false)
	if err != nil {
		return result{err: err}
	}
	defer c.Close(ctx)
	req := &ua.BrowseRequest{
		View: &ua.ViewDescription{ViewID: ua.NewTwoByteNodeID(0)},
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID:          ua.NewNumericNodeID(e.ns, memstat.FolderID),
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences),
			IncludeSubtypes: true,
			ResultMask:      uint32(ua.BrowseResultMaskAll),
		}},
	}
	refs := 0
	iters := n(200)
	r := measure(iters/10, iters, func(int) error {
		resp, err := c.Browse(ctx, req)
		if err != nil {
			return err
		}
		if len(resp.Results) != 1 || resp.Results[0].StatusCode != ua.StatusOK {
			return errors.New("browse failed")
		}
		refs = len(resp.Results[0].References)
		return nil
	})
	r.perSec = 0
	r.note = fmt.Sprintf("%d 参照", refs)
	return r
}

// scSubscription measures the time from a Write until the data change
// notification arrives. With gap 0 the next value is written right after the
// previous notification, so the publishing interval (10 ms) limits the rate;
// with a larger gap each change can be sent as soon as it happens.
func scSubscription(gap time.Duration) func(context.Context, *env) result {
	return func(ctx context.Context, e *env) result {
		return subscriptionLatency(ctx, e, gap)
	}
}

func subscriptionLatency(ctx context.Context, e *env, gap time.Duration) result {
	c, err := e.connect(ctx, false)
	if err != nil {
		return result{err: err}
	}
	defer c.Close(ctx)
	notify := make(chan *opcua.PublishNotificationData, 64)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 10 * time.Millisecond}, notify)
	if err != nil {
		return result{err: err}
	}
	defer sub.Cancel(ctx)
	nid := e.varID(2)
	mi := opcua.NewMonitoredItemCreateRequestWithDefaults(nid, ua.AttributeIDValue, 42)
	if _, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, mi); err != nil {
		return result{err: err}
	}
	// waitFor waits until a notification with value want (any value if
	// want is -1) arrives.
	waitFor := func(want int32) error {
		timeout := time.After(5 * time.Second)
		for {
			select {
			case nd := <-notify:
				if nd.Error != nil {
					return nd.Error
				}
				if dcn, ok := nd.Value.(*ua.DataChangeNotification); ok {
					for _, it := range dcn.MonitoredItems {
						if v, ok := it.Value.Value.Value().(int32); ok && (want == -1 || v == want) {
							return nil
						}
					}
				}
			case <-timeout:
				return fmt.Errorf("no notification for value %d", want)
			}
		}
	}
	if err := waitFor(-1); err != nil { // initial value
		return result{err: err}
	}
	var d []time.Duration
	for i := range n(100) + 5 {
		if gap > 0 {
			time.Sleep(gap)
		}
		val := int32(100000 + i)
		start := time.Now()
		if _, err := c.Write(ctx, writeReq(nid, val)); err != nil {
			return result{err: err}
		}
		if err := waitFor(val); err != nil {
			return result{err: err}
		}
		if i >= 5 {
			d = append(d, time.Since(start))
		}
	}
	if gap > 0 {
		// The sleeps make a wall clock mean impossible; use the samples.
		r := summarize(d)
		var sum time.Duration
		for _, x := range d {
			sum += x
		}
		r.mean = sum / time.Duration(len(d))
		return r
	}
	r := measure(5, n(100), func(i int) error {
		val := int32(200000 + i)
		if _, err := c.Write(ctx, writeReq(nid, val)); err != nil {
			return err
		}
		return waitFor(val)
	})
	r.perSec = 0
	return r
}
