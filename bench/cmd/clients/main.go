// Command clients benchmarks the uastack client against the gopcua client.
// Both talk to the same server (the uastack benchmark server, started as a
// separate process) and run the same operations; the results are printed as
// a Markdown table.
//
//	cd bench && go run ./cmd/clients
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bamchoh/uastack/bench/internal/memstat"
)

var (
	scale  = flag.Float64("scale", 1, "multiplier for the number of iterations")
	server = flag.String("server", "uastack", "server to run against: uastack or gopcua")
	cpu    = flag.String("cpu", "", "CPU description to print in the environment section")
	output = flag.String("o", "", "also write the Markdown report to this file")
)

// benchClient is the operations measured, implemented for both clients.
type benchClient interface {
	read(ctx context.Context, n int) error // read v0 .. v(n-1)
	write(ctx context.Context, i int, v int32) error
	browse(ctx context.Context) (int, error) // references of the Bench folder
	// subscribe monitors v<i>; wait returns once a notification with the
	// value arrives (any value for -1).
	subscribe(ctx context.Context, i int) (wait func(want int32) error, stop func(), err error)
	close(ctx context.Context)
}

type clientDef struct {
	name    string
	version string
	dial    func(ctx context.Context, e *env, secure bool) (benchClient, error)
}

var clients = []clientDef{
	{"uastack", "this repository", dialUAStack},
	{"gopcua", "v0.9.1", dialGopcua},
}

type env struct {
	endpoint string
	ns       uint16
	certDER  []byte
	key      *rsa.PrivateKey
}

func (e *env) varName(i int) string { return fmt.Sprintf("v%d", i) }

type result struct {
	mean          time.Duration
	perSec        float64
	unit          string
	allocs, bytes float64 // per operation, 0 if not measured
	note          string
	err           error
}

type scenario struct {
	key, name string
	run       func(ctx context.Context, e *env, cd clientDef) result
}

func n(base int) int { return max(1, int(float64(base)**scale)) }

// measure runs op warm times, then iters times; the mean comes from the
// wall clock time of the whole loop, and allocations from the heap counters.
func measure(warm, iters int, op func(i int) error) result {
	for i := range warm {
		if err := op(i); err != nil {
			return result{err: err}
		}
	}
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	start := time.Now()
	for i := range iters {
		if err := op(warm + i); err != nil {
			return result{err: err}
		}
	}
	wall := time.Since(start)
	runtime.ReadMemStats(&m1)
	return result{
		mean:   wall / time.Duration(iters),
		perSec: float64(iters) / wall.Seconds(),
		allocs: float64(m1.Mallocs-m0.Mallocs) / float64(iters),
		bytes:  float64(m1.TotalAlloc-m0.TotalAlloc) / float64(iters),
	}
}

func main() {
	flag.Parse()
	log.SetFlags(0)
	tmp, err := os.MkdirTemp("", "uabench-clients")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmp)
	certDER, key, err := clientCert()
	if err != nil {
		log.Fatal(err)
	}
	pkg, port := "./cmd/srv-uastack", 48511
	if *server == "gopcua" {
		pkg, port = "./cmd/srv-gopcua", 48512
	}
	proc, err := startServer(tmp, pkg, port)
	if err != nil {
		log.Fatal(err)
	}
	defer proc.Process.Kill()
	e := &env{endpoint: fmt.Sprintf("opc.tcp://localhost:%d", port), certDER: certDER, key: key}
	if err := e.resolveNamespace(); err != nil {
		log.Fatal(err)
	}

	scenarios := []scenario{
		{"connect", "接続と切断（None）", scConnect(false)},
		{"connect-sec", "接続と切断（Basic256Sha256 / SignAndEncrypt）", scConnect(true)},
		{"read1", "Read 1 ノード（None）", scRead(1, false)},
		{"read1-sec", "Read 1 ノード（Basic256Sha256 / SignAndEncrypt）", scRead(1, true)},
		{"read1000", "Read 1000 ノードを 1 回で（None）", scRead(memstat.NumVars, false)},
		{"read1000-sec", "Read 1000 ノードを 1 回で（Basic256Sha256 / SignAndEncrypt）", scRead(memstat.NumVars, true)},
		{"read-parallel", "Read 1 ノード、1 クライアントから 8 並列（None）", scParallelRead(8)},
		{"write1", "Write 1 ノード（None）", scWrite},
		{"browse", "Browse 1000 参照のフォルダ（None）", scBrowse},
		{"sub", "Write から データ変化通知まで（None）", scSubscription},
	}
	results := map[string]map[string]result{}
	mem := map[string]float64{}
	for _, cd := range clients {
		log.Printf("== %s client", cd.name)
		results[cd.name] = map[string]result{}
		for _, sc := range scenarios {
			log.Printf("  %s", sc.key)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			r := sc.run(ctx, e, cd)
			cancel()
			if r.err != nil {
				log.Printf("    error: %v", r.err)
			}
			results[cd.name][sc.key] = r
		}
		mem[cd.name] = connectedMemory(e, cd, 20)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "測定環境：%s/%s、CPU %d 論理コア", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	if *cpu != "" {
		fmt.Fprintf(&b, "（%s）", *cpu)
	}
	fmt.Fprintf(&b, "、%s、サーバーは %s（別プロセス、同じマシン）\n\n", runtime.Version(), *server)
	b.WriteString("| 項目 |")
	for _, cd := range clients {
		fmt.Fprintf(&b, " %s クライアント |", cd.name)
	}
	b.WriteString(" 差 |\n|---|")
	for range clients {
		b.WriteString("---|")
	}
	b.WriteString("---|\n")
	for _, sc := range scenarios {
		fmt.Fprintf(&b, "| %s |", sc.name)
		for _, cd := range clients {
			b.WriteString(" " + formatResult(results[cd.name][sc.key]) + " |")
		}
		b.WriteString(" " + ratio(results["uastack"][sc.key], results["gopcua"][sc.key]) + " |\n")
	}
	fmt.Fprintf(&b, "| クライアントのヒープ増分（20 セッション接続中） |")
	for _, cd := range clients {
		fmt.Fprintf(&b, " %.1f MB |", mem[cd.name])
	}
	b.WriteString(" |\n")
	fmt.Print(b.String())
	if *output != "" {
		if err := os.WriteFile(*output, []byte(b.String()), 0o644); err != nil {
			log.Fatal(err)
		}
	}
}

func formatResult(r result) string {
	if r.err != nil {
		s := r.err.Error()
		if len(s) > 60 {
			s = s[:60] + "…"
		}
		return "エラー: " + s
	}
	s := fmtDur(r.mean)
	if r.perSec > 0 {
		unit := r.unit
		if unit == "" {
			unit = "回/秒"
		}
		s += fmt.Sprintf("（%s %s）", fmtRate(r.perSec), unit)
	}
	if r.allocs > 0 {
		s += fmt.Sprintf("、%s 回 / %s の割り当て", fmtRate(r.allocs), fmtBytes(r.bytes))
	}
	if r.note != "" {
		s += "、" + r.note
	}
	return s
}

// ratio describes how the uastack client compares with the gopcua client.
func ratio(a, b result) string {
	if a.err != nil || b.err != nil || a.mean == 0 || b.mean == 0 {
		return "—"
	}
	f := float64(b.mean) / float64(a.mean)
	switch {
	case f >= 1.1:
		return fmt.Sprintf("uastack が約 %.1f 倍速い", f)
	case f <= 1/1.1:
		return fmt.Sprintf("gopcua が約 %.1f 倍速い", 1/f)
	}
	return "ほぼ同じ"
}

func fmtDur(d time.Duration) string {
	switch {
	case d >= time.Second:
		return fmt.Sprintf("%.2f s", d.Seconds())
	case d >= time.Millisecond:
		return fmt.Sprintf("%.2f ms", float64(d)/float64(time.Millisecond))
	}
	return fmt.Sprintf("%.0f µs", float64(d)/float64(time.Microsecond))
}

func fmtRate(v float64) string {
	if v >= 100 {
		s := fmt.Sprintf("%.0f", v)
		// Thousands separators.
		for i := len(s) - 3; i > 0; i -= 3 {
			s = s[:i] + "," + s[i:]
		}
		return s
	}
	return fmt.Sprintf("%.1f", v)
}

func fmtBytes(v float64) string {
	if v >= 1<<20 {
		return fmt.Sprintf("%.1f MB", v/(1<<20))
	}
	if v >= 1<<10 {
		return fmt.Sprintf("%.1f KB", v/(1<<10))
	}
	return fmt.Sprintf("%.0f B", v)
}

// --- scenarios ---

func scConnect(secure bool) func(context.Context, *env, clientDef) result {
	return func(ctx context.Context, e *env, cd clientDef) result {
		count := n(100)
		if secure {
			count = n(30)
		}
		r := measure(2, count, func(int) error {
			c, err := cd.dial(ctx, e, secure)
			if err != nil {
				return err
			}
			c.close(ctx)
			return nil
		})
		r.allocs, r.bytes = 0, 0 // dominated by key generation and certificate parsing
		return r
	}
}

func scRead(nodes int, secure bool) func(context.Context, *env, clientDef) result {
	return func(ctx context.Context, e *env, cd clientDef) result {
		c, err := cd.dial(ctx, e, secure)
		if err != nil {
			return result{err: err}
		}
		defer c.close(ctx)
		iters := n(3000)
		if nodes > 1 {
			iters = n(300)
		}
		r := measure(20, iters, func(int) error { return c.read(ctx, nodes) })
		if nodes > 1 {
			r.perSec *= float64(nodes)
			r.unit = "ノード/秒"
		}
		return r
	}
}

func scParallelRead(workers int) func(context.Context, *env, clientDef) result {
	return func(ctx context.Context, e *env, cd clientDef) result {
		c, err := cd.dial(ctx, e, false)
		if err != nil {
			return result{err: err}
		}
		defer c.close(ctx)
		per := n(2000)
		for range 20 {
			if err := c.read(ctx, 1); err != nil {
				return result{err: err}
			}
		}
		var wg sync.WaitGroup
		errs := make(chan error, workers)
		start := time.Now()
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range per {
					if err := c.read(ctx, 1); err != nil {
						errs <- err
						return
					}
				}
			}()
		}
		wg.Wait()
		wall := time.Since(start)
		close(errs)
		if err := <-errs; err != nil {
			return result{err: err}
		}
		total := workers * per
		return result{mean: wall / time.Duration(total), perSec: float64(total) / wall.Seconds()}
	}
}

func scWrite(ctx context.Context, e *env, cd clientDef) result {
	c, err := cd.dial(ctx, e, false)
	if err != nil {
		return result{err: err}
	}
	defer c.close(ctx)
	return measure(20, n(3000), func(i int) error { return c.write(ctx, 1, int32(i)) })
}

func scBrowse(ctx context.Context, e *env, cd clientDef) result {
	c, err := cd.dial(ctx, e, false)
	if err != nil {
		return result{err: err}
	}
	defer c.close(ctx)
	return measure(3, n(100), func(int) error {
		got, err := c.browse(ctx)
		if err != nil {
			return err
		}
		if got != memstat.NumVars {
			return fmt.Errorf("browse returned %d references, want %d", got, memstat.NumVars)
		}
		return nil
	})
}

// scSubscription measures the time from a Write to the data change
// notification, writing the next value right after each notification.
func scSubscription(ctx context.Context, e *env, cd clientDef) result {
	c, err := cd.dial(ctx, e, false)
	if err != nil {
		return result{err: err}
	}
	defer c.close(ctx)
	wait, stop, err := c.subscribe(ctx, 2)
	if err != nil {
		return result{err: err}
	}
	defer stop()
	if err := wait(-1); err != nil {
		return result{err: err}
	}
	r := measure(5, n(100), func(i int) error {
		v := int32(300000 + i)
		if err := c.write(ctx, 2, v); err != nil {
			return err
		}
		return wait(v)
	})
	r.perSec = 0
	r.note = "送信間隔 10 ms"
	return r
}

// connectedMemory returns the growth of the client's heap (MB) while count
// sessions are connected.
func connectedMemory(e *env, cd clientDef, count int) float64 {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	var cs []benchClient
	for range count {
		c, err := cd.dial(ctx, e, false)
		if err != nil {
			log.Printf("  memory: %v", err)
			break
		}
		cs = append(cs, c)
	}
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	runtime.ReadMemStats(&m1)
	for _, c := range cs {
		c.close(ctx)
	}
	return float64(int64(m1.HeapInuse)-int64(m0.HeapInuse)) / (1 << 20)
}

// --- setup ---

func (e *env) resolveNamespace() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := dialUAStack(ctx, e, false)
	if err != nil {
		return err
	}
	defer c.close(ctx)
	ns, err := c.(*uastackClient).c.NamespaceIndex(ctx, memstat.NamespaceURI)
	if err != nil {
		return err
	}
	e.ns = ns
	return nil
}

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

func startServer(tmp, pkg string, port int) (*exec.Cmd, error) {
	bin := filepath.Join(tmp, filepath.Base(pkg))
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, pkg)
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		return nil, fmt.Errorf("build %s: %w", pkg, err)
	}
	cmd := exec.Command(bin, "-port", fmt.Sprint(port))
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	ready := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stdout)
		once := sync.Once{}
		for sc.Scan() {
			if sc.Text() == "READY" {
				once.Do(func() { close(ready) })
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		return nil, errors.New("the server did not start")
	}
	for range 100 {
		if c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port)); err == nil {
			c.Close()
			return cmd, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	return nil, errors.New("the server is not listening")
}
