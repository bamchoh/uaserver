// Command opcuacli is a small OPC UA command line client built on the
// client package.
//
//	opcuacli [flags] endpoints <url>
//	opcuacli [flags] read      <url> <nodeid>...
//	opcuacli [flags] write     <url> <nodeid> <value>
//	opcuacli [flags] browse    <url> [nodeid]
//	opcuacli [flags] subscribe <url> <nodeid>...
//
// Node ids use the text format, e.g. "i=2258" or "ns=2;s=Demo.Static.Int32".
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/bamchoh/uaserver/client"
	"github.com/bamchoh/uaserver/ua"
	uaid "github.com/bamchoh/uaserver/ua/id"
	"github.com/bamchoh/uaserver/uasc"
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage: opcuacli [flags] <command> <url> [args]

commands:
  endpoints <url>              list the server's endpoints
  read      <url> <nodeid>...  read values
  write     <url> <nodeid> <v> write a value (converted to the node's current type)
  browse    <url> [nodeid]     list the children of a node (default: Objects)
  subscribe <url> <nodeid>...  print value changes until interrupted

flags:
`)
	flag.PrintDefaults()
}

func main() {
	policy := flag.String("policy", "None", "security policy: None, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss, ECC_nistP256, ECC_nistP384, or best")
	mode := flag.String("mode", "", "security mode: Sign or SignAndEncrypt (default SignAndEncrypt for secure policies)")
	user := flag.String("user", "", "user name (default anonymous)")
	password := flag.String("password", "", "password")
	pki := flag.String("pki", "pki-client", "certificate store directory (own certificate, trusted server certificates)")
	autoAccept := flag.Bool("autoaccept", false, "trust every server certificate (testing only)")
	interval := flag.Duration("interval", time.Second, "publishing interval for subscribe")
	timeout := flag.Duration("timeout", 10*time.Second, "request timeout")
	reconnect := flag.Bool("reconnect", false, "reconnect when the connection is lost (useful with subscribe)")
	verbose := flag.Bool("v", false, "log diagnostics")
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, url, rest := args[0], args[1], args[2:]

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if cmd == "endpoints" {
		check(listEndpoints(ctx, url))
		return
	}

	cfg := client.Config{
		ApplicationName:                 "opcuacli",
		PKIDir:                          *pki,
		AutoAcceptUntrustedCertificates: *autoAccept,
		RequestTimeout:                  *timeout,
		AutoReconnect:                   *reconnect,
		OnStateChange: func(s client.ConnState, err error) {
			if s != client.StateClosed {
				fmt.Fprintf(os.Stderr, "connection: %s %v\n", s, err)
			}
		},
	}
	if *verbose {
		cfg.Logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	if *user != "" {
		cfg.Identity = client.UserName(*user, *password)
	}
	switch *policy {
	case "best":
		cfg.SecurityPolicy = ""
	default:
		uri := policyURI(*policy)
		if uri == "" {
			check(fmt.Errorf("unknown security policy %q", *policy))
		}
		cfg.SecurityPolicy = uri
	}
	switch strings.ToLower(*mode) {
	case "":
	case "sign":
		cfg.SecurityMode = ua.MessageSecurityModeSign
	case "signandencrypt":
		cfg.SecurityMode = ua.MessageSecurityModeSignAndEncrypt
	default:
		check(fmt.Errorf("unknown security mode %q", *mode))
	}

	c, err := connect(ctx, url, cfg)
	check(err)
	defer c.Close(context.Background())

	switch cmd {
	case "read":
		err = read(ctx, c, rest)
	case "write":
		err = write(ctx, c, rest)
	case "browse":
		err = browse(ctx, c, rest)
	case "subscribe":
		err = subscribe(ctx, c, rest, *interval)
	default:
		usage()
		os.Exit(2)
	}
	check(err)
}

func check(err error) {
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func policyURI(name string) string {
	for _, uri := range uasc.SupportedPolicies() {
		if strings.EqualFold(uasc.PolicyByURI(uri).Name, name) {
			return uri
		}
	}
	return ""
}

// connect dials the server; an empty policy picks the most secure endpoint.
func connect(ctx context.Context, url string, cfg client.Config) (*client.Client, error) {
	if cfg.SecurityPolicy != "" {
		return client.Dial(ctx, url, cfg)
	}
	eps, err := client.GetEndpoints(ctx, url, cfg.Limits)
	if err != nil {
		return nil, err
	}
	ep, err := client.SelectEndpoint(eps, "", 0)
	if err != nil {
		return nil, err
	}
	return client.DialEndpoint(ctx, url, ep, cfg)
}

func parseNodeIDs(args []string) ([]ua.NodeId, error) {
	if len(args) == 0 {
		return nil, errors.New("no node ids given")
	}
	ids := make([]ua.NodeId, len(args))
	for i, a := range args {
		id, err := ua.ParseNodeId(a)
		if err != nil {
			return nil, fmt.Errorf("node id %q: %w", a, err)
		}
		ids[i] = id
	}
	return ids, nil
}

func listEndpoints(ctx context.Context, url string) error {
	eps, err := client.GetEndpoints(ctx, url, client.Config{}.Limits)
	if err != nil {
		return err
	}
	for _, ep := range eps {
		name := ep.SecurityPolicyUri
		if p := uasc.PolicyByURI(name); p != nil {
			name = p.Name
		}
		var tokens []string
		for _, t := range ep.UserIdentityTokens {
			tokens = append(tokens, t.TokenType.String())
		}
		fmt.Printf("%-24s %-15s level %-3d %s  users: %s\n", name, ep.SecurityMode, ep.SecurityLevel, ep.EndpointUrl,
			strings.Join(tokens, ", "))
	}
	return nil
}

func read(ctx context.Context, c *client.Client, args []string) error {
	ids, err := parseNodeIDs(args)
	if err != nil {
		return err
	}
	vs, err := c.ReadValues(ctx, ids...)
	if err != nil {
		return err
	}
	for i, dv := range vs {
		if dv.Status.IsBad() {
			fmt.Printf("%s: %s\n", ids[i], dv.Status)
			continue
		}
		fmt.Printf("%s: %s (%s)\n", ids[i], dv.Value, dv.Value.Type())
	}
	return nil
}

func write(ctx context.Context, c *client.Client, args []string) error {
	if len(args) != 2 {
		return errors.New("write needs a node id and a value")
	}
	id, err := ua.ParseNodeId(args[0])
	if err != nil {
		return err
	}
	cur, err := c.ReadValue(ctx, id)
	if err != nil {
		return err
	}
	v, err := convert(args[1], cur.Value)
	if err != nil {
		return err
	}
	if err := c.WriteValue(ctx, id, v); err != nil {
		return err
	}
	fmt.Printf("%s = %s\n", id, v)
	return nil
}

// convert parses s as a value of the same scalar type as like.
func convert(s string, like ua.Variant) (ua.Variant, error) {
	if like.IsArray() {
		return ua.Variant{}, errors.New("writing arrays is not supported by opcuacli")
	}
	var v any
	var err error
	switch like.Value().(type) {
	case bool:
		v, err = strconv.ParseBool(s)
	case int8:
		var n int64
		n, err = strconv.ParseInt(s, 0, 8)
		v = int8(n)
	case byte:
		var n uint64
		n, err = strconv.ParseUint(s, 0, 8)
		v = byte(n)
	case int16:
		var n int64
		n, err = strconv.ParseInt(s, 0, 16)
		v = int16(n)
	case uint16:
		var n uint64
		n, err = strconv.ParseUint(s, 0, 16)
		v = uint16(n)
	case int32:
		var n int64
		n, err = strconv.ParseInt(s, 0, 32)
		v = int32(n)
	case uint32:
		var n uint64
		n, err = strconv.ParseUint(s, 0, 32)
		v = uint32(n)
	case int64:
		v, err = strconv.ParseInt(s, 0, 64)
	case uint64:
		v, err = strconv.ParseUint(s, 0, 64)
	case float32:
		var f float64
		f, err = strconv.ParseFloat(s, 32)
		v = float32(f)
	case float64:
		v, err = strconv.ParseFloat(s, 64)
	case string:
		v = s
	case time.Time:
		v, err = time.Parse(time.RFC3339Nano, s)
	case ua.LocalizedText:
		v = ua.NewLocalizedText(s)
	default:
		return ua.Variant{}, fmt.Errorf("writing %s values is not supported by opcuacli", like.Type())
	}
	if err != nil {
		return ua.Variant{}, fmt.Errorf("%q is not a valid %s: %w", s, like.Type(), err)
	}
	return ua.NewVariant(v), nil
}

func browse(ctx context.Context, c *client.Client, args []string) error {
	id := ua.NewNumericNodeId(0, uaid.ObjectsFolder)
	if len(args) > 0 {
		var err error
		if id, err = ua.ParseNodeId(args[0]); err != nil {
			return err
		}
	}
	refs, err := c.BrowseChildren(ctx, id)
	if err != nil {
		return err
	}
	for _, r := range refs {
		fmt.Printf("%-40s %-10s %s\n", r.NodeId.NodeId, r.NodeClass, r.BrowseName)
	}
	return nil
}

func subscribe(ctx context.Context, c *client.Client, args []string, interval time.Duration) error {
	ids, err := parseNodeIDs(args)
	if err != nil {
		return err
	}
	sub, err := c.CreateSubscription(ctx, client.SubscriptionParams{PublishingInterval: interval})
	if err != nil {
		return err
	}
	items, err := sub.MonitorValues(ctx, ids...)
	if err != nil {
		return err
	}
	byHandle := map[uint32]ua.NodeId{}
	for _, it := range items {
		if it.Status.IsBad() {
			fmt.Printf("%s: %s\n", it.NodeID, it.Status)
			continue
		}
		byHandle[it.ClientHandle] = it.NodeID
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case n, ok := <-sub.Notifications():
			if !ok {
				return c.Err()
			}
			if n.Err != nil {
				return n.Err
			}
			for _, dc := range n.DataChanges {
				ts := dc.Value.SourceTimestamp
				if ts.IsZero() {
					ts = n.PublishTime
				}
				fmt.Printf("%s %s: %s\n", ts.Local().Format("15:04:05.000"), byHandle[dc.ClientHandle], dc.Value.Value)
			}
		}
	}
}
