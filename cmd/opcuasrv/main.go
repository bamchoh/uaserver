// Command opcuasrv runs a sample OPC UA server with a small demo address space.
package main

import (
	"flag"
	"log"
	"math"
	"os"
	"os/signal"
	"strings"
	"time"

	"opcuasrv/server"
	"opcuasrv/ua"
	"opcuasrv/uasc"
)

func main() {
	addr := flag.String("addr", ":4840", "listen address")
	endpoint := flag.String("url", "", "advertised endpoint URL (default opc.tcp://<hostname>:<port>)")
	pki := flag.String("pki", "pki", "certificate store directory")
	autoAccept := flag.Bool("autoaccept", false, "trust all client certificates (testing only)")
	users := flag.String("users", "user1:password1", "comma separated user:password list for user name login")
	noNone := flag.Bool("secure-only", false, "do not offer the None security policy")
	flag.Parse()

	accounts := map[string]string{}
	for _, up := range strings.Split(*users, ",") {
		if u, p, ok := strings.Cut(up, ":"); ok {
			accounts[u] = p
		}
	}
	both := []ua.MessageSecurityMode{ua.MessageSecurityModeSign, ua.MessageSecurityModeSignAndEncrypt}
	security := []server.SecurityConfig{
		{PolicyURI: uasc.SecurityPolicyBasic256Sha256, Modes: both},
		{PolicyURI: uasc.SecurityPolicyAes128Sha256RsaOaep, Modes: both},
		{PolicyURI: uasc.SecurityPolicyAes256Sha256RsaPss, Modes: both},
	}
	if !*noNone {
		security = append([]server.SecurityConfig{{PolicyURI: uasc.SecurityPolicyNone,
			Modes: []ua.MessageSecurityMode{ua.MessageSecurityModeNone}}}, security...)
	}

	srv, err := server.New(server.Config{
		ApplicationName: "Go OPC UA Sample Server",
		ListenAddr:      *addr,
		EndpointURL:     *endpoint,
		PKIDir:          *pki,
		Security:        security,
		UserTokens:      []server.UserTokenType{server.UserTokenAnonymous, server.UserTokenUserName, server.UserTokenCertificate},
		AuthenticateUser: func(user, password string) bool {
			p, ok := accounts[user]
			return ok && p == password
		},
		AutoAcceptUntrustedCertificates: *autoAccept,
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := buildDemo(srv.AddressSpace()); err != nil {
		log.Fatal(err)
	}

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		log.Print("shutting down")
		srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func buildDemo(as *server.AddressSpace) error {
	ns := as.RegisterNamespace("urn:opcuasrv:demo")
	id := func(s string) ua.NodeId { return ua.NewStringNodeId(ns, s) }
	qn := func(s string) ua.QualifiedName { return ua.NewQualifiedName(ns, s) }
	rw := server.VariableOptions{AccessLevel: server.AccessCurrentRead | server.AccessCurrentWrite}

	if _, err := as.AddFolder(server.ObjectsFolder, id("Demo"), qn("Demo")); err != nil {
		return err
	}
	static := map[string]any{
		"Boolean": true, "SByte": int8(-8), "Byte": byte(8), "Int16": int16(-16), "UInt16": uint16(16),
		"Int32": int32(-32), "UInt32": uint32(32), "Int64": int64(-64), "UInt64": uint64(64),
		"Float": float32(3.25), "Double": 6.5, "String": "Hello OPC UA", "DateTime": time.Now(),
		"Guid": ua.NewGuid(), "ByteString": []byte{1, 2, 3, 4},
		"LocalizedText": ua.NewLocalizedText("こんにちは"), "QualifiedName": ua.NewQualifiedName(ns, "Name"),
		"NodeId": id("Demo"), "Int32Array": []int32{1, 2, 3, 4, 5}, "StringArray": []string{"a", "b", "c"},
		"DoubleArray": []float64{1.5, 2.5, 3.5},
	}
	if _, err := as.AddFolder(id("Demo"), id("Demo.Static"), qn("Static")); err != nil {
		return err
	}
	for name, v := range static {
		if _, err := as.AddVariable(id("Demo.Static"), id("Demo.Static."+name), qn(name), ua.NewVariant(v), rw); err != nil {
			return err
		}
	}

	if _, err := as.AddFolder(id("Demo"), id("Demo.Dynamic"), qn("Dynamic")); err != nil {
		return err
	}
	if _, err := as.AddVariable(id("Demo.Dynamic"), id("Demo.Dynamic.Counter"), qn("Counter"), ua.NewVariant(uint32(0)), server.VariableOptions{}); err != nil {
		return err
	}
	if _, err := as.AddVariable(id("Demo.Dynamic"), id("Demo.Dynamic.Sine"), qn("Sine"), ua.NewVariant(0.0), server.VariableOptions{}); err != nil {
		return err
	}
	start := time.Now()
	n, err := as.AddVariable(id("Demo.Dynamic"), id("Demo.Dynamic.Time"), qn("Time"), ua.NewVariant(time.Now()), server.VariableOptions{})
	if err != nil {
		return err
	}
	n.OnRead = func(server.ReadContext) ua.DataValue {
		now := time.Now()
		return ua.DataValue{Value: ua.NewVariant(now), SourceTimestamp: now, ServerTimestamp: now}
	}
	go func() {
		var counter uint32
		for range time.Tick(500 * time.Millisecond) {
			counter++
			_ = as.SetValue(id("Demo.Dynamic.Counter"), ua.NewVariant(counter))
			t := time.Since(start).Seconds()
			_ = as.SetValue(id("Demo.Dynamic.Sine"), ua.NewVariant(math.Sin(t*2*math.Pi/10)))
		}
	}()

	if _, err := as.AddObject(id("Demo"), id("Demo.Methods"), qn("Methods"), ua.NodeId{}); err != nil {
		return err
	}
	dbl := ua.NewNumericNodeId(0, uint32(ua.TypeDouble))
	_, err = as.AddMethod(id("Demo.Methods"), id("Demo.Methods.Add"), qn("Add"),
		[]server.Argument{{Name: "a", DataType: dbl}, {Name: "b", DataType: dbl}},
		[]server.Argument{{Name: "sum", DataType: dbl}},
		func(_ server.ReadContext, _ ua.NodeId, in []ua.Variant) ([]ua.Variant, ua.StatusCode) {
			a, b := in[0].Value().(float64), in[1].Value().(float64)
			return []ua.Variant{ua.NewVariant(a + b)}, ua.StatusGood
		})
	return err
}
