// Command opcuasrv runs a sample OPC UA server with a small demo address space.
package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/bamchoh/uaserver/server"
	"github.com/bamchoh/uaserver/ua"
	uaid "github.com/bamchoh/uaserver/ua/id"
	"github.com/bamchoh/uaserver/uasc"
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
		{PolicyURI: uasc.SecurityPolicyEccNistP256, Modes: both},
		{PolicyURI: uasc.SecurityPolicyEccNistP384, Modes: both},
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
	// addAll adds writable variables to a new folder Demo.<folder>.
	addAll := func(folder string, vars map[string]ua.Variant, opts map[string]server.VariableOptions) error {
		fid := id("Demo." + folder)
		if _, err := as.AddFolder(id("Demo"), fid, qn(folder)); err != nil {
			return err
		}
		for name, v := range vars {
			o, ok := opts[name]
			if !ok {
				o = rw
			}
			if _, err := as.AddVariable(fid, id("Demo."+folder+"."+name), qn(name), v, o); err != nil {
				return fmt.Errorf("%s.%s: %w", folder, name, err)
			}
		}
		return nil
	}
	now := time.Now().Truncate(time.Millisecond)

	// Scalars of every built-in type.
	if err := addAll("Static", map[string]ua.Variant{
		"Boolean": ua.NewVariant(true), "SByte": ua.NewVariant(int8(-8)), "Byte": ua.NewVariant(byte(8)),
		"Int16": ua.NewVariant(int16(-16)), "UInt16": ua.NewVariant(uint16(16)),
		"Int32": ua.NewVariant(int32(-32)), "UInt32": ua.NewVariant(uint32(32)),
		"Int64": ua.NewVariant(int64(-64)), "UInt64": ua.NewVariant(uint64(64)),
		"Float": ua.NewVariant(float32(3.25)), "Double": ua.NewVariant(6.5),
		"String": ua.NewVariant("Hello OPC UA"), "DateTime": ua.NewVariant(now),
		"Guid": ua.NewVariant(ua.NewGuid()), "ByteString": ua.NewVariant([]byte{1, 2, 3, 4}),
		"XmlElement":    ua.NewVariant(ua.XmlElement("<Demo>xml</Demo>")),
		"LocalizedText": ua.NewVariant(ua.NewLocalizedText("こんにちは")),
		"QualifiedName": ua.NewVariant(ua.NewQualifiedName(ns, "Name")),
		"NodeId":        ua.NewVariant(id("Demo")),
		"ExpandedNodeId": ua.NewVariant(ua.ExpandedNodeId{NodeId: ua.NewStringNodeId(0, "Demo"),
			NamespaceURI: "urn:opcuasrv:demo"}),
		"StatusCode": ua.NewVariant(ua.StatusUncertain),
	}, nil); err != nil {
		return err
	}

	// One dimensional arrays of every built-in type. ByteArray is an array of
	// Byte, which is a different type from ByteString.
	if err := addAll("Arrays", map[string]ua.Variant{
		"BooleanArray":    ua.NewVariant([]bool{true, false, true}),
		"SByteArray":      ua.NewVariant([]int8{-128, -1, 0, 1, 127}),
		"ByteArray":       ua.NewByteArrayVariant([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}),
		"Int16Array":      ua.NewVariant([]int16{-32768, 0, 32767}),
		"UInt16Array":     ua.NewVariant([]uint16{0, 1000, 65535}),
		"Int32Array":      ua.NewVariant([]int32{1, 2, 3, 4, 5}),
		"UInt32Array":     ua.NewVariant([]uint32{10, 20, 30, 40}),
		"Int64Array":      ua.NewVariant([]int64{-1 << 40, 0, 1 << 40}),
		"UInt64Array":     ua.NewVariant([]uint64{0, 1 << 32, 1 << 63}),
		"FloatArray":      ua.NewVariant([]float32{0.5, 1.5, 2.5}),
		"DoubleArray":     ua.NewVariant([]float64{1.5, 2.5, 3.5}),
		"StringArray":     ua.NewVariant([]string{"a", "b", "c"}),
		"DateTimeArray":   ua.NewVariant([]time.Time{now.Add(-time.Hour), now, now.Add(time.Hour)}),
		"GuidArray":       ua.NewVariant([]ua.Guid{ua.NewGuid(), ua.NewGuid()}),
		"ByteStringArray": ua.NewVariant([][]byte{{1, 2}, {3, 4, 5}, {}}),
		"LocalizedTextArray": ua.NewVariant([]ua.LocalizedText{
			{Locale: "en", Text: "Hello"}, {Locale: "ja", Text: "こんにちは"}}),
		"QualifiedNameArray": ua.NewVariant([]ua.QualifiedName{ua.NewQualifiedName(ns, "A"), ua.NewQualifiedName(ns, "B")}),
		"NodeIdArray":        ua.NewVariant([]ua.NodeId{server.ObjectsFolder, id("Demo")}),
		"StatusCodeArray":    ua.NewVariant([]ua.StatusCode{ua.StatusGood, ua.StatusUncertain, ua.StatusBadTimeout}),
		"VariantArray":       ua.NewVariant([]ua.Variant{ua.NewVariant(int32(1)), ua.NewVariant("two"), ua.NewVariant(3.0)}),
	}, nil); err != nil {
		return err
	}

	// Multi-dimensional arrays. Elements are stored row-major (the last index
	// changes fastest) and numbered from 0, so element [i][j] of a 3x4
	// matrix is i*4+j.
	seq := func(n int) []int32 {
		a := make([]int32, n)
		for i := range a {
			a[i] = int32(i)
		}
		return a
	}
	bytes := func(n int) []byte {
		a := make([]byte, n)
		for i := range a {
			a[i] = byte(i)
		}
		return a
	}
	matrices := map[string]struct {
		flat any
		dims []int32
	}{
		"ByteMatrix2D":    {bytes(16), []int32{4, 4}},
		"Int32Matrix2D":   {seq(12), []int32{3, 4}},
		"DoubleMatrix2D":  {[]float64{0, 0.5, 1, 1.5, 2, 2.5}, []int32{2, 3}},
		"BooleanMatrix2D": {[]bool{true, false, false, true}, []int32{2, 2}},
		"StringMatrix2D":  {[]string{"r0c0", "r0c1", "r0c2", "r1c0", "r1c1", "r1c2"}, []int32{2, 3}},
		"ByteMatrix3D":    {bytes(12), []int32{2, 2, 3}},
		"Int32Matrix3D":   {seq(24), []int32{2, 3, 4}},
		"FloatMatrix3D":   {[]float32{0, 1, 2, 3, 4, 5, 6, 7}, []int32{2, 2, 2}},
	}
	mvars := map[string]ua.Variant{}
	for name, m := range matrices {
		v, err := ua.NewMatrixVariant(m.flat, m.dims)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		mvars[name] = v
	}
	if err := addAll("Matrices", mvars, nil); err != nil {
		return err
	}

	// Structures (ExtensionObjects) and an enumeration.
	celsius := &ua.EUInformation{
		NamespaceUri: "http://www.opcfoundation.org/UA/units/un/cefact", UnitId: 4408652,
		DisplayName: ua.NewLocalizedText("°C"), Description: ua.NewLocalizedText("degree Celsius"),
	}
	if err := addAll("Structures", map[string]ua.Variant{
		"Range":         ua.NewVariant(&ua.Range{Low: 0, High: 100}),
		"RangeArray":    ua.NewVariant([]ua.Range{{Low: 0, High: 10}, {Low: -50, High: 50}}),
		"EUInformation": ua.NewVariant(celsius),
		"TimeZone":      ua.NewVariant(&ua.TimeZoneDataType{Offset: 540}),
		"NodeClass":     ua.NewVariant(int32(ua.NodeClassObject)),
	}, map[string]server.VariableOptions{
		"NodeClass": {DataType: ua.NewNumericNodeId(0, uaid.NodeClass), AccessLevel: rw.AccessLevel},
	}); err != nil {
		return err
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
