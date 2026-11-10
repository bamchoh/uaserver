// Command srv-gopcua is the gopcua side of the benchmark.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"time"

	"github.com/bamchoh/uastack/bench/internal/memstat"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/ua"
)

type quietLogger struct{}

func (quietLogger) Debug(string, ...any) {}
func (quietLogger) Info(string, ...any)  {}
func (quietLogger) Warn(string, ...any)  {}
func (quietLogger) Error(msg string, args ...any) {
	log.Printf(msg, args...)
}

func main() {
	port := flag.Int("port", 48502, "listen port")
	flag.Parse()

	cert, key, err := selfSigned("urn:bench:gopcua")
	if err != nil {
		log.Fatal(err)
	}
	s := server.New(
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		// gopcua listens on the host of the first endpoint. A wildcard host makes
		// it listen on both IPv4 and IPv6, like the uastack side; with only
		// "localhost" it listens on ::1 alone and IPv4 clients (e.g. UaExpert)
		// are refused, which Windows retries for about 2 s per connection.
		server.EndPoint("[::]", *port),
		server.EndPoint("localhost", *port),
		server.PrivateKey(key),
		server.Certificate(cert),
		server.SetLogger(quietLogger{}),
	)
	ns := server.NewNodeNameSpace(s, memstat.NamespaceURI)
	folder := ns.Objects() // numeric id 85 in the bench namespace, like the uastack side
	root, err := s.Namespace(0)
	if err != nil {
		log.Fatal(err)
	}
	root.Objects().AddRef(folder, id.Organizes, true)
	for i := 0; i < memstat.NumVars; i++ {
		v := ns.AddNewVariableStringNode(fmt.Sprintf("v%d", i), int32(i))
		folder.AddRef(v, id.HasComponent, true)
	}
	if err := s.Start(context.Background()); err != nil {
		log.Fatal(err)
	}
	memstat.Serve()
	fmt.Println("READY")
	select {}
}

func selfSigned(appURI string) ([]byte, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	u, _ := url.Parse(appURI)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "bench-gopcua"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{u},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return der, key, err
}
