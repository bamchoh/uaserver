// Command srv-uaserver is the uaserver side of the benchmark.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/bamchoh/uaserver/bench/internal/memstat"
	"github.com/bamchoh/uaserver/server"
	"github.com/bamchoh/uaserver/ua"
	"github.com/bamchoh/uaserver/uasc"
)

func main() {
	port := flag.Int("port", 48501, "listen port")
	pki := flag.String("pki", "", "certificate store (default: a temporary directory)")
	flag.Parse()
	if *pki == "" {
		d, err := os.MkdirTemp("", "bench-uaserver-pki")
		if err != nil {
			log.Fatal(err)
		}
		*pki = d
	}
	srv, err := server.New(server.Config{
		ApplicationName: "bench-uaserver",
		ListenAddr:      fmt.Sprintf(":%d", *port),
		EndpointURL:     fmt.Sprintf("opc.tcp://localhost:%d", *port),
		PKIDir:          *pki,
		Security: []server.SecurityConfig{
			{PolicyURI: uasc.SecurityPolicyNone, Modes: []ua.MessageSecurityMode{ua.MessageSecurityModeNone}},
			{PolicyURI: uasc.SecurityPolicyBasic256Sha256, Modes: []ua.MessageSecurityMode{ua.MessageSecurityModeSignAndEncrypt}},
		},
		AutoAcceptUntrustedCertificates: true,
		Logger:                          log.New(io.Discard, "", 0),
	})
	if err != nil {
		log.Fatal(err)
	}
	as := srv.AddressSpace()
	ns := as.RegisterNamespace(memstat.NamespaceURI)
	folder := ua.NewNumericNodeId(ns, memstat.FolderID)
	if _, err := as.AddFolder(server.ObjectsFolder, folder, ua.NewQualifiedName(ns, "Bench")); err != nil {
		log.Fatal(err)
	}
	rw := server.VariableOptions{AccessLevel: server.AccessCurrentRead | server.AccessCurrentWrite}
	for i := 0; i < memstat.NumVars; i++ {
		name := fmt.Sprintf("v%d", i)
		if _, err := as.AddVariable(folder, ua.NewStringNodeId(ns, name), ua.NewQualifiedName(ns, name),
			ua.NewVariant(int32(i)), rw); err != nil {
			log.Fatal(err)
		}
	}
	memstat.Serve()
	fmt.Println("READY")
	log.Fatal(srv.ListenAndServe())
}
