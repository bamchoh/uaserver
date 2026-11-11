package server_test

import (
	"log"

	"github.com/bamchoh/uastack/server"
	"github.com/bamchoh/uastack/ua"
	"github.com/bamchoh/uastack/uasc"
)

// This example starts a server with a Basic256Sha256 endpoint and one variable.
// Clients subscribed to the variable are notified when SetValue changes it.
func Example() {
	srv, err := server.New(server.Config{
		ApplicationName: "My Server",
		ListenAddr:      ":4840",
		PKIDir:          "pki", // own certificate and trusted clients
		Security: []server.SecurityConfig{{
			PolicyURI: uasc.SecurityPolicyBasic256Sha256,
			Modes:     []ua.MessageSecurityMode{ua.MessageSecurityModeSignAndEncrypt},
		}},
	})
	if err != nil {
		log.Fatal(err)
	}
	as := srv.AddressSpace()
	ns := as.RegisterNamespace("urn:example")
	temp := ua.NewStringNodeId(ns, "Temperature")
	if _, err := as.AddVariable(server.ObjectsFolder, temp, ua.NewQualifiedName(ns, "Temperature"),
		ua.NewVariant(21.5), server.VariableOptions{}); err != nil {
		log.Fatal(err)
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	defer srv.Close()

	as.SetValue(temp, ua.NewVariant(22.0))
}
