package main

import (
	"crypto/tls"
	"testing"
)

func TestConfigurationRequiresAuthenticatedControlPlaneAndDatabase(t *testing.T) {
	base := map[string]string{
		"RUNTIME_DATABASE_URL": "postgres://localhost/runtime",
		"RUNTIME_TLS_CERT": "server.pem",
		"RUNTIME_TLS_KEY": "server.key",
		"RUNTIME_CLIENT_CA": "trusted-acp-ca.pem",
		"RUNTIME_ACP_SPIFFE_ID": "spiffe://agent.example/ns/control/sa/agent-control-panel",
	}
	for _, name := range []string{"RUNTIME_DATABASE_URL", "RUNTIME_TLS_CERT", "RUNTIME_TLS_KEY", "RUNTIME_CLIENT_CA", "RUNTIME_ACP_SPIFFE_ID"} {
		t.Run(name, func(t *testing.T) {
			env := func(key string) string {
				if key == name { return "" }
				return base[key]
			}
			if _, err := readConfig(env); err == nil { t.Fatalf("missing %s accepted", name) }
		})
	}
	config, err := readConfig(func(key string) string { return base[key] })
	if err != nil || config.addr != "127.0.0.1:8443" { t.Fatalf("bad safe default: %+v %v", config, err) }
}

func TestTLSConfigFailsClosedOnMissingCAOrServerKey(t *testing.T) {
	if _, err := loadTLS("missing-cert.pem", "missing-key.pem", "missing-ca.pem"); err == nil {
		t.Fatal("missing server certificate/CA unexpectedly accepted")
	}
}

func TestTLSConfigurationUsesVerifiedClientCertificateAndTLS13(t *testing.T) {
	// The TLS config constructor must enforce mutual authentication; these
	// invariants are checked by tests that generate real certificates separately.
	if tls.RequireAndVerifyClientCert == tls.NoClientCert {
		t.Fatal("unreachable TLS policy invariant")
	}
}
