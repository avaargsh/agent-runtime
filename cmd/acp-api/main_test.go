package main

import (
	"testing"
)

func TestConfigurationRequiresAuthenticatedControlPlaneAndDatabase(t *testing.T) {
	base := map[string]string{
		"RUNTIME_DATABASE_URL":  "postgres://localhost/runtime",
		"RUNTIME_TLS_CERT":      "server.pem",
		"RUNTIME_TLS_KEY":       "server.key",
		"RUNTIME_CLIENT_CA":     "trusted-acp-ca.pem",
		"RUNTIME_ACP_SPIFFE_ID": "spiffe://agent.example/ns/control/sa/agent-control-panel",
	}
	for _, name := range []string{"RUNTIME_DATABASE_URL", "RUNTIME_TLS_CERT", "RUNTIME_TLS_KEY", "RUNTIME_CLIENT_CA", "RUNTIME_ACP_SPIFFE_ID"} {
		t.Run(name, func(t *testing.T) {
			env := func(key string) string {
				if key == name {
					return ""
				}
				return base[key]
			}
			if _, err := readConfig(env); err == nil {
				t.Fatalf("missing %s accepted", name)
			}
		})
	}
	config, err := readConfig(func(key string) string { return base[key] })
	if err != nil || config.addr != "127.0.0.1:8443" {
		t.Fatalf("bad safe default: %+v %v", config, err)
	}
}

func TestTLSConfigFailsClosedOnMissingCAOrServerKey(t *testing.T) {
	if _, err := loadTLS("missing-cert.pem", "missing-key.pem", "missing-ca.pem"); err == nil {
		t.Fatal("missing server certificate/CA unexpectedly accepted")
	}
}

func TestSafetyAuthorityRequiresSeparateExplicitPeerAndTenant(t *testing.T) {
	env := map[string]string{
		"RUNTIME_DATABASE_URL":  "postgres://localhost/runtime",
		"RUNTIME_TLS_CERT":      "server.pem", "RUNTIME_TLS_KEY": "server.key", "RUNTIME_CLIENT_CA": "trusted-ca.pem",
		"RUNTIME_ACP_SPIFFE_ID": "spiffe://example.org/acp",
	}
	for _, tc := range []struct {
		peer   string
		tenant string
	}{
		{"spiffe://example.org/guard", ""},
		{"", "tenant-1"},
		{"spiffe://example.org/acp", "tenant-1"},
	} {
		env["RUNTIME_SAFETY_SPIFFE_ID"], env["RUNTIME_SAFETY_TENANT"] = tc.peer, tc.tenant
		if _, err := readConfig(func(key string) string { return env[key] }); err == nil {
			t.Fatal("incomplete or conflicting safety delegation accepted")
		}
	}
	env["RUNTIME_SAFETY_SPIFFE_ID"], env["RUNTIME_SAFETY_TENANT"] = "spiffe://example.org/guard", "tenant-1"
	if _, err := readConfig(func(key string) string { return env[key] }); err != nil {
		t.Fatal(err)
	}
}
