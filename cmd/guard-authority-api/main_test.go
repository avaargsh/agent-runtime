package main

import "testing"

func TestReadConfigRequiresDedicatedGuardIdentityAndTenant(t *testing.T) {
	values := map[string]string{
		"RUNTIME_GUARD_AUTHORITY_DATABASE_URL":   "postgres://runtime_guard@localhost/runtime",
		"RUNTIME_GUARD_AUTHORITY_TLS_CERT":       "server.pem",
		"RUNTIME_GUARD_AUTHORITY_TLS_KEY":        "server.key",
		"RUNTIME_GUARD_AUTHORITY_CLIENT_CA":      "guard-ca.pem",
		"RUNTIME_GUARD_AUTHORITY_PEER_SPIFFE_ID": "spiffe://example.org/ns/guard/sa/issuer",
		"RUNTIME_GUARD_AUTHORITY_TENANT":         "tenant-1",
	}
	get := func(key string) string { return values[key] }
	cfg, err := readConfig(get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.addr != ":8446" || cfg.peer != values["RUNTIME_GUARD_AUTHORITY_PEER_SPIFFE_ID"] || cfg.tenant != "tenant-1" {
		t.Fatalf("wrong Guard authority config: %+v", cfg)
	}
	delete(values, "RUNTIME_GUARD_AUTHORITY_PEER_SPIFFE_ID")
	if _, err := readConfig(get); err == nil {
		t.Fatal("missing Guard workload identity accepted")
	}
}

func TestReadOnlyPoolConfigEnablesReadOnlyTransactions(t *testing.T) {
	cfg, err := readOnlyPoolConfig("postgres://runtime_guard@localhost/runtime")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] != "on" || cfg.MaxConns != 8 {
		t.Fatalf("database connection is not read-only bounded: params=%v max_conns=%d", cfg.ConnConfig.RuntimeParams, cfg.MaxConns)
	}
}
