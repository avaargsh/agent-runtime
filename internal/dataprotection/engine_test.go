package dataprotection

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fakeDetector struct {
	spans []Span
	err   error
}

func (d fakeDetector) Detect(context.Context, []byte) ([]Span, error) {
	return append([]Span(nil), d.spans...), d.err
}

type vaultEntry struct {
	dataType DataType
	value    []byte
}

type fakeVault struct {
	entries map[string]vaultEntry
	putErr  error
	getErr  error
}

func newFakeVault() *fakeVault {
	return &fakeVault{entries: make(map[string]vaultEntry)}
}

func vaultKey(scope Scope, tokenID string) string {
	return scope.TenantID + "\x00" + scope.RunID + "\x00" + tokenID
}

func (v *fakeVault) Put(_ context.Context, scope Scope, tokenID string, dataType DataType, value []byte) error {
	if v.putErr != nil {
		return v.putErr
	}
	v.entries[vaultKey(scope, tokenID)] = vaultEntry{
		dataType: dataType,
		value:    bytes.Clone(value),
	}
	return nil
}

func (v *fakeVault) Get(_ context.Context, scope Scope, tokenID string) (DataType, []byte, bool, error) {
	if v.getErr != nil {
		return "", nil, false, v.getErr
	}
	entry, ok := v.entries[vaultKey(scope, tokenID)]
	if !ok {
		return "", nil, false, nil
	}
	return entry.dataType, bytes.Clone(entry.value), true, nil
}

type fakeRehydrationAuthorizer struct {
	err error
}

func (a fakeRehydrationAuthorizer) Authorize(context.Context, Scope, DataType, string, string) error {
	return a.err
}

func spanFor(t *testing.T, payload, value string, dataType DataType) Span {
	t.Helper()
	start := bytes.Index([]byte(payload), []byte(value))
	if start < 0 {
		t.Fatalf("value %q not found in payload %q", value, payload)
	}
	return Span{Start: start, End: start + len(value), Type: dataType}
}

func newTestEngine(t *testing.T, detector Detector, vault Vault, authorizer RehydrationAuthorizer) *Engine {
	t.Helper()
	engine, err := NewEngine(detector, vault, authorizer)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return engine
}

func TestProtectOutboundTokenizesPIIAndRedactsCredentials(t *testing.T) {
	ctx := context.Background()
	payload := "Contact Alice at alice@example.com. Token=sk_live_fakecredential"
	vault := newFakeVault()
	detector := fakeDetector{spans: []Span{
		spanFor(t, payload, "Alice", DataTypePerson),
		spanFor(t, payload, "alice@example.com", DataTypeEmail),
		spanFor(t, payload, "sk_live_fakecredential", DataTypeAPIKey),
	}}
	engine := newTestEngine(t, detector, vault, fakeRehydrationAuthorizer{})
	engine.random = bytes.NewReader([]byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	})

	protected, err := engine.ProtectOutbound(ctx, Scope{TenantID: "tenant-1", RunID: "run-1"}, "model-provider", []byte(payload))
	if err != nil {
		t.Fatalf("ProtectOutbound() error = %v", err)
	}
	got := string(protected)
	if strings.Contains(got, "Alice") || strings.Contains(got, "alice@example.com") || strings.Contains(got, "sk_live_fakecredential") {
		t.Fatalf("protected payload contains original sensitive data: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:API_KEY]") {
		t.Fatalf("credential was not irreversibly redacted: %q", got)
	}
	if len(vault.entries) != 2 {
		t.Fatalf("Vault entries = %d, want 2 reversible PII entries", len(vault.entries))
	}
	if strings.Contains(got, "sk_live_fakecredential") {
		t.Fatal("credential must never be reversibly tokenized")
	}

	restored, err := engine.RestoreInbound(
		ctx,
		Scope{TenantID: "tenant-1", RunID: "run-1"},
		"user-ui",
		"display",
		protected,
	)
	if err != nil {
		t.Fatalf("RestoreInbound() error = %v", err)
	}
	if got := string(restored); got != payload[:strings.Index(payload, "sk_live_fakecredential")]+"[REDACTED:API_KEY]" {
		t.Fatalf("restored payload = %q, want original PII and redacted credential", got)
	}
}

func TestRestoreInboundDoesNotResolveForgedOrCrossRunTokens(t *testing.T) {
	ctx := context.Background()
	payload := "email alice@example.com"
	vault := newFakeVault()
	detector := fakeDetector{spans: []Span{spanFor(t, payload, "alice@example.com", DataTypeEmail)}}
	engine := newTestEngine(t, detector, vault, fakeRehydrationAuthorizer{})
	engine.random = bytes.NewReader(bytes.Repeat([]byte{7}, 16))

	protected, err := engine.ProtectOutbound(ctx, Scope{TenantID: "tenant-1", RunID: "run-1"}, "model-provider", []byte(payload))
	if err != nil {
		t.Fatalf("ProtectOutbound() error = %v", err)
	}
	forged := string(protected) + " [[AGENT_TOKEN:ffffffffffffffffffffffffffffffff]]"

	got, err := engine.RestoreInbound(
		ctx,
		Scope{TenantID: "tenant-1", RunID: "run-2"},
		"user-ui",
		"display",
		[]byte(forged),
	)
	if err != nil {
		t.Fatalf("cross-Run RestoreInbound() error = %v", err)
	}
	if string(got) != forged {
		t.Fatalf("cross-Run or forged token changed: got %q, want %q", got, forged)
	}

	got, err = engine.RestoreInbound(
		ctx,
		Scope{TenantID: "tenant-1", RunID: "run-1"},
		"user-ui",
		"display",
		[]byte(forged),
	)
	if err != nil {
		t.Fatalf("forged-token RestoreInbound() error = %v", err)
	}
	if !strings.HasSuffix(string(got), " [[AGENT_TOKEN:ffffffffffffffffffffffffffffffff]]") {
		t.Fatalf("forged token should remain unresolved: %q", got)
	}
}

func TestRestoreInboundRequiresAudienceAndPurposeAuthorization(t *testing.T) {
	ctx := context.Background()
	payload := "alice@example.com"
	vault := newFakeVault()
	detector := fakeDetector{spans: []Span{spanFor(t, payload, payload, DataTypeEmail)}}
	authErr := errors.New("rehydration is not allowed")
	engine := newTestEngine(t, detector, vault, fakeRehydrationAuthorizer{err: authErr})
	engine.random = bytes.NewReader(bytes.Repeat([]byte{3}, 16))

	protected, err := engine.ProtectOutbound(ctx, Scope{TenantID: "tenant-1", RunID: "run-1"}, "model-provider", []byte(payload))
	if err != nil {
		t.Fatalf("ProtectOutbound() error = %v", err)
	}
	got, err := engine.RestoreInbound(
		ctx,
		Scope{TenantID: "tenant-1", RunID: "run-1"},
		"user-ui",
		"display",
		protected,
	)
	if !errors.Is(err, authErr) {
		t.Fatalf("RestoreInbound() error = %v, want %v", err, authErr)
	}
	if got != nil {
		t.Fatalf("denied restoration returned a payload: %q", got)
	}
}

func TestProtectOutboundFailsClosedWhenVaultWriteFails(t *testing.T) {
	ctx := context.Background()
	payload := "alice@example.com"
	vault := newFakeVault()
	vault.putErr = errors.New("vault unavailable")
	detector := fakeDetector{spans: []Span{spanFor(t, payload, payload, DataTypeEmail)}}
	engine := newTestEngine(t, detector, vault, fakeRehydrationAuthorizer{})
	engine.random = bytes.NewReader(bytes.Repeat([]byte{5}, 16))

	got, err := engine.ProtectOutbound(ctx, Scope{TenantID: "tenant-1", RunID: "run-1"}, "model-provider", []byte(payload))
	if err == nil {
		t.Fatal("ProtectOutbound() error = nil, want Vault failure")
	}
	if got != nil {
		t.Fatalf("failed protection returned a payload: %q", got)
	}
}

func TestProtectOutboundRejectsOverlappingAndInvalidSpans(t *testing.T) {
	ctx := context.Background()
	payload := "alice@example.com"
	vault := newFakeVault()
	first := spanFor(t, payload, "alice", DataTypePerson)
	second := spanFor(t, payload, "alice@example.com", DataTypeEmail)
	engine := newTestEngine(t, fakeDetector{spans: []Span{first, second}}, vault, fakeRehydrationAuthorizer{})

	if got, err := engine.ProtectOutbound(ctx, Scope{TenantID: "tenant-1", RunID: "run-1"}, "model-provider", []byte(payload)); err == nil || got != nil {
		t.Fatalf("overlapping spans: payload=%q error=%v, want nil payload and error", got, err)
	}

	engine.detector = fakeDetector{spans: []Span{{Start: 0, End: len(payload) + 1, Type: DataTypeEmail}}}
	if got, err := engine.ProtectOutbound(ctx, Scope{TenantID: "tenant-1", RunID: "run-1"}, "model-provider", []byte(payload)); err == nil || got != nil {
		t.Fatalf("out-of-bounds span: payload=%q error=%v, want nil payload and error", got, err)
	}
}

func TestProtectOutboundRejectsUnknownClassification(t *testing.T) {
	ctx := context.Background()
	payload := "sensitive"
	vault := newFakeVault()
	detector := fakeDetector{spans: []Span{{Start: 0, End: len(payload), Type: DataType("UNCLASSIFIED")}}}
	engine := newTestEngine(t, detector, vault, fakeRehydrationAuthorizer{})

	got, err := engine.ProtectOutbound(ctx, Scope{TenantID: "tenant-1", RunID: "run-1"}, "model-provider", []byte(payload))
	if !errors.Is(err, ErrUnknownDataType) {
		t.Fatalf("ProtectOutbound() error = %v, want ErrUnknownDataType", err)
	}
	if got != nil {
		t.Fatalf("unknown classification returned a payload: %q", got)
	}
}

func TestNewEngineRequiresSecurityDependencies(t *testing.T) {
	_, err := NewEngine(fakeDetector{}, nil, fakeRehydrationAuthorizer{})
	if err == nil {
		t.Fatal("NewEngine() error = nil, want missing Vault error")
	}
}

func TestProtectOutboundRequiresTrustedScopeAndAudience(t *testing.T) {
	engine := newTestEngine(t, fakeDetector{}, newFakeVault(), fakeRehydrationAuthorizer{})
	for _, tc := range []struct {
		name  string
		scope Scope
		aud   string
	}{
		{name: "missing tenant", scope: Scope{RunID: "run-1"}, aud: "model"},
		{name: "missing run", scope: Scope{TenantID: "tenant-1"}, aud: "model"},
		{name: "missing audience", scope: Scope{TenantID: "tenant-1", RunID: "run-1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.ProtectOutbound(context.Background(), tc.scope, tc.aud, []byte("plain"))
			if err == nil || got != nil {
				t.Fatalf("ProtectOutbound() = %q, %v; want nil payload and error", got, err)
			}
		})
	}
}

func TestProtectOutboundScannerFailureReturnsNoOriginalPayload(t *testing.T) {
	ctx := context.Background()
	payload := "alice@example.com"
	scannerErr := fmt.Errorf("scanner offline")
	engine := newTestEngine(t, fakeDetector{err: scannerErr}, newFakeVault(), fakeRehydrationAuthorizer{})

	got, err := engine.ProtectOutbound(ctx, Scope{TenantID: "tenant-1", RunID: "run-1"}, "model-provider", []byte(payload))
	if !errors.Is(err, scannerErr) {
		t.Fatalf("ProtectOutbound() error = %v, want %v", err, scannerErr)
	}
	if got != nil {
		t.Fatalf("scanner failure returned original payload: %q", got)
	}
}

func TestProtectOutboundDeniesRestrictedClassification(t *testing.T) {
	payload := "confidential contract text"
	engine := newTestEngine(t, fakeDetector{
		spans: []Span{spanFor(t, payload, payload, DataTypeRestricted)},
	}, newFakeVault(), fakeRehydrationAuthorizer{})

	got, err := engine.ProtectOutbound(
		context.Background(),
		Scope{TenantID: "tenant-1", RunID: "run-1"},
		"model-provider",
		[]byte(payload),
	)
	if !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("ProtectOutbound() error = %v, want ErrEgressDenied", err)
	}
	if got != nil {
		t.Fatalf("restricted payload escaped scanner: %q", got)
	}
}

func TestRestoreInboundPreservesMalformedTokenMarkers(t *testing.T) {
	engine := newTestEngine(t, fakeDetector{}, newFakeVault(), fakeRehydrationAuthorizer{})
	input := []byte("before [[AGENT_TOKEN:not-a-token]] after")
	got, err := engine.RestoreInbound(
		context.Background(),
		Scope{TenantID: "tenant-1", RunID: "run-1"},
		"user-ui",
		"display",
		input,
	)
	if err != nil {
		t.Fatalf("RestoreInbound() error = %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("malformed token marker changed: got %q, want %q", got, input)
	}
}
