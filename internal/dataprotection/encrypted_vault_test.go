package dataprotection

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
)

type fakeKeyProvider struct {
	current map[string]KeyMaterial
	keys    map[string]KeyMaterial
	getErr  error
}

func keyLookup(tenantID, keyID string) string {
	return tenantID + "\x00" + keyID
}

func (p *fakeKeyProvider) CurrentKey(_ context.Context, tenantID string) (KeyMaterial, error) {
	material, ok := p.current[tenantID]
	if !ok {
		return KeyMaterial{}, errors.New("no current key")
	}
	return cloneKeyMaterial(material), nil
}

func (p *fakeKeyProvider) KeyByID(_ context.Context, tenantID, keyID string) (KeyMaterial, error) {
	if p.getErr != nil {
		return KeyMaterial{}, p.getErr
	}
	material, ok := p.keys[keyLookup(tenantID, keyID)]
	if !ok {
		return KeyMaterial{}, fmt.Errorf("key %q not found", keyID)
	}
	return cloneKeyMaterial(material), nil
}

func cloneKeyMaterial(in KeyMaterial) KeyMaterial {
	return KeyMaterial{ID: in.ID, Key: bytes.Clone(in.Key)}
}

type memoryRecordStore struct {
	records map[string]VaultRecord
}

func newMemoryRecordStore() *memoryRecordStore {
	return &memoryRecordStore{records: make(map[string]VaultRecord)}
}

func (s *memoryRecordStore) Create(_ context.Context, scope Scope, tokenID string, record VaultRecord) error {
	key := vaultKey(scope, tokenID)
	if _, exists := s.records[key]; exists {
		return ErrVaultRecordExists
	}
	s.records[key] = cloneVaultRecord(record)
	return nil
}

func (s *memoryRecordStore) Load(_ context.Context, scope Scope, tokenID string) (VaultRecord, bool, error) {
	record, ok := s.records[vaultKey(scope, tokenID)]
	return cloneVaultRecord(record), ok, nil
}

func TestEncryptedVaultEncryptsAtRestAndSupportsKeyRotation(t *testing.T) {
	ctx := context.Background()
	scope := Scope{TenantID: "tenant-1", RunID: "run-1"}
	plaintext := []byte("alice@example.com")
	oldKey := KeyMaterial{ID: "key-v1", Key: bytes.Repeat([]byte{1}, 32)}
	newKey := KeyMaterial{ID: "key-v2", Key: bytes.Repeat([]byte{2}, 32)}
	provider := &fakeKeyProvider{
		current: map[string]KeyMaterial{"tenant-1": oldKey},
		keys: map[string]KeyMaterial{
			keyLookup("tenant-1", "key-v1"): oldKey,
			keyLookup("tenant-1", "key-v2"): newKey,
		},
	}
	store := newMemoryRecordStore()
	vault, err := NewEncryptedVault(store, provider)
	if err != nil {
		t.Fatalf("NewEncryptedVault() error = %v", err)
	}
	vault.random = bytes.NewReader(bytes.Repeat([]byte{9}, 64))

	if err := vault.Put(ctx, scope, "0123456789abcdef0123456789abcdef", DataTypeEmail, plaintext); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	record := store.records[vaultKey(scope, "0123456789abcdef0123456789abcdef")]
	if record.KeyID != "key-v1" {
		t.Fatalf("record KeyID = %q, want key-v1", record.KeyID)
	}
	if bytes.Contains(record.Ciphertext, plaintext) {
		t.Fatal("Vault record contains plaintext")
	}

	// Rotate the write key. Existing records must remain readable by key ID.
	provider.current["tenant-1"] = newKey
	gotType, got, found, err := vault.Get(ctx, scope, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("Get() after rotation error = %v", err)
	}
	if !found || gotType != DataTypeEmail || !bytes.Equal(got, plaintext) {
		t.Fatalf("Get() after rotation = (%q, %q, %v), want EMAIL and original value", gotType, got, found)
	}

	if err := vault.Put(ctx, scope, "abcdef0123456789abcdef0123456789", DataTypeEmail, plaintext); err != nil {
		t.Fatalf("Put() after rotation error = %v", err)
	}
	rotated := store.records[vaultKey(scope, "abcdef0123456789abcdef0123456789")]
	if rotated.KeyID != "key-v2" {
		t.Fatalf("new record KeyID = %q, want key-v2", rotated.KeyID)
	}
}

func TestEncryptedVaultBindsCiphertextToTenantRunTokenAndDataType(t *testing.T) {
	ctx := context.Background()
	scope := Scope{TenantID: "tenant-1", RunID: "run-1"}
	tokenID := "0123456789abcdef0123456789abcdef"
	provider := &fakeKeyProvider{
		current: map[string]KeyMaterial{"tenant-1": {ID: "key-v1", Key: bytes.Repeat([]byte{3}, 32)}},
		keys: map[string]KeyMaterial{
			keyLookup("tenant-1", "key-v1"): {ID: "key-v1", Key: bytes.Repeat([]byte{3}, 32)},
		},
	}
	store := newMemoryRecordStore()
	vault, err := NewEncryptedVault(store, provider)
	if err != nil {
		t.Fatalf("NewEncryptedVault() error = %v", err)
	}
	vault.random = bytes.NewReader(bytes.Repeat([]byte{7}, 32))
	if err := vault.Put(ctx, scope, tokenID, DataTypeEmail, []byte("alice@example.com")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	if _, _, found, err := vault.Get(ctx, Scope{TenantID: "tenant-1", RunID: "run-2"}, tokenID); err != nil || found {
		t.Fatalf("cross-Run Get() = found %v, err %v; want not found", found, err)
	}
	if _, _, found, err := vault.Get(ctx, Scope{TenantID: "tenant-2", RunID: "run-1"}, tokenID); err != nil || found {
		t.Fatalf("cross-tenant Get() = found %v, err %v; want not found", found, err)
	}

	record := store.records[vaultKey(scope, tokenID)]
	record.DataType = DataTypePhone
	store.records[vaultKey(scope, tokenID)] = record
	if _, _, _, err := vault.Get(ctx, scope, tokenID); !errors.Is(err, ErrVaultAuthentication) {
		t.Fatalf("Get() after data type tampering error = %v, want ErrVaultAuthentication", err)
	}
}

func TestEncryptedVaultRejectsDuplicateTokenAndNeverOverwrites(t *testing.T) {
	ctx := context.Background()
	scope := Scope{TenantID: "tenant-1", RunID: "run-1"}
	tokenID := "0123456789abcdef0123456789abcdef"
	material := KeyMaterial{ID: "key-v1", Key: bytes.Repeat([]byte{4}, 32)}
	provider := &fakeKeyProvider{
		current: map[string]KeyMaterial{"tenant-1": material},
		keys: map[string]KeyMaterial{keyLookup("tenant-1", "key-v1"): material},
	}
	store := newMemoryRecordStore()
	vault, err := NewEncryptedVault(store, provider)
	if err != nil {
		t.Fatalf("NewEncryptedVault() error = %v", err)
	}
	vault.random = bytes.NewReader(bytes.Repeat([]byte{8}, 32))
	if err := vault.Put(ctx, scope, tokenID, DataTypeEmail, []byte("first@example.com")); err != nil {
		t.Fatalf("first Put() error = %v", err)
	}
	first := cloneVaultRecord(store.records[vaultKey(scope, tokenID)])
	if err := vault.Put(ctx, scope, tokenID, DataTypeEmail, []byte("second@example.com")); !errors.Is(err, ErrVaultRecordExists) {
		t.Fatalf("duplicate Put() error = %v, want ErrVaultRecordExists", err)
	}
	if !bytes.Equal(store.records[vaultKey(scope, tokenID)].Ciphertext, first.Ciphertext) {
		t.Fatal("duplicate token write overwrote the existing Vault record")
	}
}

func TestEncryptedVaultFailsClosedOnUnknownKeyOrCorruptedCiphertext(t *testing.T) {
	ctx := context.Background()
	scope := Scope{TenantID: "tenant-1", RunID: "run-1"}
	tokenID := "0123456789abcdef0123456789abcdef"
	material := KeyMaterial{ID: "key-v1", Key: bytes.Repeat([]byte{5}, 32)}
	provider := &fakeKeyProvider{
		current: map[string]KeyMaterial{"tenant-1": material},
		keys: map[string]KeyMaterial{keyLookup("tenant-1", "key-v1"): material},
	}
	store := newMemoryRecordStore()
	vault, err := NewEncryptedVault(store, provider)
	if err != nil {
		t.Fatalf("NewEncryptedVault() error = %v", err)
	}
	vault.random = bytes.NewReader(bytes.Repeat([]byte{6}, 32))
	if err := vault.Put(ctx, scope, tokenID, DataTypeEmail, []byte("alice@example.com")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	delete(provider.keys, keyLookup("tenant-1", "key-v1"))
	if _, _, _, err := vault.Get(ctx, scope, tokenID); err == nil {
		t.Fatal("Get() with unavailable key succeeded")
	}
	provider.keys[keyLookup("tenant-1", "key-v1")] = material

	record := store.records[vaultKey(scope, tokenID)]
	record.Ciphertext[len(record.Ciphertext)-1] ^= 0xff
	store.records[vaultKey(scope, tokenID)] = record
	if _, _, _, err := vault.Get(ctx, scope, tokenID); !errors.Is(err, ErrVaultAuthentication) {
		t.Fatalf("Get() after ciphertext tampering error = %v, want ErrVaultAuthentication", err)
	}
}
