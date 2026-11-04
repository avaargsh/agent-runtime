package dataprotection

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	ErrVaultRecordExists  = errors.New("Vault token record already exists")
	ErrVaultAuthentication = errors.New("Vault record authentication failed")
	ErrVaultKeyInvalid    = errors.New("Vault encryption key is invalid")
)

// KeyMaterial identifies one tenant encryption key. Key bytes are supplied by
// a managed key provider and must never be persisted in VaultRecordStore.
type KeyMaterial struct {
	ID  string
	Key []byte
}

// KeyProvider supplies the active write key and resolves historical versions
// for decryption. Implementations should wrap KMS/HSM or an equivalent managed
// key service, not a key literal committed with Runtime configuration.
type KeyProvider interface {
	CurrentKey(ctx context.Context, tenantID string) (KeyMaterial, error)
	KeyByID(ctx context.Context, tenantID, keyID string) (KeyMaterial, error)
}

// VaultRecord is ciphertext-only persisted metadata. Nonce and Ciphertext must
// be stored as binary values without logging their contents.
type VaultRecord struct {
	DataType   DataType
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
	ExpiresAt  time.Time
}

// VaultRecordStore is a persistence boundary. Create MUST be atomic
// create-if-absent for (tenant_id, run_id, token_id); it must never overwrite a
// prior mapping. Load must enforce the same composite scope.
type VaultRecordStore interface {
	Create(ctx context.Context, scope Scope, tokenID string, record VaultRecord) error
	Load(ctx context.Context, scope Scope, tokenID string) (VaultRecord, bool, error)
}

// EncryptedVault implements Vault using AES-GCM with metadata-bound
// associated data. Key rotation is write-new/read-old: CurrentKey is used for
// new records, while KeyByID resolves each stored key version.
type EncryptedVault struct {
	store    VaultRecordStore
	keys     KeyProvider
	random   io.Reader
	randomMu sync.Mutex
	ttl      time.Duration
	now      func() time.Time
}

func NewEncryptedVault(store VaultRecordStore, keys KeyProvider, ttl time.Duration) (*EncryptedVault, error) {
	if store == nil || keys == nil {
		return nil, ErrMissingDependency
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("%w: Token Vault TTL must be positive", ErrInvalidVaultEntry)
	}
	return &EncryptedVault{
		store: store,
		keys: keys,
		random: rand.Reader,
		ttl: ttl,
		now: time.Now,
	}, nil
}

func (v *EncryptedVault) Put(
	ctx context.Context,
	scope Scope,
	tokenID string,
	dataType DataType,
	plaintext []byte,
) error {
	if err := v.validate(scope, tokenID); err != nil {
		return err
	}
	if !reversibleType(dataType) {
		return fmt.Errorf("%w: only approved reversible PII can enter the Token Vault", ErrInvalidVaultEntry)
	}
	if len(plaintext) == 0 || !utf8.Valid(plaintext) {
		return fmt.Errorf("%w: Vault value must be non-empty UTF-8", ErrInvalidVaultEntry)
	}

	material, err := v.keys.CurrentKey(ctx, scope.TenantID)
	if err != nil {
		return fmt.Errorf("resolve current Vault key: %w", err)
	}
	if err := validateKeyMaterial(material); err != nil {
		return err
	}
	aead, err := newAEAD(material.Key)
	if err != nil {
		return err
	}

	nonce := make([]byte, aead.NonceSize())
	v.randomMu.Lock()
	_, randomErr := io.ReadFull(v.random, nonce)
	v.randomMu.Unlock()
	if randomErr != nil {
		return fmt.Errorf("generate Vault nonce: %w", randomErr)
	}

	aad := vaultAssociatedData(scope, tokenID, dataType, material.ID)
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	record := VaultRecord{
		DataType:   dataType,
		KeyID:      material.ID,
		Nonce:      bytes.Clone(nonce),
		Ciphertext: bytes.Clone(ciphertext),
		ExpiresAt:  v.now().UTC().Add(v.ttl),
	}
	if err := v.store.Create(ctx, scope, tokenID, record); err != nil {
		return fmt.Errorf("persist encrypted Vault record: %w", err)
	}
	return nil
}

func (v *EncryptedVault) Get(
	ctx context.Context,
	scope Scope,
	tokenID string,
) (DataType, []byte, bool, error) {
	if err := v.validate(scope, tokenID); err != nil {
		return "", nil, false, err
	}

	record, found, err := v.store.Load(ctx, scope, tokenID)
	if err != nil {
		return "", nil, false, fmt.Errorf("load encrypted Vault record: %w", err)
	}
	if !found {
		return "", nil, false, nil
	}
	if record.ExpiresAt.IsZero() || !v.now().Before(record.ExpiresAt) {
		return "", nil, false, nil
	}
	if !reversibleType(record.DataType) || len(record.Ciphertext) == 0 {
		return "", nil, false, ErrInvalidVaultEntry
	}
	if err := validateOpaqueField("Vault key_id", record.KeyID, 128); err != nil {
		return "", nil, false, ErrInvalidVaultEntry
	}

	material, err := v.keys.KeyByID(ctx, scope.TenantID, record.KeyID)
	if err != nil {
		return "", nil, false, fmt.Errorf("resolve Vault key %q: %w", record.KeyID, err)
	}
	if err := validateKeyMaterial(material); err != nil || material.ID != record.KeyID {
		return "", nil, false, ErrVaultKeyInvalid
	}
	aead, err := newAEAD(material.Key)
	if err != nil {
		return "", nil, false, err
	}
	if len(record.Nonce) != aead.NonceSize() || len(record.Ciphertext) < aead.Overhead() {
		return "", nil, false, ErrVaultAuthentication
	}

	aad := vaultAssociatedData(scope, tokenID, record.DataType, record.KeyID)
	plaintext, err := aead.Open(nil, record.Nonce, record.Ciphertext, aad)
	if err != nil {
		return "", nil, false, ErrVaultAuthentication
	}
	if len(plaintext) == 0 || !utf8.Valid(plaintext) {
		return "", nil, false, ErrInvalidVaultEntry
	}
	return record.DataType, plaintext, true, nil
}

func (v *EncryptedVault) validate(scope Scope, tokenID string) error {
	if v == nil || v.store == nil || v.keys == nil || v.random == nil || v.now == nil || v.ttl <= 0 {
		return ErrMissingDependency
	}
	if err := validateOpaqueField("tenant_id", scope.TenantID, 255); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidScope, err)
	}
	if err := validateOpaqueField("run_id", scope.RunID, 255); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidScope, err)
	}
	if len(tokenID) != tokenIDSize*2 || strings.ToLower(tokenID) != tokenID {
		return ErrInvalidVaultEntry
	}
	decoded, err := hex.DecodeString(tokenID)
	if err != nil || len(decoded) != tokenIDSize {
		return ErrInvalidVaultEntry
	}
	return nil
}

func validateKeyMaterial(material KeyMaterial) error {
	if err := validateOpaqueField("Vault key_id", material.ID, 128); err != nil {
		return ErrVaultKeyInvalid
	}
	if len(material.Key) != 16 && len(material.Key) != 24 && len(material.Key) != 32 {
		return ErrVaultKeyInvalid
	}
	return nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(bytes.Clone(key))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVaultKeyInvalid, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVaultKeyInvalid, err)
	}
	return aead, nil
}

// vaultAssociatedData uses length-prefixed fields so concatenated identity
// values cannot collide. The scope and metadata are authenticated, not encrypted.
func vaultAssociatedData(scope Scope, tokenID string, dataType DataType, keyID string) []byte {
	fields := []string{
		"agent-runtime/token-vault/v1",
		scope.TenantID,
		scope.RunID,
		tokenID,
		string(dataType),
		keyID,
	}
	var encoded bytes.Buffer
	for _, field := range fields {
		_ = binary.Write(&encoded, binary.BigEndian, uint32(len(field)))
		_, _ = encoded.WriteString(field)
	}
	return encoded.Bytes()
}
