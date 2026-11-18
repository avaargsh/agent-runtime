package dataprotection

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	tokenPrefix = "[[AGENT_TOKEN:"
	tokenSuffix = "]]"
	tokenIDSize = 16
)

var (
	ErrMissingDependency = errors.New("data protection dependency is missing")
	ErrInvalidScope      = errors.New("invalid data protection scope")
	ErrInvalidPayload    = errors.New("invalid data protection payload")
	ErrInvalidSpan       = errors.New("detector returned an invalid or overlapping span")
	ErrUnknownDataType   = errors.New("unrecognized sensitive data type")
	ErrEgressDenied      = errors.New("external egress denied by data protection policy")
	ErrInvalidVaultEntry = errors.New("Vault returned an invalid or non-reversible entry")
)

// DataType is a detector-owned classification. Only the explicit PII allowlist
// below can be reversibly tokenized and restored.
type DataType string

const (
	DataTypePerson        DataType = "PERSON"
	DataTypeEmail         DataType = "EMAIL"
	DataTypePhone         DataType = "PHONE"
	DataTypeCustomerID    DataType = "CUSTOMER_ID"
	DataTypePassword      DataType = "PASSWORD"
	DataTypeAPIKey        DataType = "API_KEY"
	DataTypeBearerToken   DataType = "BEARER_TOKEN"
	DataTypePrivateKey    DataType = "PRIVATE_KEY"
	DataTypeSessionCookie DataType = "SESSION_COOKIE"
	DataTypeRestricted    DataType = "RESTRICTED"
)

// Scope is constructed from a trusted Runtime SecurityContext. It must never
// be populated from untrusted Framework/plugin fields.
type Scope struct {
	TenantID string
	RunID    string
}

// Span uses byte offsets into the exact UTF-8 payload passed to Detector.
type Span struct {
	Start int
	End   int
	Type  DataType
}

// Detector identifies sensitive spans. Implementations must return byte offsets
// into payload and must not mutate it.
type Detector interface {
	Detect(ctx context.Context, payload []byte) ([]Span, error)
}

// Vault stores plaintext only through an encrypted, tenant/Run-scoped adapter.
// Production implementations must use authenticated encryption and managed keys;
// plaintext mappings must never be persisted in ordinary Runtime storage.
type Vault interface {
	Put(ctx context.Context, scope Scope, tokenID string, dataType DataType, plaintext []byte) error
	Get(ctx context.Context, scope Scope, tokenID string) (DataType, []byte, bool, error)
}

// RehydrationAuthorizer approves each restore for one data type, audience and
// purpose. An implementation must fail closed when the policy source is absent.
type RehydrationAuthorizer interface {
	Authorize(ctx context.Context, scope Scope, dataType DataType, audience, purpose string) error
}

// Engine protects outbound payloads and restores only previously registered
// reversible tokens for the exact tenant/Run scope.
type Engine struct {
	detector   Detector
	vault      Vault
	authorizer RehydrationAuthorizer
	random     io.Reader
}

func NewEngine(detector Detector, vault Vault, authorizer RehydrationAuthorizer) (*Engine, error) {
	if detector == nil || vault == nil || authorizer == nil {
		return nil, ErrMissingDependency
	}
	return &Engine{
		detector:   detector,
		vault:      vault,
		authorizer: authorizer,
		random:     rand.Reader,
	}, nil
}

// ProtectOutbound classifies and transforms a payload before it crosses an
// external model or remote-tool boundary. It returns no payload on any error;
// callers must never fall back to the original bytes.
func (e *Engine) ProtectOutbound(
	ctx context.Context,
	scope Scope,
	audience string,
	payload []byte,
) ([]byte, error) {
	if err := e.validate(scope, audience); err != nil {
		return nil, err
	}
	if !utf8.Valid(payload) {
		return nil, fmt.Errorf("%w: payload must be UTF-8", ErrInvalidPayload)
	}

	spans, err := e.detector.Detect(ctx, bytes.Clone(payload))
	if err != nil {
		return nil, fmt.Errorf("scan outbound payload: %w", err)
	}
	spans = append([]Span(nil), spans...)
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start == spans[j].Start {
			return spans[i].End < spans[j].End
		}
		return spans[i].Start < spans[j].Start
	})
	if err := validateSpans(payload, spans); err != nil {
		return nil, err
	}

	protected := make([]byte, 0, len(payload))
	cursor := 0
	for _, span := range spans {
		protected = append(protected, payload[cursor:span.Start]...)
		switch {
		case reversibleType(span.Type):
			tokenID, err := e.newTokenID()
			if err != nil {
				return nil, fmt.Errorf("generate data token: %w", err)
			}
			value := bytes.Clone(payload[span.Start:span.End])
			if err := e.vault.Put(ctx, scope, tokenID, span.Type, value); err != nil {
				return nil, fmt.Errorf("store protected value in Vault: %w", err)
			}
			protected = append(protected, tokenPlaceholder(tokenID)...)
		case redactedType(span.Type):
			protected = append(protected, []byte("[REDACTED:"+string(span.Type)+"]")...)
		case span.Type == DataTypeRestricted:
			return nil, fmt.Errorf("%w: %s", ErrEgressDenied, span.Type)
		default:
			return nil, fmt.Errorf("%w: %q", ErrUnknownDataType, span.Type)
		}
		cursor = span.End
	}
	protected = append(protected, payload[cursor:]...)
	return protected, nil
}

// RestoreInbound replaces only exact placeholders previously issued by this
// Engine and found in the same scope. Unknown/forged/cross-Run placeholders are
// left untouched. Any Vault or authorization failure returns no response bytes.
func (e *Engine) RestoreInbound(
	ctx context.Context,
	scope Scope,
	audience string,
	purpose string,
	payload []byte,
) ([]byte, error) {
	if err := e.validate(scope, audience); err != nil {
		return nil, err
	}
	if err := validateOpaqueField("purpose", purpose, 128); err != nil {
		return nil, err
	}
	if !utf8.Valid(payload) {
		return nil, fmt.Errorf("%w: response must be UTF-8", ErrInvalidPayload)
	}

	protected := make([]byte, 0, len(payload))
	cursor := 0
	for cursor < len(payload) {
		relative := bytes.Index(payload[cursor:], []byte(tokenPrefix))
		if relative < 0 {
			protected = append(protected, payload[cursor:]...)
			break
		}
		start := cursor + relative
		protected = append(protected, payload[cursor:start]...)

		tokenID, end, ok := parseToken(payload, start)
		if !ok {
			// Preserve malformed text and continue scanning for a later valid token.
			protected = append(protected, tokenPrefix...)
			cursor = start + len(tokenPrefix)
			continue
		}

		dataType, original, found, err := e.vault.Get(ctx, scope, tokenID)
		if err != nil {
			return nil, fmt.Errorf("resolve response token: %w", err)
		}
		if !found {
			protected = append(protected, payload[start:end]...)
			cursor = end
			continue
		}
		if !reversibleType(dataType) || len(original) == 0 {
			return nil, ErrInvalidVaultEntry
		}
		if err := e.authorizer.Authorize(ctx, scope, dataType, audience, purpose); err != nil {
			return nil, fmt.Errorf("authorize token restoration: %w", err)
		}
		if !utf8.Valid(original) {
			return nil, ErrInvalidVaultEntry
		}
		protected = append(protected, original...)
		cursor = end
	}
	return protected, nil
}

func (e *Engine) validate(scope Scope, audience string) error {
	if e == nil || e.detector == nil || e.vault == nil || e.authorizer == nil || e.random == nil {
		return ErrMissingDependency
	}
	if err := validateOpaqueField("tenant_id", scope.TenantID, 255); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidScope, err)
	}
	if err := validateOpaqueField("run_id", scope.RunID, 255); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidScope, err)
	}
	if err := validateOpaqueField("audience", audience, 128); err != nil {
		return err
	}
	return nil
}

func validateOpaqueField(name, value string, maxLength int) error {
	if value == "" || strings.TrimSpace(value) != value || len(value) > maxLength ||
		!utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("invalid %s", name)
	}
	return nil
}

func validateSpans(payload []byte, spans []Span) error {
	previousEnd := 0
	for _, span := range spans {
		if span.Start < previousEnd || span.Start < 0 || span.End <= span.Start || span.End > len(payload) {
			return ErrInvalidSpan
		}
		if !utf8.RuneStart(payload[span.Start]) ||
			(span.End < len(payload) && !utf8.RuneStart(payload[span.End])) {
			return ErrInvalidSpan
		}
		if !knownType(span.Type) {
			return fmt.Errorf("%w: %q", ErrUnknownDataType, span.Type)
		}
		previousEnd = span.End
	}
	return nil
}

func knownType(dataType DataType) bool {
	return reversibleType(dataType) || redactedType(dataType) || dataType == DataTypeRestricted
}

func reversibleType(dataType DataType) bool {
	switch dataType {
	case DataTypePerson, DataTypeEmail, DataTypePhone, DataTypeCustomerID:
		return true
	default:
		return false
	}
}

func redactedType(dataType DataType) bool {
	switch dataType {
	case DataTypePassword, DataTypeAPIKey, DataTypeBearerToken, DataTypePrivateKey, DataTypeSessionCookie:
		return true
	default:
		return false
	}
}

func (e *Engine) newTokenID() (string, error) {
	var raw [tokenIDSize]byte
	if _, err := io.ReadFull(e.random, raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func tokenPlaceholder(tokenID string) []byte {
	return []byte(tokenPrefix + tokenID + tokenSuffix)
}

func parseToken(payload []byte, start int) (string, int, bool) {
	idStart := start + len(tokenPrefix)
	idEnd := idStart + tokenIDSize*2
	tokenEnd := idEnd + len(tokenSuffix)
	if start < 0 || tokenEnd > len(payload) ||
		!bytes.Equal(payload[start:start+len(tokenPrefix)], []byte(tokenPrefix)) ||
		!bytes.Equal(payload[idEnd:tokenEnd], []byte(tokenSuffix)) {
		return "", start, false
	}
	idBytes := payload[idStart:idEnd]
	for _, value := range idBytes {
		if !((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')) {
			return "", start, false
		}
	}
	return string(idBytes), tokenEnd, true
}
