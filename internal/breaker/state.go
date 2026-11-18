package breaker

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidScope             = errors.New("invalid circuit breaker scope")
	ErrInvalidRecord            = errors.New("invalid circuit breaker record")
	ErrInvalidTransition        = errors.New("invalid circuit breaker transition")
	ErrBreakerOpen              = errors.New("circuit breaker is OPEN")
	ErrReadOnlyProbeOnly        = errors.New("HALF_OPEN permits read-only probes only")
	ErrStaleEpoch               = errors.New("stale circuit breaker epoch")
	ErrApprovalRequired         = errors.New("recovery approval is required")
	ErrApprovalMismatch         = errors.New("recovery approval does not match")
	ErrRecoveryEvidenceRequired = errors.New("recovery evidence is required")
)

type ScopeKind string

const (
	ScopeRun           ScopeKind = "RUN"
	ScopeAgentInstance ScopeKind = "AGENT_INSTANCE"
	ScopeTenant        ScopeKind = "TENANT"
)

type Scope struct {
	Kind ScopeKind
	ID   string
}

type State string

const (
	StateClosed   State = "CLOSED"
	StateOpen     State = "OPEN"
	StateHalfOpen State = "HALF_OPEN"
)

type EffectClass string

const (
	EffectReadOnly          EffectClass = "READ_ONLY"
	EffectReversibleWrite   EffectClass = "REVERSIBLE_WRITE"
	EffectIrreversibleWrite EffectClass = "IRREVERSIBLE_WRITE"
)

type Record struct {
	Scope                   Scope
	State                   State
	Epoch                   uint64
	Version                 uint64
	ReasonCode              string
	TriggerEventID          string
	OpenedAt                time.Time
	RecoveryApprovalID      string
	LastRecoveryEvidenceRef string
	UpdatedAt               time.Time
}

func NewClosed(scope Scope, now time.Time) (Record, error) {
	if err := validateScope(scope); err != nil {
		return Record{}, err
	}
	if now.IsZero() {
		return Record{}, ErrInvalidRecord
	}
	return Record{
		Scope:     scope,
		State:     StateClosed,
		Epoch:     1,
		Version:   1,
		UpdatedAt: now.UTC(),
	}, nil
}

func (r Record) Trip(reasonCode, triggerEventID string, at time.Time) (Record, error) {
	if err := r.Validate(); err != nil {
		return Record{}, err
	}
	if !validIdentifier(reasonCode) || !validIdentifier(triggerEventID) || at.IsZero() {
		return Record{}, ErrInvalidRecord
	}
	if r.State == StateOpen {
		return r, nil
	}
	if !at.After(r.UpdatedAt) {
		return Record{}, ErrInvalidRecord
	}

	next := r
	next.State = StateOpen
	next.Epoch++
	next.Version++
	next.ReasonCode = reasonCode
	next.TriggerEventID = triggerEventID
	next.OpenedAt = at.UTC()
	next.RecoveryApprovalID = ""
	next.UpdatedAt = at.UTC()
	return next, nil
}

func (r Record) BeginRecovery(approvalID string, at time.Time) (Record, error) {
	if err := r.Validate(); err != nil {
		return Record{}, err
	}
	if r.State != StateOpen {
		return Record{}, ErrInvalidTransition
	}
	if !validIdentifier(approvalID) {
		return Record{}, ErrApprovalRequired
	}
	if at.IsZero() || !at.After(r.UpdatedAt) {
		return Record{}, ErrInvalidRecord
	}

	next := r
	next.State = StateHalfOpen
	next.Epoch++
	next.Version++
	next.RecoveryApprovalID = approvalID
	next.UpdatedAt = at.UTC()
	return next, nil
}

func (r Record) CompleteRecovery(approvalID, evidenceRef string, at time.Time) (Record, error) {
	if err := r.Validate(); err != nil {
		return Record{}, err
	}
	if r.State != StateHalfOpen {
		return Record{}, ErrInvalidTransition
	}
	if approvalID != r.RecoveryApprovalID {
		return Record{}, ErrApprovalMismatch
	}
	if !validIdentifier(evidenceRef) {
		return Record{}, ErrRecoveryEvidenceRequired
	}
	if at.IsZero() || !at.After(r.UpdatedAt) {
		return Record{}, ErrInvalidRecord
	}

	next := r
	next.State = StateClosed
	next.Epoch++
	next.Version++
	next.ReasonCode = ""
	next.TriggerEventID = ""
	next.OpenedAt = time.Time{}
	next.RecoveryApprovalID = ""
	next.LastRecoveryEvidenceRef = evidenceRef
	next.UpdatedAt = at.UTC()
	return next, nil
}

func (r Record) Check(expectedEpoch uint64, effect EffectClass) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if expectedEpoch != r.Epoch {
		return ErrStaleEpoch
	}
	switch effect {
	case EffectReadOnly, EffectReversibleWrite, EffectIrreversibleWrite:
	default:
		return fmt.Errorf("%w: unknown effect class %q", ErrInvalidRecord, effect)
	}
	switch r.State {
	case StateOpen:
		return ErrBreakerOpen
	case StateHalfOpen:
		if effect != EffectReadOnly {
			return ErrReadOnlyProbeOnly
		}
	}
	return nil
}

func (r Record) Validate() error {
	if err := validateScope(r.Scope); err != nil {
		return err
	}
	if r.Epoch == 0 || r.Version == 0 || r.UpdatedAt.IsZero() {
		return ErrInvalidRecord
	}
	switch r.State {
	case StateClosed:
		if r.ReasonCode != "" || r.TriggerEventID != "" || !r.OpenedAt.IsZero() || r.RecoveryApprovalID != "" {
			return ErrInvalidRecord
		}
	case StateOpen:
		if !validIdentifier(r.ReasonCode) || !validIdentifier(r.TriggerEventID) ||
			r.OpenedAt.IsZero() || r.OpenedAt.After(r.UpdatedAt) || r.RecoveryApprovalID != "" {
			return ErrInvalidRecord
		}
	case StateHalfOpen:
		if !validIdentifier(r.ReasonCode) || !validIdentifier(r.TriggerEventID) ||
			r.OpenedAt.IsZero() || r.OpenedAt.After(r.UpdatedAt) ||
			!validIdentifier(r.RecoveryApprovalID) {
			return ErrInvalidRecord
		}
	default:
		return ErrInvalidRecord
	}
	if r.LastRecoveryEvidenceRef != "" && !validIdentifier(r.LastRecoveryEvidenceRef) {
		return ErrInvalidRecord
	}
	return nil
}

func validateScope(scope Scope) error {
	switch scope.Kind {
	case ScopeRun, ScopeAgentInstance, ScopeTenant:
	default:
		return ErrInvalidScope
	}
	if !validIdentifier(scope.ID) {
		return ErrInvalidScope
	}
	return nil
}

func validIdentifier(value string) bool {
	return value != "" && strings.TrimSpace(value) == value &&
		len(value) <= 512 && !strings.ContainsRune(value, 0)
}
