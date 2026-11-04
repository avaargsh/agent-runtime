package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/avaargsh/agent-runtime/internal/securitycontext"
)

var (
	ErrInvalidEvent       = errors.New("invalid Runtime audit event")
	ErrRecorderUnavailable = errors.New("Runtime audit recorder unavailable")
)

type EventType string

const (
	EventRunStarted             EventType = "RUN_STARTED"
	EventRunCancelled           EventType = "RUN_CANCELLED"
	EventModelRequestPrepared   EventType = "MODEL_REQUEST_PREPARED"
	EventModelRequestSent       EventType = "MODEL_REQUEST_SENT"
	EventModelResponseReceived  EventType = "MODEL_RESPONSE_RECEIVED"
	EventModelRequestFailed     EventType = "MODEL_REQUEST_FAILED"
	EventToolProposed           EventType = "TOOL_PROPOSED"
	EventToolCallStarted        EventType = "TOOL_CALL_STARTED"
	EventToolCallCompleted      EventType = "TOOL_CALL_COMPLETED"
	EventToolCallFailed         EventType = "TOOL_CALL_FAILED"
	EventFileOperationObserved  EventType = "FILE_OPERATION_OBSERVED"
	EventShellOperationObserved EventType = "SHELL_OPERATION_OBSERVED"
	EventNetworkEgressObserved  EventType = "NETWORK_EGRESS_OBSERVED"
	EventPolicyAllowed          EventType = "POLICY_ALLOWED"
	EventPolicyDenied           EventType = "POLICY_DENIED"
	EventApprovalRequested      EventType = "APPROVAL_REQUESTED"
	EventApprovalResolved       EventType = "APPROVAL_RESOLVED"
	EventDataProtected          EventType = "DATA_PROTECTED"
	EventDataRestored           EventType = "DATA_RESTORED"
	EventSecurityDenied         EventType = "SECURITY_DENIED"
	EventBreakerTripped         EventType = "BREAKER_TRIPPED"
	EventBreakerRecovered       EventType = "BREAKER_RECOVERED"
	EventGuardOperationLinked   EventType = "GUARD_OPERATION_LINKED"
)

type Outcome string

const (
	OutcomeObserved   Outcome = "OBSERVED"
	OutcomeDispatched Outcome = "DISPATCHED"
	OutcomeSucceeded  Outcome = "SUCCEEDED"
	OutcomeFailed     Outcome = "FAILED"
	OutcomeDenied     Outcome = "DENIED"
	OutcomeCancelled  Outcome = "CANCELLED"
	OutcomePending    Outcome = "PENDING"
)

// Event intentionally carries digests and references, not raw prompts, tool
// arguments, secrets, or model response bodies.
type Event struct {
	EventID         string
	OccurredAt      time.Time
	Type            EventType
	Identity        securitycontext.Context
	Source          string
	Action          string
	Resource        string
	Outcome         Outcome
	ReasonCode      string
	RiskLevel       string
	PayloadDigest   string
	EvidenceRef     string
	GuardOperationID string
	ParentEventID   string
	BreakerEpoch    uint64
}

func (e Event) Validate() error {
	if !validIdentifier(e.EventID) || e.OccurredAt.IsZero() ||
		!validEventType(e.Type) || e.Identity.Validate() != nil ||
		!validIdentifier(e.Source) || !validOutcome(e.Outcome) {
		return ErrInvalidEvent
	}
	for name, value := range map[string]string{
		"action":             e.Action,
		"resource":           e.Resource,
		"reason_code":        e.ReasonCode,
		"risk_level":         e.RiskLevel,
		"evidence_ref":       e.EvidenceRef,
		"guard_operation_id": e.GuardOperationID,
		"parent_event_id":    e.ParentEventID,
	} {
		if value != "" && !validIdentifier(value) {
			return fmt.Errorf("%w: invalid %s", ErrInvalidEvent, name)
		}
	}
	if e.PayloadDigest != "" && !validDigest(e.PayloadDigest) {
		return fmt.Errorf("%w: invalid payload digest", ErrInvalidEvent)
	}
	return nil
}

func (e Event) IdentityClaims() securitycontext.Claims {
	return e.Identity.Claims()
}

// Recorder is an append-only durable audit boundary. Implementations must
// atomically reject duplicate EventID reuse with different content and expose
// no update/delete operation. Audit payloads must remain redacted.
type Recorder interface {
	Append(ctx context.Context, event Event) error
}

// AppendChecked validates an event before persistence. Its error must be
// propagated to the enforcement boundary: callers must not dispatch protected
// actions or external egress if the audit append fails.
func AppendChecked(ctx context.Context, recorder Recorder, event Event) error {
	if recorder == nil {
		return ErrRecorderUnavailable
	}
	if err := event.Validate(); err != nil {
		return err
	}
	if err := recorder.Append(ctx, event); err != nil {
		return fmt.Errorf("append Runtime audit event: %w", err)
	}
	return nil
}

func validEventType(value EventType) bool {
	switch value {
	case EventRunStarted, EventRunCancelled,
		EventModelRequestPrepared, EventModelRequestSent, EventModelResponseReceived, EventModelRequestFailed,
		EventToolProposed, EventToolCallStarted, EventToolCallCompleted, EventToolCallFailed,
		EventFileOperationObserved, EventShellOperationObserved, EventNetworkEgressObserved,
		EventPolicyAllowed, EventPolicyDenied, EventApprovalRequested, EventApprovalResolved,
		EventDataProtected, EventDataRestored, EventSecurityDenied,
		EventBreakerTripped, EventBreakerRecovered, EventGuardOperationLinked:
		return true
	default:
		return false
	}
}

func validOutcome(value Outcome) bool {
	switch value {
	case OutcomeObserved, OutcomeDispatched, OutcomeSucceeded, OutcomeFailed,
		OutcomeDenied, OutcomeCancelled, OutcomePending:
		return true
	default:
		return false
	}
}

func validIdentifier(value string) bool {
	return value != "" && strings.TrimSpace(value) == value &&
		len(value) <= 512 && !strings.ContainsRune(value, 0)
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}
