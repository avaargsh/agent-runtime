// Package recovery contains pure, fail-closed decisions for Runtime's view of
// EngageGuard operations. It does not dispatch or reconcile provider side effects.
package recovery

// OperationState is a Guard-owned state observed by Runtime, never its authority.
type OperationState string

const (
	StateRequested       OperationState = "REQUESTED"
	StateWaitingApproval OperationState = "WAITING_APPROVAL"
	StateAuthorized      OperationState = "AUTHORIZED"
	StateClaimed         OperationState = "CLAIMED"
	StateDispatching     OperationState = "DISPATCHING"
	StateUnknown         OperationState = "UNKNOWN"
	StateReconciling     OperationState = "RECONCILING"
	StateManualReview    OperationState = "MANUAL_REVIEW"
	StateSucceeded       OperationState = "SUCCEEDED"
	StateFailedConfirmed OperationState = "FAILED_CONFIRMED"
	StateRejected        OperationState = "REJECTED"
	StateDenied          OperationState = "DENIED"
	StateExpired         OperationState = "EXPIRED"
	StateCancelled       OperationState = "CANCELLED"
)

// NextStep is a Runtime-side action; none of these values triggers provider I/O.
type NextStep string

const (
	StepWait         NextStep = "WAIT"
	StepReconcile    NextStep = "QUERY_GUARD_RECONCILIATION"
	StepManualReview NextStep = "MANUAL_REVIEW"
	StepContinue     NextStep = "CONTINUE_WORKFLOW"
	StepStop         NextStep = "STOP"
)

// GuardOperationNextStep never treats UNKNOWN or missing evidence as failure.
// Only a verifiable Guard receipt permits continuing after SUCCEEDED.
func GuardOperationNextStep(state OperationState, receiptVerified bool) NextStep {
	switch state {
	case StateRequested, StateWaitingApproval, StateAuthorized, StateClaimed, StateDispatching:
		return StepWait
	case StateUnknown, StateReconciling:
		return StepReconcile
	case StateManualReview:
		return StepManualReview
	case StateSucceeded:
		if receiptVerified {
			return StepContinue
		}
		return StepReconcile
	case StateFailedConfirmed, StateRejected, StateDenied, StateExpired, StateCancelled:
		return StepStop
	default:
		return StepStop
	}
}

// EnsureRecord is a durably persisted Runtime submission correlation. Its key
// must predate the network request, and the digest identifies immutable intent.
type EnsureRecord struct {
	Key           string
	RequestDigest string
	State         OperationState
}

type EnsureRequest struct {
	Key           string
	RequestDigest string
}

type EnsureDecision string

const (
	EnsureResubmit  EnsureDecision = "RESUBMIT_SAME_IDEMPOTENT_GUARD_REQUEST"
	EnsureQueryOnly EnsureDecision = "QUERY_EXISTING_GUARD_OPERATION"
	EnsureReject    EnsureDecision = "REJECT"
)

// DecideEnsureRetry is ONLY about resending a Guard idempotent HTTP submission,
// never calling Trusted Executor. Once Guard's action operation is known to be
// dispatched/ambiguous, only an authoritative status query is safe.
func DecideEnsureRetry(original EnsureRecord, candidate EnsureRequest) EnsureDecision {
	if original.Key == "" || original.RequestDigest == "" ||
		candidate.Key != original.Key || candidate.RequestDigest != original.RequestDigest {
		return EnsureReject
	}

	switch original.State {
	case StateRequested, StateWaitingApproval, StateAuthorized:
		return EnsureResubmit
	case StateClaimed, StateDispatching, StateUnknown, StateReconciling,
		StateManualReview, StateSucceeded:
		return EnsureQueryOnly
	case StateFailedConfirmed, StateRejected, StateDenied, StateExpired, StateCancelled:
		return EnsureReject
	default:
		return EnsureReject
	}
}
