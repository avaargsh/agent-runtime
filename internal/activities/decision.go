package activities

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/avaargsh/agent-runtime/internal/breaker"
	"github.com/avaargsh/agent-runtime/internal/decision"
	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/securitycontext"
	"go.temporal.io/sdk/temporal"
)

var (
	ErrBreakerGuardUnavailable = errors.New("Run breaker guard is unavailable")
	ErrRunIdentityUnavailable  = errors.New("trusted Run identity resolver is unavailable")
	ErrRunIdentityMismatch     = errors.New("Workflow Run identity does not match persisted Runtime identity")
	ErrRunPrincipalUnavailable = errors.New("trusted Runtime principal snapshot is unavailable")
)

type DecisionInvoker interface {
	Invoke(ctx context.Context, turn decision.Turn, identity run.Identity) (decision.Result, error)
}

type BreakerReader interface {
	GetRunBreaker(ctx context.Context, tenantID, runID string) (breaker.Record, error)
}

type RunIdentityReader interface {
	GetRunIdentity(ctx context.Context, runID string) (run.Identity, error)
}

type RunPrincipalReader interface {
	GetRunPrincipalSnapshot(context.Context, string, string) (run.PrincipalSnapshot, error)
}

type Activities struct {
	Client       DecisionInvoker
	Breakers     BreakerReader
	Runs         RunIdentityReader
	Principals    RunPrincipalReader
	Execution     TemporalExecutionResolver
	TemporalTurns TemporalTurnWriter
	PollInterval  time.Duration
}

// InvokeDecision resolves canonical identity from the Runtime Run store before
// breaker checks or external egress. Workflow-supplied tenant/Agent fields are
// correlation claims only and must match the persisted Run row.
func (a *Activities) InvokeDecision(ctx context.Context, turn decision.Turn) (decision.Result, error) {
	var empty decision.Result
	if a == nil || a.Client == nil || a.Breakers == nil {
		return empty, ErrBreakerGuardUnavailable
	}
	if a.Runs == nil {
		return empty, ErrRunIdentityUnavailable
	}
	if err := turn.Validate(); err != nil {
		return empty, err
	}

	identity, err := a.Runs.GetRunIdentity(ctx, turn.RunID)
	if err != nil {
		return empty, fmt.Errorf("resolve persisted Runtime Run identity: %w", err)
	}
	if err := identity.Validate(); err != nil {
		return empty, nonRetryableRunIdentityError(err)
	}
	if identity.RunID != turn.RunID || identity.TenantID != turn.TenantID || identity.AgentID != turn.AgentID {
		return empty, nonRetryableRunIdentityError(ErrRunIdentityMismatch)
	}
	if a.Principals == nil {
		return empty, ErrRunPrincipalUnavailable
	}
	// Resolve principal only from the authoritative Runtime store after
	// canonical Run identity resolution; never use untrusted Workflow input.
	// This is a necessary-only gate, not a policy decision or audit receipt.
	principal, err := a.Principals.GetRunPrincipalSnapshot(ctx, identity.TenantID, identity.RunID)
	if err != nil {
		return empty, nonRetryableRunPrincipalError(err)
	}
	if err := principal.Validate(); err != nil {
		return empty, nonRetryableRunPrincipalError(err)
	}

	if a.Execution == nil || a.TemporalTurns == nil {
		return empty, ErrTemporalExecutionUnavailable
	}
	execution, err := a.Execution.Resolve(ctx)
	if err != nil {
		return empty, nonRetryableTemporalIdentityError(fmt.Errorf("%w: %v", ErrTemporalExecutionUnavailable, err))
	}
	expectedWorkflowID := run.ACPWorkflowPrefix + identity.RunID
	if execution.WorkflowID != expectedWorkflowID || execution.ExecutionID == "" {
		return empty, nonRetryableTemporalIdentityError(ErrTemporalIdentityMismatch)
	}
	temporalTurn, err := a.TemporalTurns.GetOrCreateTemporalTurn(
		ctx, identity.TenantID, identity.RunID, execution.WorkflowID, execution.ExecutionID, 1,
	)
	if err != nil {
		return empty, fmt.Errorf("persist server-bound Runtime Temporal Turn identity: %w", err)
	}
	if err := temporalTurn.Validate(); err != nil ||
		temporalTurn.TenantID != identity.TenantID ||
		temporalTurn.RunID != identity.RunID ||
		temporalTurn.WorkflowID != execution.WorkflowID ||
		temporalTurn.TemporalExecutionID != execution.ExecutionID ||
		temporalTurn.TurnIndex != 1 {
		return empty, nonRetryableTemporalIdentityError(ErrTemporalIdentityMismatch)
	}

	// Workflow-supplied turn/invocation IDs are correlation hints only.
	// Replace them with Runtime-owned IDs bound to the Temporal Server
	// execution before any external egress.
	turn.TurnID = temporalTurn.TurnID
	turn.InvocationID = temporalTurn.InvocationID
	trustedContext, err := securitycontext.New(securitycontext.Claims{
		TenantID: identity.TenantID, SubjectID: principal.SubjectID, ActorID: principal.ActorID,
		AgentID: identity.AgentID, AgentReleaseID: identity.AgentReleaseID,
		SessionID: identity.SessionID, RunID: identity.RunID,
		RunAttemptID: temporalTurn.RunAttemptID, TurnID: temporalTurn.TurnID,
		PolicyRevision: principal.PolicyRevision,
	})
	if err != nil {
		return empty, nonRetryableRunPrincipalError(err)
	}
	ctx = securitycontext.WithContext(ctx, trustedContext)

	initial, err := a.Breakers.GetRunBreaker(ctx, identity.TenantID, identity.RunID)
	if err != nil {
		return empty, nonRetryableBreakerError(fmt.Errorf("load Run breaker before Decision egress: %w", err))
	}
	expectedEpoch := initial.Epoch
	if err := initial.Check(expectedEpoch, breaker.EffectReadOnly); err != nil {
		return empty, nonRetryableBreakerError(err)
	}

	interval := a.PollInterval
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	requestCtx, cancelRequest := context.WithCancel(ctx)
	watchCtx, stopWatcher := context.WithCancel(ctx)
	watcherDone := make(chan struct{})
	breakerErrors := make(chan error, 1)

	go func() {
		defer close(watcherDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-ticker.C:
				current, err := a.Breakers.GetRunBreaker(watchCtx, identity.TenantID, identity.RunID)
				if err != nil {
					if watchCtx.Err() != nil {
						return
					}
					select {
					case breakerErrors <- fmt.Errorf("Run breaker became unavailable during Decision egress: %w", err):
					default:
					}
					cancelRequest()
					return
				}
				if err := current.Check(expectedEpoch, breaker.EffectReadOnly); err != nil {
					select {
					case breakerErrors <- err:
					default:
					}
					cancelRequest()
					return
				}
			}
		}
	}()

	result, invokeErr := a.Client.Invoke(requestCtx, turn, identity)
	stopWatcher()
	cancelRequest()
	<-watcherDone

	select {
	case err := <-breakerErrors:
		return empty, nonRetryableBreakerError(err)
	default:
	}
	if ctx.Err() != nil {
		return empty, ctx.Err()
	}
	// Fast replies may beat the first periodic poll. Revalidate the breaker
	// fencing epoch using the persisted Runtime Run identity after egress.
	postflight, err := a.Breakers.GetRunBreaker(ctx, identity.TenantID, identity.RunID)
	if err != nil {
		return empty, nonRetryableBreakerError(fmt.Errorf("load Run breaker after Decision egress: %w", err))
	}
	if err := postflight.Check(expectedEpoch, breaker.EffectReadOnly); err != nil {
		return empty, nonRetryableBreakerError(err)
	}
	if invokeErr != nil {
		return empty, invokeErr
	}
	if err := result.Validate(turn); err != nil {
		return empty, err
	}
	return result, nil
}

func nonRetryableBreakerError(cause error) error {
	return temporal.NewNonRetryableApplicationError(
		"Run circuit breaker blocked or interrupted Decision Activity",
		"RUN_BREAKER_BLOCKED",
		cause,
	)
}

func nonRetryableRunPrincipalError(cause error) error {
	return temporal.NewNonRetryableApplicationError(
		"Decision Activity cannot execute without an immutable trusted Run principal",
		"RUN_PRINCIPAL_UNAVAILABLE",
		cause,
	)
}

func nonRetryableTemporalIdentityError(cause error) error {
	return temporal.NewNonRetryableApplicationError(
		"Decision Activity rejected an untrusted or mismatched Temporal execution identity",
		"TEMPORAL_EXECUTION_UNTRUSTED",
		cause,
	)
}

func nonRetryableRunIdentityError(cause error) error {
	return temporal.NewNonRetryableApplicationError(
		"Decision Activity rejected an untrusted or inconsistent Run identity",
		"RUN_IDENTITY_MISMATCH",
		cause,
	)
}
