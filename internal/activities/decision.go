package activities

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/avaargsh/agent-runtime/internal/breaker"
	"github.com/avaargsh/agent-runtime/internal/decision"
	"github.com/avaargsh/agent-runtime/internal/run"
	"go.temporal.io/sdk/temporal"
)

var (
	ErrBreakerGuardUnavailable = errors.New("Run breaker guard is unavailable")
	ErrRunIdentityUnavailable  = errors.New("trusted Run identity resolver is unavailable")
	ErrRunIdentityMismatch     = errors.New("Workflow Run identity does not match persisted Runtime identity")
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

type Activities struct {
	Client       DecisionInvoker
	Breakers     BreakerReader
	Runs         RunIdentityReader
	PollInterval time.Duration
}

// InvokeDecision resolves canonical identity from the Runtime Run store before
// breaker checks or external egress. Workflow-supplied tenant/Agent fields are
// correlation claims only and must match the persisted Run row.
func (a *Activities) InvokeDecision(ctx context.Context, turn decision.Turn) (decision.Result, error) {
	var empty decision.Result
	if a == nil || a.Client == nil || a.Breakers == nil || a.Runs == nil {
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

func nonRetryableRunIdentityError(cause error) error {
	return temporal.NewNonRetryableApplicationError(
		"Decision Activity rejected an untrusted or inconsistent Run identity",
		"RUN_IDENTITY_MISMATCH",
		cause,
	)
}
