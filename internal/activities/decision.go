package activities

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/avaargsh/agent-runtime/internal/breaker"
	"github.com/avaargsh/agent-runtime/internal/decision"
	"go.temporal.io/sdk/temporal"
)

var ErrBreakerGuardUnavailable = errors.New("Run breaker guard is unavailable")

type DecisionInvoker interface {
	Invoke(ctx context.Context, turn decision.Turn) (decision.Result, error)
}

type BreakerReader interface {
	GetBreaker(ctx context.Context, scope breaker.Scope) (breaker.Record, error)
}

type Activities struct {
	Client       DecisionInvoker
	Breakers     BreakerReader
	PollInterval time.Duration
}

// InvokeDecision checks the durable Run breaker before external egress and
// watches the same fencing epoch while the HTTP request is in flight. A state
// transition invalidates the Activity even when the breaker is later recovered.
func (a *Activities) InvokeDecision(ctx context.Context, turn decision.Turn) (decision.Result, error) {
	var empty decision.Result
	if a == nil || a.Client == nil || a.Breakers == nil {
		return empty, ErrBreakerGuardUnavailable
	}
	if err := turn.Validate(); err != nil {
		return empty, err
	}

	scope := breaker.Scope{Kind: breaker.ScopeRun, ID: turn.RunID}
	initial, err := a.Breakers.GetBreaker(ctx, scope)
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
				current, err := a.Breakers.GetBreaker(watchCtx, scope)
				if err != nil {
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

	result, invokeErr := a.Client.Invoke(requestCtx, turn)
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
