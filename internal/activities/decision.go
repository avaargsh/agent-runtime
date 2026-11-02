package activities

import (
	"context"

	"github.com/avaargsh/agent-runtime/internal/decision"
)

type Activities struct {
	Client decision.Client
}

func (a *Activities) InvokeDecision(ctx context.Context, turn decision.Turn) (decision.Result, error) {
	return a.Client.Invoke(ctx, turn)
}
