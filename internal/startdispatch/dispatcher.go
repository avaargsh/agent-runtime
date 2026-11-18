// Package startdispatch implements a development-only Outbox to Temporal
// admission probe. It must only use an isolated namespace, database and
// worker; it does not run the production Decision workflow or model/tools.
package startdispatch

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/google/uuid"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
)

const (
	DevelopmentQueue    = "runtime-admission-development-v1"
	DevelopmentWorkflow = "RuntimeAdmissionProbeV1"
)

var (
	ErrInvalidConfig     = errors.New("invalid development start dispatcher configuration")
	ErrUnverifiedStart   = errors.New("Temporal start outcome is unverified")
	ErrExecutionConflict = errors.New("Temporal start history differs from the committed Runtime binding")
)

type StartStore interface {
	ClaimRuntimeStart(context.Context, string, time.Duration) (postgres.RuntimeStartLease, bool, error)
	AcknowledgeRuntimeStart(context.Context, postgres.RuntimeStartLease) error
	ReleaseRuntimeStart(context.Context, postgres.RuntimeStartLease, time.Duration) error
}

type ProbeInput struct {
	TenantID      string
	RunID         string
	RunIntentID   string
	RequestDigest string
	WorkflowID    string
}

func (p ProbeInput) validate() error {
	for _, v := range []string{p.RunID, p.RunIntentID} {
		id, err := uuid.Parse(v)
		if err != nil || id.String() != v {
			return ErrExecutionConflict
		}
	}
	if p.WorkflowID != run.ACPWorkflowPrefix+p.RunID ||
		(run.IntentStartRequest{TenantID: p.TenantID, RunIntentID: p.RunIntentID, RequestDigest: p.RequestDigest}).ValidateLookup() != nil {
		return ErrExecutionConflict
	}
	return nil
}

type Result struct {
	Found       bool
	Delivered   bool
	RunID       string
	ExecutionID string
}

// DispatchOnce leases exactly one persisted start event. The initial claim
// may submit the canonical Workflow ID; every later claim is inspect-only.
// Temporal retention expiry or a missing history is never proof of absence.
// The isolated dev path prioritizes safety over liveness: an ambiguous
// pre-send failure may require manual resolution, not automatic resubmission.
func DispatchOnce(ctx context.Context, store StartStore, c client.Client, owner string, ttl, retryDelay time.Duration) (Result, error) {
	if store == nil || c == nil || owner == "" || ttl < time.Second || ttl > 10*time.Minute ||
		retryDelay < time.Microsecond || retryDelay > time.Hour {
		return Result{}, ErrInvalidConfig
	}
	lease, found, err := store.ClaimRuntimeStart(ctx, owner, ttl)
	if err != nil || !found {
		return Result{}, err
	}
	result := Result{Found: true, RunID: lease.RunID}
	input := ProbeInput{
		TenantID: lease.TenantID, RunID: lease.RunID, RunIntentID: lease.RunIntentID,
		RequestDigest: lease.RequestDigest, WorkflowID: lease.WorkflowID,
	}
	// Keep network calls bounded; database lease compare-and-swap remains
	// authoritative for acknowledging or releasing after this deadline.
	workCtx, cancel := context.WithTimeout(ctx, ttl/2)
	defer cancel()
	fail := func(cause error) (Result, error) {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		return result, errors.Join(cause, store.ReleaseRuntimeStart(cleanup, lease, retryDelay))
	}
	if err := input.validate(); err != nil {
		return fail(err)
	}
	if lease.Attempt == 1 {
		execution, err := c.ExecuteWorkflow(workCtx, client.StartWorkflowOptions{
			ID:                                       input.WorkflowID,
			TaskQueue:                                DevelopmentQueue,
			WorkflowIDReusePolicy:                    enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
			WorkflowIDConflictPolicy:                 enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL,
			WorkflowExecutionErrorWhenAlreadyStarted: true,
			WorkflowExecutionTimeout:                 5 * time.Minute,
		}, DevelopmentWorkflow, input)
		if err != nil {
			// Even AlreadyStarted is not evidence that the existing Workflow
			// is ours. Persist uncertainty and verify history on the next lease.
			return fail(ErrUnverifiedStart)
		}
		if execution == nil || execution.GetID() != input.WorkflowID || execution.GetRunID() == "" {
			return fail(ErrExecutionConflict)
		}
		result.ExecutionID = execution.GetRunID()
	}
	executionID, err := verifyStart(workCtx, c, input, result.ExecutionID)
	if err != nil {
		return fail(err)
	}
	result.ExecutionID = executionID
	if err := store.AcknowledgeRuntimeStart(workCtx, lease); err != nil {
		return result, fmt.Errorf("persist verified Temporal start ACK: %w", err)
	}
	result.Delivered = true
	return result, nil
}

func verifyStart(ctx context.Context, c client.Client, input ProbeInput, expectedExecution string) (string, error) {
	description, err := c.DescribeWorkflowExecution(ctx, input.WorkflowID, expectedExecution)
	if err != nil || description == nil {
		return "", ErrUnverifiedStart
	}
	info := description.GetWorkflowExecutionInfo()
	execution := info.GetExecution()
	id := execution.GetRunId()
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.String() != id || execution.GetWorkflowId() != input.WorkflowID ||
		(expectedExecution != "" && id != expectedExecution) ||
		info.GetType().GetName() != DevelopmentWorkflow || info.GetTaskQueue() != DevelopmentQueue {
		return "", ErrExecutionConflict
	}
	history := c.GetWorkflowHistory(ctx, input.WorkflowID, id, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	if !history.HasNext() {
		return "", ErrUnverifiedStart
	}
	event, err := history.Next()
	if err != nil || event == nil {
		return "", ErrUnverifiedStart
	}
	started := event.GetWorkflowExecutionStartedEventAttributes()
	if event.GetEventId() != 1 || started == nil || started.GetWorkflowType().GetName() != DevelopmentWorkflow ||
		started.GetTaskQueue().GetName() != DevelopmentQueue ||
		started.GetOriginalExecutionRunId() != id || started.GetContinuedExecutionRunId() != "" ||
		len(started.GetInput().GetPayloads()) != 1 {
		return "", ErrExecutionConflict
	}
	var persisted ProbeInput
	if err := converter.GetDefaultDataConverter().FromPayloads(started.GetInput(), &persisted); err != nil || persisted != input {
		return "", ErrExecutionConflict
	}
	return id, nil
}
