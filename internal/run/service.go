package run

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

var (
	ErrInvalidRequest        = errors.New("invalid StartRun request")
	ErrIdempotencyConflict   = errors.New("idempotency key was already used with a different request")
	ErrRepositoryUnavailable = errors.New("run repository is unavailable")
)

const (
	WorkflowIDPrefix = "agent-run/"
	maxInputBytes    = 256 * 1024
	maxIdentifierLen = 255
)

type Status string

const (
	StatusQueued    Status = "QUEUED"
	StatusRunning   Status = "RUNNING"
	StatusSucceeded Status = "SUCCEEDED"
	StatusFailed    Status = "FAILED"
	StatusCancelled Status = "CANCELLED"
)

type StartRequest struct {
	TenantID       string          `json:"tenant_id"`
	AgentID        string          `json:"agent_id"`
	AgentReleaseID string          `json:"agent_release_id"`
	SessionID      string          `json:"session_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	Input          json.RawMessage `json:"input"`
}

type Run struct {
	ID             string          `json:"run_id"`
	TenantID       string          `json:"tenant_id"`
	AgentID        string          `json:"agent_id"`
	AgentReleaseID string          `json:"agent_release_id"`
	SessionID      string          `json:"session_id"`
	IdempotencyKey string          `json:"-"`
	RequestDigest  string          `json:"-"`
	WorkflowID     string          `json:"workflow_id"`
	Status         Status          `json:"status"`
	Input          json.RawMessage `json:"input"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

type StartResult struct {
	Run     Run  `json:"run"`
	Created bool `json:"created"`
}

type Repository interface {
	// CreateOrGet atomically creates a Run and its workflow-start outbox record.
	// It returns the canonical existing Run for an identical idempotent request.
	CreateOrGet(ctx context.Context, candidate Run) (Run, bool, error)
}

type Service struct {
	repository Repository
	now        func() time.Time
	newID      func() string
}

func NewService(repository Repository) *Service {
	return &Service{
		repository: repository,
		now:        time.Now,
		newID:      uuid.NewString,
	}
}

func (s *Service) Start(ctx context.Context, request StartRequest) (StartResult, error) {
	if s == nil || s.repository == nil {
		return StartResult{}, ErrRepositoryUnavailable
	}

	normalized, err := normalizeRequest(request)
	if err != nil {
		return StartResult{}, err
	}

	digest, err := requestDigest(normalized)
	if err != nil {
		return StartResult{}, fmt.Errorf("digest StartRun request: %w", err)
	}

	runID := s.newID()
	now := s.now().UTC()
	candidate := Run{
		ID:             runID,
		TenantID:       normalized.TenantID,
		AgentID:        normalized.AgentID,
		AgentReleaseID: normalized.AgentReleaseID,
		SessionID:      normalized.SessionID,
		IdempotencyKey: normalized.IdempotencyKey,
		RequestDigest:  digest,
		WorkflowID:     WorkflowIDPrefix + runID,
		Status:         StatusQueued,
		Input:          normalized.Input,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	persisted, created, err := s.repository.CreateOrGet(ctx, candidate)
	if err != nil {
		return StartResult{}, err
	}
	return StartResult{Run: persisted, Created: created}, nil
}

func normalizeRequest(request StartRequest) (StartRequest, error) {
	fields := map[string]string{
		"tenant_id":        request.TenantID,
		"agent_id":         request.AgentID,
		"agent_release_id": request.AgentReleaseID,
		"session_id":       request.SessionID,
		"idempotency_key":  request.IdempotencyKey,
	}
	for name, value := range fields {
		if value == "" || strings.TrimSpace(value) != value ||
			len(value) > maxIdentifierLen || !utf8.ValidString(value) ||
			strings.ContainsRune(value, '\x00') {
			return StartRequest{}, fmt.Errorf("%w: %s is empty or malformed", ErrInvalidRequest, name)
		}
	}

	input, err := canonicalObject(request.Input)
	if err != nil {
		return StartRequest{}, fmt.Errorf("%w: input must be a JSON object: %v", ErrInvalidRequest, err)
	}
	request.Input = input
	return request, nil
}

func canonicalObject(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return json.RawMessage("{}"), nil
	}
	if len(raw) > maxInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxInputBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, errors.New("top-level JSON value must be an object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("multiple JSON values are not allowed")
		}
		return nil, err
	}

	canonical, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

func requestDigest(request StartRequest) (string, error) {
	payload := struct {
		TenantID       string          `json:"tenant_id"`
		AgentID        string          `json:"agent_id"`
		AgentReleaseID string          `json:"agent_release_id"`
		SessionID      string          `json:"session_id"`
		Input          json.RawMessage `json:"input"`
	}{
		TenantID:       request.TenantID,
		AgentID:        request.AgentID,
		AgentReleaseID: request.AgentReleaseID,
		SessionID:      request.SessionID,
		Input:          request.Input,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
