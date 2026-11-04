package securitycontext

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var ErrInvalidContext = errors.New("invalid trusted security context")

// Claims are copied only from an authenticated principal and authoritative
// ACP/Runtime identity records. Agent Framework output is never a source.
type Claims struct {
	TenantID       string
	SubjectID      string
	ActorID        string
	AgentID        string
	AgentReleaseID string
	SessionID      string
	RunID          string
	RunAttemptID   string
	TurnID         string
	PolicyRevision string
}

// Context is an immutable-by-API identity chain. Fields remain unexported so
// callers must use New and cannot replace identifiers after validation.
type Context struct {
	tenantID       string
	subjectID      string
	actorID        string
	agentID        string
	agentReleaseID string
	sessionID      string
	runID          string
	runAttemptID   string
	turnID         string
	policyRevision string
}

func New(claims Claims) (Context, error) {
	fields := []struct {
		name  string
		value string
	}{
		{"tenant_id", claims.TenantID},
		{"subject_id", claims.SubjectID},
		{"actor_id", claims.ActorID},
		{"agent_id", claims.AgentID},
		{"agent_release_id", claims.AgentReleaseID},
		{"session_id", claims.SessionID},
		{"run_id", claims.RunID},
		{"run_attempt_id", claims.RunAttemptID},
		{"turn_id", claims.TurnID},
		{"policy_revision", claims.PolicyRevision},
	}
	for _, field := range fields {
		if !validIdentifier(field.value) {
			return Context{}, fmt.Errorf("%w: %s", ErrInvalidContext, field.name)
		}
	}
	return Context{
		tenantID:       claims.TenantID,
		subjectID:      claims.SubjectID,
		actorID:        claims.ActorID,
		agentID:        claims.AgentID,
		agentReleaseID: claims.AgentReleaseID,
		sessionID:      claims.SessionID,
		runID:          claims.RunID,
		runAttemptID:   claims.RunAttemptID,
		turnID:         claims.TurnID,
		policyRevision: claims.PolicyRevision,
	}, nil
}

func (c Context) Validate() error {
	_, err := New(c.Claims())
	return err
}

func (c Context) Claims() Claims {
	return Claims{
		TenantID:       c.tenantID,
		SubjectID:      c.subjectID,
		ActorID:        c.actorID,
		AgentID:        c.agentID,
		AgentReleaseID: c.agentReleaseID,
		SessionID:      c.sessionID,
		RunID:          c.runID,
		RunAttemptID:   c.runAttemptID,
		TurnID:         c.turnID,
		PolicyRevision: c.policyRevision,
	}
}

func (c Context) TenantID() string       { return c.tenantID }
func (c Context) SubjectID() string      { return c.subjectID }
func (c Context) ActorID() string        { return c.actorID }
func (c Context) AgentID() string        { return c.agentID }
func (c Context) AgentReleaseID() string { return c.agentReleaseID }
func (c Context) SessionID() string      { return c.sessionID }
func (c Context) RunID() string          { return c.runID }
func (c Context) RunAttemptID() string   { return c.runAttemptID }
func (c Context) TurnID() string         { return c.turnID }
func (c Context) PolicyRevision() string { return c.policyRevision }

type contextKey struct{}

// WithContext propagates a previously validated identity context through Go
// call boundaries. FromContext validates it again before returning it.
func WithContext(ctx context.Context, security Context) context.Context {
	return context.WithValue(ctx, contextKey{}, security)
}

func FromContext(ctx context.Context) (Context, bool) {
	if ctx == nil {
		return Context{}, false
	}
	security, ok := ctx.Value(contextKey{}).(Context)
	if !ok || security.Validate() != nil {
		return Context{}, false
	}
	return security, true
}

func validIdentifier(value string) bool {
	return value != "" &&
		strings.TrimSpace(value) == value &&
		len(value) <= 255 &&
		utf8.ValidString(value) &&
		!strings.ContainsRune(value, 0)
}
