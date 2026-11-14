package decision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"time"
	"unicode/utf8"

	"github.com/avaargsh/agent-runtime/internal/audit"
	"github.com/avaargsh/agent-runtime/internal/dataprotection"
	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/avaargsh/agent-runtime/internal/securitycontext"
	"github.com/google/uuid"
)

const (
	maxResponseBytes                   = 8192
	DecisionModelAudience              = "model-provider"
	DecisionUserAudience               = "runtime-user"
	DecisionUserVisibleResponsePurpose = "user-visible-response"
)

var (
	ErrDataProtectionUnavailable  = errors.New("Decision data protection is unavailable")
	ErrRunIdentityMismatch        = errors.New("Decision Run identity does not match persisted Runtime identity")
	ErrSecurityContextUnavailable = errors.New("trusted Decision SecurityContext is unavailable")
)

// DataProtector is the mandatory egress and response boundary. Implementations
// must fail closed on detector, Vault or authorization errors.
type DataProtector interface {
	ProtectOutbound(ctx context.Context, scope dataprotection.Scope, audience string, payload []byte) ([]byte, error)
	RestoreInbound(ctx context.Context, scope dataprotection.Scope, audience, purpose string, payload []byte) ([]byte, error)
}

type Client struct {
	Endpoint  string
	HTTP      *http.Client
	Protector DataProtector
	Audit     audit.Recorder
}

func validateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid decision endpoint")
	}
	// Plain HTTP is confined to a development loopback address. Production
	// connections use HTTPS with workload authentication at the network boundary.
	if u.Scheme == "http" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return errors.New("plaintext decision endpoint must be loopback")
		}
	}
	return nil
}

// Invoke sends only protected user input to the remote Decision plugin. The
// supplied identity must have been resolved from Runtime's persisted Run row
// by the calling Activity; fields inside Turn are checked as correlation data.
func (c Client) Invoke(ctx context.Context, turn Turn, identity run.Identity) (Result, error) {
	var result Result
	if err := turn.Validate(); err != nil {
		return result, err
	}
	if err := identity.Validate(); err != nil {
		return result, fmt.Errorf("invalid trusted Run identity: %w", err)
	}
	if identity.RunID != turn.RunID || identity.TenantID != turn.TenantID || identity.AgentID != turn.AgentID {
		return result, ErrRunIdentityMismatch
	}
	if c.Protector == nil {
		return result, ErrDataProtectionUnavailable
	}
	if err := validateEndpoint(c.Endpoint); err != nil {
		return result, err
	}
	trustedContext, ok := securitycontext.FromContext(ctx)
	if !ok {
		return result, ErrSecurityContextUnavailable
	}
	claims := trustedContext.Claims()
	if claims.TenantID != identity.TenantID || claims.AgentID != identity.AgentID ||
		claims.AgentReleaseID != identity.AgentReleaseID || claims.SessionID != identity.SessionID ||
		claims.RunID != identity.RunID {
		return result, ErrRunIdentityMismatch
	}

	scope := dataprotection.Scope{TenantID: identity.TenantID, RunID: identity.RunID}
	protectedInput, err := c.Protector.ProtectOutbound(
		ctx,
		scope,
		DecisionModelAudience,
		[]byte(turn.UserInput),
	)
	if err != nil {
		return result, fmt.Errorf("protect Decision request before egress: %w", err)
	}
	outboundTurn := turn
	outboundTurn.UserInput = string(protectedInput)
	payload, err := json.Marshal(outboundTurn)
	if err != nil {
		return result, err
	}
	payloadDigest := sha256.Sum256(payload)
	if err := audit.AppendChecked(ctx, c.Audit, audit.Event{
		EventID:       uuid.NewString(),
		OccurredAt:    time.Now().UTC(),
		Type:          audit.EventModelRequestPrepared,
		Identity:      trustedContext,
		Source:        "agent-runtime/decision-client",
		Action:        "MODEL_REQUEST",
		Resource:      DecisionModelAudience,
		Outcome:       audit.OutcomePending,
		PayloadDigest: "sha256:" + hex.EncodeToString(payloadDigest[:]),
	}); err != nil {
		return result, fmt.Errorf("persist model egress audit before HTTP request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	h := c.HTTP
	if h == nil {
		h = &http.Client{Timeout: 15 * time.Second}
	}
	// Do not permit the standard client's redirect behavior to forward a
	// decision request to a different authority.
	restricted := *h
	restricted.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := restricted.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("decision plugin returned HTTP %d", resp.StatusCode)
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return result, errors.New("invalid response content type")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return result, err
	}
	if len(body) > maxResponseBytes {
		return result, errors.New("decision result too large")
	}
	result, err = strictResult(body)
	if err != nil {
		return Result{}, err
	}
	if err = result.Validate(turn); err != nil {
		return Result{}, err
	}

	restoredText, err := c.Protector.RestoreInbound(
		ctx,
		scope,
		DecisionUserAudience,
		DecisionUserVisibleResponsePurpose,
		[]byte(result.Text),
	)
	if err != nil {
		return Result{}, fmt.Errorf("restore authorized Decision response: %w", err)
	}
	result.Text = string(restoredText)
	if err = result.Validate(turn); err != nil {
		return Result{}, fmt.Errorf("validate restored Decision response: %w", err)
	}
	return result, nil
}

// strictResult rejects duplicate, unknown, non-string and missing fields.
func strictResult(body []byte) (Result, error) {
	var result Result
	if !utf8.Valid(body) {
		return result, errors.New("invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return result, errors.New("expected result object")
	}
	seen := make(map[string]bool, 4)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return result, err
		}
		key, ok := keyToken.(string)
		if !ok || seen[key] {
			return result, errors.New("duplicate or invalid result key")
		}
		seen[key] = true
		var value string
		if err := decoder.Decode(&value); err != nil {
			return result, err
		}
		switch key {
		case "protocol_version":
			result.ProtocolVersion = value
		case "invocation_id":
			result.InvocationID = value
		case "kind":
			result.Kind = value
		case "text":
			result.Text = value
		default:
			return result, errors.New("unexpected decision result field")
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return result, errors.New("invalid result terminator")
	}
	if len(seen) != 4 {
		return result, errors.New("missing decision result field")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return result, errors.New("trailing decision result data")
	}
	return result, nil
}
