// Package decisioncontinuation implements the bounded, authenticated Decision
// /verify read needed before the Runtime-owned immutable acceptance CAS.
// This is an observation, never a tool Permit or side-effect authorization.
package decisioncontinuation

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
	"github.com/google/uuid"
)

const (
	verifyPrefix = "/internal/v1/decision-turns/"
	maxReceiptBytes = 32 * 1024
)

var (
	// An unavailable or absent committed Decision is UNKNOWN, not final denial.
	ErrUnavailable = errors.New("Decision continuation verification unavailable")
	// A mismatched scope, source, schema or revoked authority is rejected.
	ErrRejected = errors.New("Decision continuation verification rejected")
)

type AcceptanceStore interface {
	AcceptDecisionContinuation(context.Context, run.DecisionAuthority, run.DecisionContinuationReceipt) (run.DecisionContinuationReceipt, error)
}

type Client struct {
	base *url.URL
	http *http.Client
	peer string
}

// NewClient requires a dedicated TLS 1.3 mTLS transport with a pinned trust
// bundle and client identity. Redirects are disabled to avoid leaking the
// request to another endpoint. The server SPIFFE ID is checked on every read.
func NewClient(endpoint string, client *http.Client, expectedPeer string) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || u.Opaque != "" || u.String() != endpoint ||
		strings.ContainsAny(u.Host, "\\ \t\r\n\x00") {
		return nil, ErrRejected
	}
	peerURI, err := url.Parse(expectedPeer)
	if err != nil || peerURI.Scheme != "spiffe" || peerURI.Host == "" ||
		peerURI.Port() != "" || peerURI.Path == "" || peerURI.Path == "/" ||
		peerURI.User != nil || peerURI.Opaque != "" || peerURI.RawPath != "" ||
		peerURI.RawQuery != "" || peerURI.ForceQuery || peerURI.Fragment != "" ||
		peerURI.String() != expectedPeer {
		return nil, ErrRejected
	}
	if client == nil {
		return nil, ErrRejected
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		return nil, ErrRejected
	}
	security := transport.TLSClientConfig
	if security.InsecureSkipVerify || security.MinVersion < tls.VersionTLS13 ||
		security.RootCAs == nil ||
		(len(security.Certificates) == 0 && security.GetClientCertificate == nil) {
		return nil, ErrRejected
	}
	copyTransport := transport.Clone()
	copyClient := *client
	copyClient.Transport = copyTransport
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if copyClient.Timeout == 0 || copyClient.Timeout > 10*time.Second {
		copyClient.Timeout = 10 * time.Second
	}
	return &Client{base: u, http: &copyClient, peer: expectedPeer}, nil
}

func canonicalUUID(raw string) bool {
	u, err := uuid.Parse(raw)
	return err == nil && u.String() == raw
}

func (c *Client) trustedPeer(state *tls.ConnectionState) bool {
	if c == nil || state == nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 ||
		len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return false
	}
	leaf := state.PeerCertificates[0]
	if leaf == nil || leaf.IsCA || len(leaf.URIs) != 1 || leaf.URIs[0] == nil ||
		leaf.URIs[0].String() != c.peer || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return false
	}
	serverAuth := false
	for _, purpose := range leaf.ExtKeyUsage {
		serverAuth = serverAuth || purpose == x509.ExtKeyUsageServerAuth
	}
	if !serverAuth {
		return false
	}
	for _, chain := range state.VerifiedChains {
		if len(chain) > 0 && chain[0] != nil && chain[0].Equal(leaf) {
			return true
		}
	}
	return false
}

// Fetch obtains a fresh, scope-bound DecisionRecord revalidation receipt.
// HTTP 404 is absence-uncertain and MUST NOT be used as authority to replan
// or repeat an operation. A later protected action still requires Guard checks.
func (c *Client) Fetch(ctx context.Context, expected run.DecisionAuthority) (run.DecisionContinuationReceipt, error) {
	var empty run.DecisionContinuationReceipt
	if c == nil || c.http == nil || c.base == nil || expected.Validate() != nil ||
		!canonicalUUID(expected.RunID) || !canonicalUUID(expected.InvocationID) {
		return empty, ErrRejected
	}
	u := *c.base
	u.Path = verifyPrefix + expected.RunID + "/" + expected.InvocationID + "/verify"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return empty, ErrRejected
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	res, err := c.http.Do(req)
	if err != nil {
		return empty, ErrUnavailable
	}
	defer res.Body.Close()
	if !c.trustedPeer(res.TLS) || res.Header.Get("Cache-Control") != "no-store" {
		return empty, ErrRejected
	}
	if res.StatusCode == http.StatusNotFound || res.StatusCode >= 500 {
		return empty, ErrUnavailable
	}
	if res.StatusCode != http.StatusOK {
		return empty, ErrRejected
	}
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return empty, ErrRejected
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxReceiptBytes+1))
	if err != nil {
		return empty, ErrUnavailable
	}
	if len(body) == 0 || len(body) > maxReceiptBytes {
		return empty, ErrRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var receipt run.DecisionContinuationReceipt
	if decoder.Decode(&receipt) != nil || receipt.Validate() != nil || receipt.Authority != expected {
		return empty, ErrRejected
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return empty, ErrRejected
	}
	return receipt, nil
}

// VerifyAndAccept never accepts a caller-supplied receipt. The returned
// observation is retrieved over verified mTLS and then fenced again by the
// local transactional Run/Breaker CAS. This is not a distributed Permit.
func (c *Client) VerifyAndAccept(ctx context.Context, expected run.DecisionAuthority, store AcceptanceStore) (run.DecisionContinuationReceipt, error) {
	var empty run.DecisionContinuationReceipt
	if store == nil {
		return empty, ErrRejected
	}
	receipt, err := c.Fetch(ctx, expected)
	if err != nil {
		return empty, err
	}
	return store.AcceptDecisionContinuation(ctx, expected, receipt)
}
