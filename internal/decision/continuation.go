package decision

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/avaargsh/agent-runtime/internal/run"
)

var ErrContinuationUnavailable = errors.New("fresh Decision continuation unavailable")

// ContinuationClient owns a deployment-pinned, reference-only Decision read.
// No caller-supplied transport, endpoint, proxy, redirect or cached response.
type ContinuationClient struct {
	origin string
	http   *http.Client
}

func NewContinuationClient(origin, peer string, roots *x509.CertPool, cert tls.Certificate) (*ContinuationClient, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" ||
		u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != origin {
		return nil, ErrContinuationUnavailable
	}
	id, err := url.Parse(peer)
	if err != nil || id.Scheme != "spiffe" || id.Host == "" || id.Port() != "" || id.Path == "" || id.Path == "/" ||
		id.User != nil || id.Opaque != "" || id.RawPath != "" || id.RawQuery != "" || id.ForceQuery || id.Fragment != "" || id.String() != peer ||
		roots == nil || len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return nil, ErrContinuationUnavailable
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs: roots.Clone(),
			Certificates: []tls.Certificate{cert},
			VerifyConnection: func(s tls.ConnectionState) error {
				if s.Version != tls.VersionTLS13 || len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 {
					return ErrContinuationUnavailable
				}
				leaf := s.PeerCertificates[0]
				now := time.Now()
				if leaf == nil || leaf.IsCA || len(leaf.URIs) != 1 || leaf.URIs[0] == nil || leaf.URIs[0].String() != peer ||
					now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
					return ErrContinuationUnavailable
				}
				for _, usage := range leaf.ExtKeyUsage {
					if usage == x509.ExtKeyUsageServerAuth {
						return nil
					}
				}
				return ErrContinuationUnavailable
			},
		},
	}
	return &ContinuationClient{origin: origin, http: &http.Client{
		Transport: tr, Timeout: 45 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// Verify fetches a freshly verified immutable record for the already bound
// invocation. Historical Inspect is deliberately not used and ABSENT never
// causes a Plan retry. No credential or evidence body enters this request.
func (c *ContinuationClient) Verify(ctx context.Context, expected run.DecisionAuthority) (run.DecisionContinuationReceipt, error) {
	var empty run.DecisionContinuationReceipt
	if c == nil || c.http == nil || expected.Validate() != nil {
		return empty, run.ErrDecisionPreparationDenied
	}
	path := "/internal/v1/decision-turns/" + expected.RunID + "/" + expected.InvocationID + "/verify"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+path, nil)
	if err != nil {
		return empty, ErrContinuationUnavailable
	}
	res, err := c.http.Do(req)
	if err != nil {
		return empty, ErrContinuationUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnauthorized {
		return empty, run.ErrDecisionPreparationDenied
	}
	if res.StatusCode != http.StatusOK || res.Header.Get("Cache-Control") != "no-store" ||
		res.Header.Get("Content-Type") != "application/json" {
		return empty, ErrContinuationUnavailable
	}
	const maxReceipt = 8192
	body, err := io.ReadAll(io.LimitReader(res.Body, maxReceipt+1))
	if err != nil || len(body) == 0 || len(body) > maxReceipt {
		return empty, ErrContinuationUnavailable
	}
	var receipt run.DecisionContinuationReceipt
	if json.Unmarshal(body, &receipt) != nil || receipt.Validate() != nil || receipt.Authority != expected {
		return empty, run.ErrDecisionPreparationDenied
	}
	// Canonical wire comparison rejects extra, duplicate, missing and
	// case-folded fields, even within nested Runtime authority.
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(body)) {
		return empty, run.ErrDecisionPreparationDenied
	}
	return receipt, nil
}
