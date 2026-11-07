package run

import (
	"net/url"
	"strings"
	"unicode/utf8"
)

// PrincipalSnapshot is a proposed, versioned ACP assertion. The issuer must
// be supplied by verified mTLS transport context, not from arbitrary JSON,
// forwarded headers, Workflow input, or an end-user bearer token.
type PrincipalSnapshot struct {
	Version        string
	IssuerSPIFFEID string
	ProjectID      string
	SubjectID      string
	ActorID        string
	PolicyRevision string
	ConfigDigest   string
}

func (p PrincipalSnapshot) Validate() error {
	if p.Version != "acp-principal/v1" || !sha256Digest.MatchString(p.ConfigDigest) {
		return ErrInvalidRequest
	}
	for _, value := range []string{p.ProjectID, p.SubjectID, p.ActorID, p.PolicyRevision} {
		if value == "" || len(value) > 255 || value != strings.TrimSpace(value) ||
			!utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n\t") {
			return ErrInvalidRequest
		}
	}
	u, err := url.Parse(p.IssuerSPIFFEID)
	if err != nil || u.Scheme != "spiffe" || u.Host == "" || u.Port() != "" ||
		u.Path == "" || u.Path == "/" || u.User != nil || u.Opaque != "" ||
		u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.String() != p.IssuerSPIFFEID {
		return ErrInvalidRequest
	}
	return nil
}
