package decision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	Endpoint string
	HTTP *http.Client
}

func (c Client) Invoke(ctx context.Context, turn Turn) (Result, error) {
	var result Result
	if err := turn.Validate(); err != nil { return result, err }
	u, err := url.Parse(c.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return result, errors.New("invalid decision endpoint")
	}
	payload, err := json.Marshal(turn)
	if err != nil { return result, err }
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(payload))
	if err != nil { return result, err }
	req.Header.Set("Content-Type", "application/json")
	client := c.HTTP
	if client == nil { client = &http.Client{Timeout: 15 * time.Second} }
	resp, err := client.Do(req)
	if err != nil { return result, err }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return result, errors.New("decision plugin returned non-200") }
	if resp.ContentLength > 8192 { return result, errors.New("decision result too large") }
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 8193))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil { return result, err }
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF { return Result{}, errors.New("trailing decision response data") }
	if err := result.Validate(turn); err != nil { return Result{}, err }
	return result, nil
}
