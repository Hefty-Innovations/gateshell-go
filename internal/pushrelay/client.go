// Package pushrelay talks to the GateShell push relay (gateshell.com/api/push/*
// by default, self-hostable) so this agent never needs to hold an Apple
// APNs credential itself. The relay is the only thing that ever calls
// Apple; this package's job is a small, authenticated HTTPS client to it.
//
// Trust model: the relay is stateless -- it stores nothing between requests.
// Every Send call carries the device token itself (kept locally by this
// agent, see TokenStore), so the relay never needs a database, a
// registration step, or a writable directory at all. Token (the bearer
// credential) is a high-entropy secret the operator generates once (e.g.
// `openssl rand -hex 32`) and configures on both this agent
// (--push-relay-token / GATESHELL_AGENT_PUSH_RELAY_TOKEN / config file) and
// nowhere else; it is never sent anywhere but the relay, over HTTPS. It does
// NOT authorize delivery to a specific device -- the relay is open-source
// and its binaries are public, so nothing it holds can prove "this request
// is really from a legitimate install." What actually protects a device is
// its own APNs token: 256 bits, unguessable, HTTPS-only in transit, never
// logged. The bearer token's job is narrower: give the relay's rate
// limiter a stable per-install key so it can reject a runaway agent
// without one bad actor exhausting everyone else's quota.
package pushrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL is GateShell's own hosted relay. Self-hosters running
// their own relay override it via --push-relay-url /
// GATESHELL_AGENT_PUSH_RELAY_URL.
const DefaultBaseURL = "https://gateshell.com"

// ErrNoDevices reports that no device has registered for push with this
// agent, so there was nothing to deliver. Not a failure -- but not a
// delivery either, and callers log the two differently.
var ErrNoDevices = errors.New("pushrelay: no device registered")

// ErrTokenUnregistered means APNs considers this device token permanently
// dead -- the app was deleted, or the token was replaced. The caller should
// drop it rather than retry.
var ErrTokenUnregistered = errors.New("pushrelay: device token is no longer registered")

// Client is a thin, authenticated HTTP client for the relay's push API.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewClient builds a Client. An empty baseURL uses DefaultBaseURL.
//
// baseURL must be https:// -- Token is a bearer credential sent on every
// request, so this refuses to construct a client that would send it over
// plaintext HTTP, even to a self-hosted relay (put a TLS-terminating proxy
// in front of it; this is not negotiable for a credential in transit).
func NewClient(baseURL, token string) (*Client, error) {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("pushrelay: invalid relay URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("pushrelay: relay URL must use https, got %q", parsed.Scheme)
	}
	if token == "" {
		return nil, fmt.Errorf("pushrelay: token must not be empty")
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		token:      token,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Send asks the relay to push a notification with the given title/body to
// deviceToken. The relay stores nothing -- deviceToken travels on every
// call, and so does environment, which tells the relay whether to reach
// Apple's production or sandbox host (a development-signed app's token is
// only valid against sandbox, and vice versa).
func (c *Client) Send(ctx context.Context, deviceToken, environment, title, body string) error {
	return c.post(ctx, "/api/push/send", map[string]string{
		"deviceToken": deviceToken,
		"environment": NormalizeEnvironment(environment),
		"title":       title,
		"body":        body,
	})
}

// SendMetrics delivers a silent, user-invisible push carrying one sample, so
// the iOS Health widget can refresh on this agent's poll cycle instead of only
// when the app is open. Separate endpoint from Send because the relay has to
// use different APNs semantics (background push type, priority 5, no alert).
func (c *Client) SendMetrics(ctx context.Context, deviceToken, environment string, m WidgetMetrics) error {
	payload := map[string]any{
		"deviceToken": deviceToken,
		"environment": NormalizeEnvironment(environment),
		"serverName":  m.ServerName,
		"cpuPercent":  m.CPUPercent,
		"capturedAt":  m.CapturedAt.Unix(),
	}
	if m.MemoryPercent != nil {
		payload["memoryPercent"] = *m.MemoryPercent
	}
	if m.DiskUsePercent != nil {
		payload["diskUsePercent"] = *m.DiskUsePercent
	}
	return c.post(ctx, "/api/push/metrics", payload)
}

func (c *Client) post(ctx context.Context, path string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("pushrelay: marshaling payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("pushrelay: building request: %w", err)
	}
	req.Header.Set("authorization", "Bearer "+c.token)
	req.Header.Set("content-type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pushrelay: request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusGone {
		return ErrTokenUnregistered
	}
	if resp.StatusCode >= 300 {
		// Deliberately don't surface the response body for auth failures --
		// it's the relay's response, not our own secret, but there's no
		// reason to echo arbitrary server-controlled text into agent logs
		// either. Non-auth failures include a short, size-capped snippet to
		// aid debugging.
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return fmt.Errorf("pushrelay: %s rejected our token (status %d)", path, resp.StatusCode)
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("pushrelay: %s returned status %d: %s", path, resp.StatusCode, string(respBody))
	}
	return nil
}
