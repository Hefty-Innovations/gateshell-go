package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Hefty-Innovations/gateshell-go/internal/alerts"
	"github.com/Hefty-Innovations/gateshell-go/internal/store"
)

// TestHealthzReportsVersion covers the mobile app's motivation for this
// field: checking the agent's version without an extra SSH round-trip to
// run `gateshell-agent version` directly (there is no other HTTP surface
// for it -- /api/v1/config only carries pollInterval).
func TestHealthzReportsVersion(t *testing.T) {
	st := store.NewMemoryStore(10)
	srv := NewServer(st, "token", "test-server", "v0.1.1", nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["version"] != "v0.1.1" {
		t.Errorf("expected version %q, got %q", "v0.1.1", body["version"])
	}
	if body["server"] != "test-server" {
		t.Errorf("expected server %q, got %q", "test-server", body["server"])
	}
	if body["status"] != "ok" {
		t.Errorf("expected status \"ok\", got %q", body["status"])
	}
}

// TestHealthzIsUnauthenticated documents that /healthz deliberately skips
// the bearer-token check (so uptime monitors can probe it) -- a request
// with no Authorization header must still succeed.
func TestHealthzIsUnauthenticated(t *testing.T) {
	st := store.NewMemoryStore(10)
	srv := NewServer(st, "token", "test-server", "dev", nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected /healthz to be reachable without a token, got %d", rec.Code)
	}
}

// alertsServer builds a Server wired to a real *alerts.Evaluator (rather
// than a fake) since Evaluator's Rules()/SetRules() already do exactly
// what RulesController needs -- no persistence in these tests
// (persistRules is nil), matching how handleGetConfig/handlePatchConfig
// are tested without a real config file.
func alertsServer(t *testing.T, testPublisher ...alerts.Publisher) *Server {
	t.Helper()
	st := store.NewMemoryStore(10)
	evaluator := alerts.NewEvaluator(nil, nil)
	var pub alerts.Publisher
	if len(testPublisher) > 0 {
		pub = testPublisher[0]
	}
	return NewServer(st, "token", "test-server", "dev", nil, nil, evaluator, nil, nil, nil, pub, nil, nil)
}

// fakePublisher is a bare in-memory alerts.Publisher for exercising
// POST /api/v1/alerts/test without a real APNs delivery path.
type fakePublisher struct {
	published []string
	err       error
}

func (f *fakePublisher) Publish(ctx context.Context, message string) error {
	f.published = append(f.published, message)
	return f.err
}

func authedRequest(method, path string, body []byte) *http.Request {
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Authorization", "Bearer token")
	return req
}

func TestGetAlertsReturnsEmptyRulesByDefault(t *testing.T) {
	srv := alertsServer(t)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/alerts", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload alertsPayload
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(payload.Rules) != 0 || len(payload.ServiceRules) != 0 {
		t.Errorf("expected no rules by default, got %+v", payload)
	}
}

func TestPatchAlertsAppliesRulesAtRuntime(t *testing.T) {
	srv := alertsServer(t)

	body, _ := json.Marshal(alertsPayload{
		Rules: []alerts.Rule{
			{Name: "High CPU", Metric: alerts.MetricCPUPercent, Comparator: alerts.ComparatorGreaterThan, Threshold: 90, For: 2 * time.Minute},
		},
	})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authedRequest(http.MethodPatch, "/api/v1/alerts", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Confirm it's actually live on the evaluator, not just echoed back.
	getRec := httptest.NewRecorder()
	srv.ServeHTTP(getRec, authedRequest(http.MethodGet, "/api/v1/alerts", nil))
	var payload alertsPayload
	if err := json.Unmarshal(getRec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(payload.Rules) != 1 || payload.Rules[0].Name != "High CPU" {
		t.Errorf("expected the rule to be live, got %+v", payload)
	}
	if payload.Rules[0].For != 2*time.Minute {
		t.Errorf("expected For to round-trip as 2m, got %s", payload.Rules[0].For)
	}
}

func TestPatchAlertsRejectsUnknownMetric(t *testing.T) {
	srv := alertsServer(t)

	body, _ := json.Marshal(alertsPayload{
		Rules: []alerts.Rule{
			{Name: "Bogus", Metric: "not_a_real_metric", Comparator: alerts.ComparatorGreaterThan, Threshold: 1},
		},
	})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authedRequest(http.MethodPatch, "/api/v1/alerts", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unknown metric, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPatchAlertsRejectsUnnamedRule(t *testing.T) {
	srv := alertsServer(t)

	body, _ := json.Marshal(alertsPayload{
		Rules: []alerts.Rule{
			{Metric: alerts.MetricCPUPercent, Comparator: alerts.ComparatorGreaterThan, Threshold: 1},
		},
	})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authedRequest(http.MethodPatch, "/api/v1/alerts", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a nameless rule, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAlertsEndpointsRequireAuth(t *testing.T) {
	srv := alertsServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil) // no Authorization header
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without a bearer token, got %d", rec.Code)
	}
}

// fakePushTokenStore is a bare in-memory PushTokenStore -- tests don't need
// a real pushrelay.RegisteringStore (which would make an actual HTTPS call)
// to exercise the HTTP layer. setErr, when non-nil, simulates the relay
// rejecting a registration.
type fakePushTokenStore struct {
	token       string
	environment string
	setErr      error
}

func (f *fakePushTokenStore) Labels() []string {
	if f.token == "" {
		return nil
	}
	return []string{"Test Device"}
}
func (f *fakePushTokenStore) Count() int {
	if f.token == "" {
		return 0
	}
	return 1
}
func (f *fakePushTokenStore) Set(token, environment, label string) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.token = token
	f.environment = environment
	return nil
}

func pushTokenServer(tokenStore PushTokenStore) *Server {
	st := store.NewMemoryStore(10)
	return NewServer(st, "token", "test-server", "dev", nil, nil, nil, nil, nil, tokenStore, nil, nil, nil)
}

func TestGetPushTokenReportsNotRegisteredByDefault(t *testing.T) {
	srv := pushTokenServer(&fakePushTokenStore{})

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/push-token", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var payload pushTokenPayload
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if payload.Registered {
		t.Error("expected registered=false with no token set")
	}
}

func TestPostPushTokenRegisters(t *testing.T) {
	fake := &fakePushTokenStore{}
	srv := pushTokenServer(fake)

	body, _ := json.Marshal(map[string]string{"token": "abc123devicetoken"})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authedRequest(http.MethodPost, "/api/v1/push-token", body))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if fake.token != "abc123devicetoken" {
		t.Errorf("expected the store to be updated, got %q", fake.token)
	}
}

// The app reports which APNs environment its own signed aps-environment
// entitlement says it is; a development-signed build's token is only
// valid against Apple's sandbox host, so this has to survive all the way
// from the app through the agent to the relay.
func TestPostPushTokenRecordsEnvironment(t *testing.T) {
	fake := &fakePushTokenStore{}
	srv := pushTokenServer(fake)

	body, _ := json.Marshal(map[string]string{"token": "abc123devicetoken", "environment": "development"})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authedRequest(http.MethodPost, "/api/v1/push-token", body))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if fake.environment != "development" {
		t.Errorf("expected environment to be recorded, got %q", fake.environment)
	}
}

func TestPostPushTokenSurfacesStoreFailure(t *testing.T) {
	fake := &fakePushTokenStore{setErr: errors.New("relay rejected token")}
	srv := pushTokenServer(fake)

	body, _ := json.Marshal(map[string]string{"token": "abc123devicetoken"})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authedRequest(http.MethodPost, "/api/v1/push-token", body))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when the store rejects the token, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPostPushTokenRejectsEmptyToken(t *testing.T) {
	srv := pushTokenServer(&fakePushTokenStore{})

	body, _ := json.Marshal(map[string]string{"token": ""})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authedRequest(http.MethodPost, "/api/v1/push-token", body))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an empty token, got %d", rec.Code)
	}
}

func TestPushTokenEndpointsUnavailableWithoutController(t *testing.T) {
	srv := alertsServer(t) // no pushTokenCtl wired up

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/push-token", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when push isn't configured, got %d", rec.Code)
	}
}

// MARK: - Test alert

func TestPostTestAlertPublishesFixedMessage(t *testing.T) {
	pub := &fakePublisher{}
	srv := alertsServer(t, pub)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authedRequest(http.MethodPost, "/api/v1/alerts/test", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(pub.published) != 1 {
		t.Fatalf("expected exactly one publish, got %v", pub.published)
	}
}

func TestPostTestAlertUnavailableWithoutAnyPublisher(t *testing.T) {
	srv := alertsServer(t) // no testPublisher wired up

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authedRequest(http.MethodPost, "/api/v1/alerts/test", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no delivery path is configured, got %d", rec.Code)
	}
}

func TestPostTestAlertSurfacesPublishFailure(t *testing.T) {
	pub := &fakePublisher{err: errors.New("relay unreachable")}
	srv := alertsServer(t, pub)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, authedRequest(http.MethodPost, "/api/v1/alerts/test", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when the publisher fails, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTestAlertRequiresAuth(t *testing.T) {
	srv := alertsServer(t, &fakePublisher{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/alerts/test", nil) // no Authorization header
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without a bearer token, got %d", rec.Code)
	}
}
