// Package api serves the REST + streaming API the GateShell mobile app
// polls/subscribes to for metrics and service health.
//
// It also exposes a small config surface (GET/PATCH /api/v1/config) so the
// app can read and change how often the agent polls (V1-10): a PATCH is
// applied to the running collector immediately (no restart) and persisted
// to the config file so it survives one. GET/PATCH /api/v1/alerts follows
// the identical pattern for the alerts.Evaluator's rule set.
//
// Transport choice: this implements the live-update endpoint as
// Server-Sent Events (GET /api/v1/stream) over plain net/http, rather than
// a WebSocket, to keep the module dependency-free by default (stdlib only).
// SSE is sufficient for a one-way "push new samples to the app" feed and
// works fine through the same Bearer-token middleware and TLS termination
// as every other endpoint. If bidirectional messaging is ever needed
// (e.g. the app pushing commands back to the agent over the same
// connection), swap this handler for github.com/coder/websocket -- the
// route and auth middleware are structured so that's a localized change.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Hefty-Innovations/gateshell-go/internal/alerts"
	"github.com/Hefty-Innovations/gateshell-go/internal/collector"
	"github.com/Hefty-Innovations/gateshell-go/internal/securityaudit"
	"github.com/Hefty-Innovations/gateshell-go/internal/store"
)

// MinPollInterval is the smallest non-zero poll interval the config API
// will accept, to stop the app from hammering the host. A value of 0 is
// always allowed and pauses collection.
const MinPollInterval = 5 * time.Second

// IntervalController lets the config API read and change the collector's
// poll interval at runtime. *collector.Collector satisfies it.
type IntervalController interface {
	Interval() time.Duration
	SetInterval(d time.Duration)
}

// PersistIntervalFunc persists a changed poll interval so it survives a
// restart (typically config.SavePollInterval bound to the config file
// path). It may be nil, in which case changes apply at runtime only.
type PersistIntervalFunc func(d time.Duration) error

// RulesController lets the alerts config API read and change the alert
// evaluator's rule set at runtime. *alerts.Evaluator satisfies it.
type RulesController interface {
	Rules() ([]alerts.Rule, []alerts.ServiceRule)
	SetRules(rules []alerts.Rule, serviceRules []alerts.ServiceRule)
}

// PersistRulesFunc persists a changed rule set so it survives a restart
// (typically config.SaveRules bound to the config file path). It may be
// nil, in which case changes apply at runtime only.
type PersistRulesFunc func(rules []alerts.Rule, serviceRules []alerts.ServiceRule) error

// SecurityScanner backs GET /api/v1/security -- *securityaudit.CachedScanner
// satisfies it.
type SecurityScanner interface {
	Scan(refresh bool) securityaudit.Report
}

// PushTokenStore backs GET/POST /api/v1/push-token. Wiring it (or not) is
// how the server signals whether this agent build has push delivery
// available at all. In practice this is pushrelay.TokenStore, which
// persists the token locally -- the relay itself is stateless and gets the
// token fresh on every alert (see internal/pushrelay) -- nothing in this
// package assumes that, it just needs Get/Set.
type PushTokenStore interface {
	// Count reports how many devices are registered. A Mac and an iPhone
	// paired to the same agent are two.
	Count() int
	// Labels names them, for display. Never returns tokens.
	Labels() []string
	Set(token, environment, label string) error
}

// PushTester delivers a test message to one specific device. Separate from
// alertPublisher, which fans out to everything: "Send Test Alert" is a
// per-device check, so tapping it on a Mac must prove that Mac can receive
// rather than making some other device buzz. nil when push isn't configured.
type PushTester interface {
	SendTest(ctx context.Context, deviceToken, message string) error
}

// Server wires the HTTP handlers to a Store and broadcasts live samples to
// connected /api/v1/stream clients.
type Server struct {
	store        store.Store
	pairingToken string
	serverName   string
	version      string
	logger       *slog.Logger

	intervalCtl IntervalController
	persist     PersistIntervalFunc

	rulesCtl     RulesController
	persistRules PersistRulesFunc

	securityScanner SecurityScanner
	pushTokens      PushTokenStore

	// alertPublisher is the same alerts.Publisher (typically a
	// the push-relay publisher) the evaluator
	// publishes real triggered alerts through -- POST /api/v1/alerts/test
	// calls it directly with a fixed message, bypassing rule evaluation
	// entirely, so the app can verify actual delivery end-to-end without
	// waiting for (or fabricating) a real threshold crossing. nil when no
	// delivery path is configured at all.
	alertPublisher alerts.Publisher

	// pushTester delivers a test to one device; see PushTester.
	pushTester PushTester

	mux *http.ServeMux

	broadcastMu sync.RWMutex
	subscribers map[chan collector.Sample]struct{}
}

// NewServer builds a Server ready to be used as an http.Handler, or run via
// ListenAndServe.
//
// intervalCtl drives GET/PATCH /api/v1/config; persist (may be nil)
// persists a PATCHed interval so it survives a restart. version is the
// build-time agent version (main.version) surfaced on GET /healthz so the
// mobile app can check it without an extra SSH round-trip to run
// `gateshell-agent version` directly. rulesCtl/persistRules are the same
// pattern as intervalCtl/persist, for GET/PATCH /api/v1/alerts.
// securityScanner, pushTokens, and alertPublisher may all be nil, in which
// case their respective endpoints report 503 -- each is independently
// optional based on what this agent build/config actually supports.
func NewServer(
	st store.Store,
	pairingToken, serverName, version string,
	intervalCtl IntervalController,
	persist PersistIntervalFunc,
	rulesCtl RulesController,
	persistRules PersistRulesFunc,
	securityScanner SecurityScanner,
	pushTokens PushTokenStore,
	alertPublisher alerts.Publisher,
	pushTester PushTester,
	logger *slog.Logger,
) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		store:           st,
		pairingToken:    pairingToken,
		serverName:      serverName,
		version:         version,
		intervalCtl:     intervalCtl,
		persist:         persist,
		rulesCtl:        rulesCtl,
		persistRules:    persistRules,
		securityScanner: securityScanner,
		pushTokens:      pushTokens,
		alertPublisher:  alertPublisher,
		pushTester:      pushTester,
		logger:          logger,
		subscribers:     make(map[chan collector.Sample]struct{}),
	}
	s.mux = s.routes()
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// BroadcastSample fans a newly-collected sample out to every connected
// /api/v1/stream client. Intended to be wired as a collector.Sink by
// cmd/gateshell-agent's `serve` command.
func (s *Server) BroadcastSample(sample collector.Sample) {
	s.broadcastMu.RLock()
	defer s.broadcastMu.RUnlock()

	for ch := range s.subscribers {
		select {
		case ch <- sample:
		default:
			// Slow subscriber; drop the sample rather than blocking the
			// collector tick. The client will catch up via /api/v1/latest
			// or /api/v1/metrics on reconnect.
		}
	}
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()

	// /healthz is intentionally unauthenticated so external uptime
	// monitors / load balancers can probe it without a token.
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	mux.Handle("GET /api/v1/metrics", s.authed(http.HandlerFunc(s.handleMetrics)))
	mux.Handle("GET /api/v1/services", s.authed(http.HandlerFunc(s.handleServices)))
	mux.Handle("GET /api/v1/latest", s.authed(http.HandlerFunc(s.handleLatest)))
	mux.Handle("GET /api/v1/stream", s.authed(http.HandlerFunc(s.handleStream)))
	mux.Handle("GET /api/v1/config", s.authed(http.HandlerFunc(s.handleGetConfig)))
	mux.Handle("PATCH /api/v1/config", s.authed(http.HandlerFunc(s.handlePatchConfig)))
	mux.Handle("GET /api/v1/alerts", s.authed(http.HandlerFunc(s.handleGetAlerts)))
	mux.Handle("PATCH /api/v1/alerts", s.authed(http.HandlerFunc(s.handlePatchAlerts)))
	mux.Handle("GET /api/v1/security", s.authed(http.HandlerFunc(s.handleSecurity)))
	mux.Handle("GET /api/v1/push-token", s.authed(http.HandlerFunc(s.handleGetPushToken)))
	mux.Handle("POST /api/v1/push-token", s.authed(http.HandlerFunc(s.handlePostPushToken)))
	mux.Handle("POST /api/v1/alerts/test", s.authed(http.HandlerFunc(s.handlePostTestAlert)))

	return mux
}

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	if s.securityScanner == nil {
		writeError(w, http.StatusServiceUnavailable, "security scanner not available")
		return
	}
	refresh := r.URL.Query().Get("refresh") == "1"
	writeJSON(w, http.StatusOK, s.securityScanner.Scan(refresh))
}

// authed wraps next with Bearer-token validation against the configured
// pairing token. See internal/pair for token generation/validation
// semantics (constant-time compare, no-token-means-refuse-all).
func (s *Server) authed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(authHeader, "Bearer ")
		if !ok || !constantTimeTokenEqual(s.pairingToken, token) {
			writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// constantTimeTokenEqual is a thin wrapper so this file doesn't need to
// import internal/pair just for the comparison (avoids a package cycle
// risk if pair ever needs api's types); logic mirrors pair.Validate.
func constantTimeTokenEqual(expected, candidate string) bool {
	if expected == "" {
		return false
	}
	if len(expected) != len(candidate) {
		return false
	}
	var diff byte
	for i := 0; i < len(expected); i++ {
		diff |= expected[i] ^ candidate[i]
	}
	return diff == 0
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"server":  s.serverName,
		"version": s.version,
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	from, to, err := parseRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	samples, err := s.store.QueryRange(r.Context(), from, to)
	if err != nil {
		s.logger.Error("query range failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to query metrics")
		return
	}
	writeJSON(w, http.StatusOK, samples)
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	sample, err := s.store.LatestSample(r.Context())
	if err != nil {
		if err == store.ErrNoSamples {
			writeJSON(w, http.StatusOK, []collector.ServiceStatus{})
			return
		}
		s.logger.Error("latest sample failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to load services")
		return
	}
	writeJSON(w, http.StatusOK, sample.Services)
}

func (s *Server) handleLatest(w http.ResponseWriter, r *http.Request) {
	sample, err := s.store.LatestSample(r.Context())
	if err != nil {
		if err == store.ErrNoSamples {
			writeError(w, http.StatusNotFound, "no samples collected yet")
			return
		}
		s.logger.Error("latest sample failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to load latest sample")
		return
	}
	writeJSON(w, http.StatusOK, sample)
}

// configPayload is the request/response body for the config endpoints.
// PollInterval is a Go duration string (e.g. "60s"); "0s" means paused.
type configPayload struct {
	PollInterval string `json:"pollInterval"`
}

// handleGetConfig returns the collector's current poll interval (V1-10).
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if s.intervalCtl == nil {
		writeError(w, http.StatusServiceUnavailable, "config controller not available")
		return
	}
	writeJSON(w, http.StatusOK, configPayload{
		PollInterval: s.intervalCtl.Interval().String(),
	})
}

// handlePatchConfig validates and applies a new poll interval at runtime,
// then persists it so it survives a restart (V1-10). A value of 0 pauses
// collection; negatives are rejected; non-zero values below MinPollInterval
// are rejected.
func (s *Server) handlePatchConfig(w http.ResponseWriter, r *http.Request) {
	if s.intervalCtl == nil {
		writeError(w, http.StatusServiceUnavailable, "config controller not available")
		return
	}

	var payload configPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if payload.PollInterval == "" {
		writeError(w, http.StatusBadRequest, "pollInterval is required")
		return
	}

	d, err := time.ParseDuration(payload.PollInterval)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid pollInterval: %v", err))
		return
	}
	if d < 0 {
		writeError(w, http.StatusBadRequest, "pollInterval must not be negative")
		return
	}
	if d > 0 && d < MinPollInterval {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("pollInterval must be 0 (paused) or at least %s", MinPollInterval))
		return
	}

	// Apply at runtime first -- this cannot fail and is what the user
	// asked for; persistence is best-effort on top.
	s.intervalCtl.SetInterval(d)

	if s.persist != nil {
		if err := s.persist(d); err != nil {
			// The change is live, but won't survive a restart. Surface
			// this rather than silently claiming success.
			s.logger.Error("persisting poll interval failed", "error", err, "interval", d)
			writeError(w, http.StatusInternalServerError,
				"poll interval applied at runtime but could not be persisted; it will not survive a restart")
			return
		}
	}

	writeJSON(w, http.StatusOK, configPayload{PollInterval: d.String()})
}

// alertsPayload is the request/response body for the alerts config
// endpoints. Empty slices (never nil on the wire, see handleGetAlerts) mean
// no rules configured -- no alerts fire.
type alertsPayload struct {
	Rules        []alerts.Rule        `json:"rules"`
	ServiceRules []alerts.ServiceRule `json:"service_rules"`
}

// handleGetAlerts returns the evaluator's currently configured rule set.
func (s *Server) handleGetAlerts(w http.ResponseWriter, r *http.Request) {
	if s.rulesCtl == nil {
		writeError(w, http.StatusServiceUnavailable, "alerts controller not available")
		return
	}
	rules, serviceRules := s.rulesCtl.Rules()
	if rules == nil {
		rules = []alerts.Rule{}
	}
	if serviceRules == nil {
		serviceRules = []alerts.ServiceRule{}
	}
	writeJSON(w, http.StatusOK, alertsPayload{Rules: rules, ServiceRules: serviceRules})
}

// handlePatchAlerts validates and applies a new rule set at runtime, then
// persists it so it survives a restart -- same shape as handlePatchConfig.
// A request replaces the whole rule set (no partial add/remove of one
// rule); the app is expected to send back the full set it wants, same as
// how it already has to fetch-then-render the whole thing to show a
// rules-list UI in the first place.
func (s *Server) handlePatchAlerts(w http.ResponseWriter, r *http.Request) {
	if s.rulesCtl == nil {
		writeError(w, http.StatusServiceUnavailable, "alerts controller not available")
		return
	}

	var payload alertsPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if err := validateRules(payload.Rules, payload.ServiceRules); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Apply at runtime first -- this cannot fail and is what the user
	// asked for; persistence is best-effort on top.
	s.rulesCtl.SetRules(payload.Rules, payload.ServiceRules)

	if s.persistRules != nil {
		if err := s.persistRules(payload.Rules, payload.ServiceRules); err != nil {
			// The change is live, but won't survive a restart. Surface
			// this rather than silently claiming success -- same pattern
			// as handlePatchConfig's persistence failure.
			s.logger.Error("persisting alert rules failed", "error", err)
			writeError(w, http.StatusInternalServerError,
				"alert rules applied at runtime but could not be persisted; they will not survive a restart")
			return
		}
	}

	writeJSON(w, http.StatusOK, alertsPayload{Rules: payload.Rules, ServiceRules: payload.ServiceRules})
}

// validateRules rejects a rule set that would silently never fire or crash
// the evaluator, rather than accepting garbage and having it fail quietly
// later inside Evaluator.evaluateRule (which just logs a warning and skips
// an unknown comparator).
func validateRules(rules []alerts.Rule, serviceRules []alerts.ServiceRule) error {
	validMetrics := map[alerts.Metric]bool{
		alerts.MetricCPUPercent: true, alerts.MetricMemPercent: true,
		alerts.MetricDiskPercent: true, alerts.MetricLoadAvg1: true,
	}
	validComparators := map[alerts.Comparator]bool{
		alerts.ComparatorGreaterThan: true, alerts.ComparatorLessThan: true,
	}

	for _, rule := range rules {
		if rule.Name == "" {
			return errors.New("alerts: every rule needs a name")
		}
		if !validMetrics[rule.Metric] {
			return fmt.Errorf("alerts: rule %q has unknown metric %q", rule.Name, rule.Metric)
		}
		if !validComparators[rule.Comparator] {
			return fmt.Errorf("alerts: rule %q has unknown comparator %q", rule.Name, rule.Comparator)
		}
		if rule.For < 0 {
			return fmt.Errorf("alerts: rule %q has a negative \"for\" duration", rule.Name)
		}
	}
	for _, rule := range serviceRules {
		if rule.Name == "" {
			return errors.New("alerts: every service rule needs a name")
		}
		if rule.ServiceName == "" {
			return fmt.Errorf("alerts: service rule %q needs a service_name to watch", rule.Name)
		}
	}
	return nil
}

// pushTokenPayload is the response body for GET/POST /api/v1/push-token.
// The raw token is only ever sent by the app (registering one), never
// echoed back by GET -- the app never needs it back and there's no reason
// to repeat it over the wire.
type pushTokenPayload struct {
	Registered bool `json:"registered"`
	// Devices is how many are registered; `registered` stays for older
	// app builds that only look at the boolean.
	Devices int `json:"devices"`
	// DeviceLabels names them so the app can show which devices an agent
	// will notify, instead of leaving it to be inferred from which one
	// happened to buzz.
	DeviceLabels []string `json:"device_labels,omitempty"`
}

// handleGetPushToken reports whether a device is currently registered for
// push, without echoing the token itself.
func (s *Server) handleGetPushToken(w http.ResponseWriter, r *http.Request) {
	if s.pushTokens == nil {
		writeError(w, http.StatusServiceUnavailable, "push delivery is not configured on this agent")
		return
	}
	count := s.pushTokens.Count()
	writeJSON(w, http.StatusOK, pushTokenPayload{
		Registered: count > 0, Devices: count, DeviceLabels: s.pushTokens.Labels(),
	})
}

// handlePostPushToken registers (or replaces) the APNs device token this
// agent's alerts should push to -- called by the mobile app during
// install/re-pair once it has registered for remote notifications with
// Apple. This only persists locally (s.pushTokens, pushrelay.TokenStore in
// production) -- the relay is stateless and never sees the token until an
// alert actually fires, so there's nothing to fail at "registration" time
// beyond writing the local file.
func (s *Server) handlePostPushToken(w http.ResponseWriter, r *http.Request) {
	if s.pushTokens == nil {
		writeError(w, http.StatusServiceUnavailable, "push delivery is not configured on this agent")
		return
	}
	var payload struct {
		Token string `json:"token"`
		// Which APNs environment the token belongs to, as reported by the
		// app from its own signed aps-environment entitlement. Absent or
		// unrecognized means production -- that's what app builds
		// predating this field always were, and the only environment the
		// relay could reach.
		Environment string `json:"environment"`
		// Human-readable device name, so alerts and failures can name a
		// device rather than a token.
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	if err := s.pushTokens.Set(payload.Token, payload.Environment, payload.Label); err != nil {
		s.logger.Error("registering push token failed", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to register push token")
		return
	}
	writeJSON(w, http.StatusOK, pushTokenPayload{
		Registered: true, Devices: s.pushTokens.Count(), DeviceLabels: s.pushTokens.Labels(),
	})
}

// handlePostTestAlert publishes a fixed test message through whichever
// delivery is actually configured (a device token registered for push),
// bypassing rule evaluation entirely.
// Lets the app verify real end-to-end delivery on demand -- tap a button,
// see if a push arrives -- instead of waiting for (or contriving) an
// actual threshold crossing.
func (s *Server) handlePostTestAlert(w http.ResponseWriter, r *http.Request) {
	// A device token in the body means "prove THIS device can receive",
	// which is what the button means when you tap it on one of several
	// paired devices. Without one, fall back to the fan-out behaviour
	// older app builds expect.
	var payload struct {
		DeviceToken string `json:"device_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)
	if payload.DeviceToken != "" {
		if s.pushTester == nil {
			writeError(w, http.StatusServiceUnavailable, "push delivery is not configured on this agent")
			return
		}
		if err := s.pushTester.SendTest(r.Context(), payload.DeviceToken, fmt.Sprintf("Test alert from %s", s.serverName)); err != nil {
			s.logger.Error("targeted test alert failed", "error", err)
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
		return
	}

	if s.alertPublisher == nil {
		writeError(w, http.StatusServiceUnavailable,
			"no alert delivery configured on this agent (register a push token from the app)")
		return
	}
	if err := s.alertPublisher.Publish(r.Context(), fmt.Sprintf("Test alert from %s", s.serverName)); err != nil {
		// The publisher attempts every registered device and joins any
		// failures, so this error may mean only one device failed while
		// others still received it -- phrased accordingly rather than
		// implying total failure.
		s.logger.Error("test alert publish failed", "error", err)
		writeError(w, http.StatusInternalServerError,
			fmt.Sprintf("at least one delivery path failed (others may have still succeeded): %v", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// handleStream serves live samples as Server-Sent Events. See the package
// doc comment for why SSE was chosen over a WebSocket.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	ch := make(chan collector.Sample, 8)
	s.broadcastMu.Lock()
	s.subscribers[ch] = struct{}{}
	s.broadcastMu.Unlock()

	defer func() {
		s.broadcastMu.Lock()
		delete(s.subscribers, ch)
		s.broadcastMu.Unlock()
		close(ch)
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	keepAlive := time.NewTicker(30 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case sample := <-ch:
			data, err := json.Marshal(sample)
			if err != nil {
				s.logger.Error("marshal sample for stream failed", "error", err)
				continue
			}
			fmt.Fprintf(w, "event: sample\ndata: %s\n\n", data)
			flusher.Flush()
		case <-keepAlive.C:
			fmt.Fprint(w, ": keep-alive\n\n")
			flusher.Flush()
		}
	}
}

// parseRange extracts ?from=&to= unix-second query params, defaulting to
// the last hour when absent.
func parseRange(r *http.Request) (from, to time.Time, err error) {
	to = time.Now().UTC()
	from = to.Add(-1 * time.Hour)

	if v := r.URL.Query().Get("from"); v != "" {
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid 'from': %w", err)
		}
		from = time.Unix(sec, 0).UTC()
	}
	if v := r.URL.Query().Get("to"); v != "" {
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid 'to': %w", err)
		}
		to = time.Unix(sec, 0).UTC()
	}
	if from.After(to) {
		return time.Time{}, time.Time{}, fmt.Errorf("'from' must not be after 'to'")
	}
	return from, to, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Default().Error("writeJSON encode failed", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// ListenAndServe is a convenience wrapper for cmd/gateshell-agent; callers
// needing graceful shutdown should build an *http.Server directly with
// this Server as its Handler instead.
func ListenAndServe(ctx context.Context, addr string, handler http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
