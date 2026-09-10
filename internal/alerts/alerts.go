// Package alerts evaluates collector.Sample values against threshold rules
// and publishes triggered alerts through a Publisher.
package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Hefty-Innovations/gateshell-go/internal/collector"
)

// Metric identifies which Sample field a Rule watches.
type Metric string

const (
	MetricCPUPercent  Metric = "cpu_percent"
	MetricMemPercent  Metric = "mem_percent"  // derived: mem_used_mb / mem_total_mb * 100
	MetricDiskPercent Metric = "disk_percent" // derived: disk_used_gb / disk_total_gb * 100
	MetricLoadAvg1    Metric = "load_avg_1"
)

// Comparator is how a Rule's Threshold is compared against the observed
// metric value.
type Comparator string

const (
	ComparatorGreaterThan Comparator = "gt"
	ComparatorLessThan    Comparator = "lt"
)

// Rule is a single threshold alert definition: fire when Metric has been on
// the wrong side of Threshold (per Comparator) continuously for at least
// For duration.
//
// A separate class of rule -- "service up/down" -- is represented by
// ServiceRule below, since it watches collector.ServiceStatus rather than a
// numeric metric.
type Rule struct {
	Name       string        `json:"name"`
	Metric     Metric        `json:"metric"`
	Comparator Comparator    `json:"comparator"`
	Threshold  float64       `json:"threshold"`
	For        time.Duration `json:"-"` // marshaled as a duration string; see (Un)MarshalJSON
	// RepeatInterval re-sends the alert while the condition is still true,
	// no more often than this. Zero (the default, and what every rule
	// written before this field says) means notify once per episode --
	// previously the only behaviour, so a metric pinned over its threshold
	// for hours produced a single notification at the start.
	RepeatInterval time.Duration `json:"-"` // see (Un)MarshalJSON
}

// ruleJSON mirrors Rule but with For as a Go duration string (e.g. "5m0s"),
// matching how poll_interval is already represented everywhere else in this
// API/config surface -- a raw nanosecond count would be the only field on
// the wire not human-readable this way.
type ruleJSON struct {
	Name       string     `json:"name"`
	Metric     Metric     `json:"metric"`
	Comparator Comparator `json:"comparator"`
	Threshold  float64    `json:"threshold"`
	For        string     `json:"for"`
	// Omitted by clients that predate repeat alerts; absent means zero,
	// which means "never repeat".
	RepeatInterval string `json:"repeat_interval,omitempty"`
}

func (r Rule) MarshalJSON() ([]byte, error) {
	repeat := ""
	if r.RepeatInterval > 0 {
		repeat = r.RepeatInterval.String()
	}
	return json.Marshal(ruleJSON{
		Name: r.Name, Metric: r.Metric, Comparator: r.Comparator,
		Threshold: r.Threshold, For: r.For.String(), RepeatInterval: repeat,
	})
}

func (r *Rule) UnmarshalJSON(data []byte) error {
	var raw ruleJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	d, err := time.ParseDuration(raw.For)
	if err != nil {
		return fmt.Errorf("alerts: parsing rule %q's \"for\" duration %q: %w", raw.Name, raw.For, err)
	}
	var repeat time.Duration
	if raw.RepeatInterval != "" {
		repeat, err = time.ParseDuration(raw.RepeatInterval)
		if err != nil {
			return fmt.Errorf("alerts: parsing rule %q's \"repeat_interval\" %q: %w", raw.Name, raw.RepeatInterval, err)
		}
		if repeat < 0 {
			return fmt.Errorf("alerts: rule %q has a negative \"repeat_interval\" %q", raw.Name, raw.RepeatInterval)
		}
	}
	r.Name, r.Metric, r.Comparator, r.Threshold, r.For = raw.Name, raw.Metric, raw.Comparator, raw.Threshold, d
	r.RepeatInterval = repeat
	return nil
}

// ServiceRule fires when a named service's Running state changes (flips
// down, or optionally flips back up -- see NotifyOnRecovery).
type ServiceRule struct {
	// Name is a human-readable alert name.
	Name string `json:"name"`
	// ServiceName must match collector.ServiceStatus.Name.
	ServiceName      string `json:"service_name"`
	NotifyOnRecovery bool   `json:"notify_on_recovery"`
	// RepeatInterval re-sends the "is DOWN" alert while the service is
	// still down, no more often than this. Zero means notify once per
	// outage -- previously the only behaviour, so a service that stayed
	// down for hours announced itself once and then went quiet.
	RepeatInterval time.Duration `json:"-"` // see (Un)MarshalJSON
}

// serviceRuleJSON mirrors ServiceRule with RepeatInterval as a duration
// string, for the same reason ruleJSON exists.
type serviceRuleJSON struct {
	Name             string `json:"name"`
	ServiceName      string `json:"service_name"`
	NotifyOnRecovery bool   `json:"notify_on_recovery"`
	RepeatInterval   string `json:"repeat_interval,omitempty"`
}

func (r ServiceRule) MarshalJSON() ([]byte, error) {
	repeat := ""
	if r.RepeatInterval > 0 {
		repeat = r.RepeatInterval.String()
	}
	return json.Marshal(serviceRuleJSON{
		Name: r.Name, ServiceName: r.ServiceName,
		NotifyOnRecovery: r.NotifyOnRecovery, RepeatInterval: repeat,
	})
}

func (r *ServiceRule) UnmarshalJSON(data []byte) error {
	var raw serviceRuleJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var repeat time.Duration
	if raw.RepeatInterval != "" {
		var err error
		repeat, err = time.ParseDuration(raw.RepeatInterval)
		if err != nil {
			return fmt.Errorf("alerts: parsing service rule %q's \"repeat_interval\" %q: %w", raw.Name, raw.RepeatInterval, err)
		}
		if repeat < 0 {
			return fmt.Errorf("alerts: service rule %q has a negative \"repeat_interval\" %q", raw.Name, raw.RepeatInterval)
		}
	}
	r.Name, r.ServiceName, r.NotifyOnRecovery, r.RepeatInterval = raw.Name, raw.ServiceName, raw.NotifyOnRecovery, repeat
	return nil
}

// state tracks how long a numeric Rule's condition has been continuously
// true, to implement the "for N duration" debounce.
type ruleState struct {
	conditionSince time.Time
	firing         bool
	// lastFiredAt drives RepeatInterval. Tracked separately from
	// conditionSince so a repeat is measured from the previous
	// notification, not from when the breach began.
	lastFiredAt time.Time
}

// serviceState tracks a service's last observed Running state and, while
// it is down, when it last notified -- the equivalent of ruleState for
// service rules.
type serviceState struct {
	running     bool
	lastFiredAt time.Time
}

// Evaluator watches incoming samples against a set of Rules/ServiceRules
// and publishes to a Publisher when a rule transitions into (or, for
// services, out of) an alerting state.
type Evaluator struct {
	mu            sync.Mutex
	rules         []Rule
	serviceRules  []ServiceRule
	ruleStates    map[string]*ruleState
	serviceStates map[string]*serviceState // by service name

	publisher Publisher
	logger    *slog.Logger
}

// NewEvaluator builds an Evaluator that publishes triggered alerts via pub.
func NewEvaluator(pub Publisher, logger *slog.Logger) *Evaluator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Evaluator{
		ruleStates:    make(map[string]*ruleState),
		serviceStates: make(map[string]*serviceState),
		publisher:     pub,
		logger:        logger,
	}
}

// SetRules replaces the current rule set.
func (e *Evaluator) SetRules(rules []Rule, serviceRules []ServiceRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
	e.serviceRules = serviceRules
}

// Rules returns the currently active rule set, for GET /api/v1/alerts.
func (e *Evaluator) Rules() ([]Rule, []ServiceRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rules, e.serviceRules
}

// Handle implements collector.Sink, so an Evaluator can be attached directly
// to a collector.Collector via AddSink.
func (e *Evaluator) Handle(sample collector.Sample) {
	e.evaluate(context.Background(), sample)
}

func (e *Evaluator) evaluate(ctx context.Context, sample collector.Sample) {
	e.mu.Lock()
	rules := e.rules
	serviceRules := e.serviceRules
	e.mu.Unlock()

	for _, rule := range rules {
		e.evaluateRule(ctx, rule, sample)
	}
	for _, rule := range serviceRules {
		e.evaluateServiceRule(ctx, rule, sample)
	}
}

func (e *Evaluator) evaluateRule(ctx context.Context, rule Rule, sample collector.Sample) {
	value, ok := metricValue(rule.Metric, sample)
	if !ok {
		return
	}

	conditionMet := false
	switch rule.Comparator {
	case ComparatorGreaterThan:
		conditionMet = value > rule.Threshold
	case ComparatorLessThan:
		conditionMet = value < rule.Threshold
	default:
		e.logger.Warn("unknown comparator", "rule", rule.Name, "comparator", rule.Comparator)
		return
	}

	e.mu.Lock()
	state, exists := e.ruleStates[rule.Name]
	if !exists {
		state = &ruleState{}
		e.ruleStates[rule.Name] = state
	}

	if !conditionMet {
		state.conditionSince = time.Time{}
		wasFiring := state.firing
		state.firing = false
		state.lastFiredAt = time.Time{}
		e.mu.Unlock()
		if wasFiring {
			e.publish(ctx, fmt.Sprintf("%s recovered (%s = %.1f)", rule.Name, rule.Metric, value))
		}
		return
	}

	if state.conditionSince.IsZero() {
		state.conditionSince = sample.Timestamp
	}
	firstFire := !state.firing && sample.Timestamp.Sub(state.conditionSince) >= rule.For
	// A still-breaching rule re-notifies once RepeatInterval has elapsed
	// since the last notification. Driven off sample timestamps rather than
	// a timer, so the cadence follows the agent's own polling and a missed
	// poll cannot double-fire.
	repeatFire := state.firing && rule.RepeatInterval > 0 &&
		sample.Timestamp.Sub(state.lastFiredAt) >= rule.RepeatInterval
	shouldFire := firstFire || repeatFire
	if shouldFire {
		state.firing = true
		state.lastFiredAt = sample.Timestamp
	}
	e.mu.Unlock()

	if shouldFire {
		message := fmt.Sprintf("%s: %s = %.1f (threshold %.1f for %s)",
			rule.Name, rule.Metric, value, rule.Threshold, rule.For)
		if repeatFire {
			message = fmt.Sprintf("%s: %s = %.1f (still over threshold %.1f)",
				rule.Name, rule.Metric, value, rule.Threshold)
		}
		e.publish(ctx, message)
	}
}

func (e *Evaluator) evaluateServiceRule(ctx context.Context, rule ServiceRule, sample collector.Sample) {
	var current *collector.ServiceStatus
	for i := range sample.Services {
		if sample.Services[i].Name == rule.ServiceName {
			current = &sample.Services[i]
			break
		}
	}
	if current == nil {
		return // service not observed in this sample; nothing to compare
	}

	e.mu.Lock()
	state, known := e.serviceStates[rule.ServiceName]
	if !known {
		e.serviceStates[rule.ServiceName] = &serviceState{running: current.Running}
		e.mu.Unlock()
		return // first observation; no transition to alert on
	}
	previous := state.running
	state.running = current.Running

	wentDown := previous && !current.Running
	cameUp := !previous && current.Running
	// A service that is still down re-notifies once RepeatInterval has
	// elapsed since the last notification, the same cadence rule numeric
	// thresholds use.
	stillDown := !previous && !current.Running && rule.RepeatInterval > 0 &&
		sample.Timestamp.Sub(state.lastFiredAt) >= rule.RepeatInterval
	if wentDown || stillDown {
		state.lastFiredAt = sample.Timestamp
	}
	if cameUp {
		state.lastFiredAt = time.Time{}
	}
	e.mu.Unlock()

	switch {
	case wentDown:
		e.publish(ctx, fmt.Sprintf("%s: service %q is DOWN", rule.Name, rule.ServiceName))
	case stillDown:
		e.publish(ctx, fmt.Sprintf("%s: service %q is still DOWN", rule.Name, rule.ServiceName))
	case cameUp && rule.NotifyOnRecovery:
		e.publish(ctx, fmt.Sprintf("%s: service %q recovered", rule.Name, rule.ServiceName))
	}
}

func (e *Evaluator) publish(ctx context.Context, message string) {
	if e.publisher == nil {
		e.logger.Warn("alert triggered but no publisher configured", "message", message)
		return
	}
	if err := e.publisher.Publish(ctx, message); err != nil {
		e.logger.Error("publishing alert failed", "error", err, "message", message)
	}
}

// metricValue extracts (possibly deriving) a Metric's value from a Sample.
func metricValue(metric Metric, sample collector.Sample) (float64, bool) {
	switch metric {
	case MetricCPUPercent:
		return sample.CPUPercent, true
	case MetricMemPercent:
		if sample.MemTotalMB == 0 {
			return 0, false
		}
		return sample.MemUsedMB / sample.MemTotalMB * 100, true
	case MetricDiskPercent:
		if sample.DiskTotalGB == 0 {
			return 0, false
		}
		return sample.DiskUsedGB / sample.DiskTotalGB * 100, true
	case MetricLoadAvg1:
		return sample.LoadAvg1, true
	default:
		return 0, false
	}
}

// Publisher delivers an alert message somewhere (the GateShell
// push relay).
type Publisher interface {
	Publish(ctx context.Context, message string) error
}
