package alerts

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Hefty-Innovations/gateshell-go/internal/collector"
)

// TestRuleJSONRoundTrip covers the reason Rule has custom (Un)MarshalJSON:
// For is a time.Duration, which encodes as a raw nanosecond integer by
// default -- everywhere else in this API/config surface (poll_interval)
// duration values are human-readable strings on the wire, and this keeps
// that consistent.
func TestRuleJSONRoundTrip(t *testing.T) {
	original := Rule{
		Name: "High CPU", Metric: MetricCPUPercent, Comparator: ComparatorGreaterThan,
		Threshold: 90, For: 2 * time.Minute,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal into map: %v", err)
	}
	if decoded["for"] != "2m0s" {
		t.Errorf("expected \"for\" to be the string \"2m0s\", got %#v", decoded["for"])
	}

	var roundTripped Rule
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unmarshal into Rule: %v", err)
	}
	if roundTripped != original {
		t.Errorf("round-trip mismatch: got %+v, want %+v", roundTripped, original)
	}
}

func TestRuleUnmarshalRejectsUnparseableDuration(t *testing.T) {
	var r Rule
	err := json.Unmarshal([]byte(`{"name":"x","metric":"cpu_percent","comparator":"gt","threshold":1,"for":"not-a-duration"}`), &r)
	if err == nil {
		t.Fatal("expected an error for an unparseable \"for\" duration, got nil")
	}
}

// TestEvaluatorRulesReturnsWhatWasSet covers the getter added alongside
// SetRules so GET /api/v1/alerts has something to read.
func TestEvaluatorRulesReturnsWhatWasSet(t *testing.T) {
	e := NewEvaluator(nil, nil)

	rules, serviceRules := e.Rules()
	if len(rules) != 0 || len(serviceRules) != 0 {
		t.Fatalf("expected no rules before SetRules, got %v / %v", rules, serviceRules)
	}

	want := []Rule{{Name: "x", Metric: MetricCPUPercent, Comparator: ComparatorGreaterThan, Threshold: 1, For: time.Minute}}
	wantServices := []ServiceRule{{Name: "y", ServiceName: "nginx"}}
	e.SetRules(want, wantServices)

	gotRules, gotServiceRules := e.Rules()
	if len(gotRules) != 1 || gotRules[0] != want[0] {
		t.Errorf("Rules() = %v, want %v", gotRules, want)
	}
	if len(gotServiceRules) != 1 || gotServiceRules[0] != wantServices[0] {
		t.Errorf("Rules() service rules = %v, want %v", gotServiceRules, wantServices)
	}
}

type fakePublisher struct {
	published []string
	err       error
}

func (f *fakePublisher) Publish(ctx context.Context, message string) error {
	f.published = append(f.published, message)
	return f.err
}

// A metric pinned over its threshold produced exactly one notification for
// the whole episode, however long it lasted. With RepeatInterval set the
// agent keeps reminding at that cadence.
func TestRepeatIntervalReNotifiesWhileStillBreaching(t *testing.T) {
	pub := &fakePublisher{}
	e := NewEvaluator(pub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.SetRules([]Rule{{
		Name: "CPU", Metric: MetricCPUPercent, Comparator: ComparatorGreaterThan,
		Threshold: 80, For: time.Minute, RepeatInterval: 10 * time.Minute,
	}}, nil)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// t+0 starts the breach, t+1m satisfies "for", then repeats every 10m.
	for _, offset := range []time.Duration{0, time.Minute, 5 * time.Minute, 11 * time.Minute, 21 * time.Minute} {
		e.Handle(collector.Sample{Timestamp: base.Add(offset), CPUPercent: 95})
	}

	if len(pub.published) != 3 {
		t.Fatalf("expected first fire plus two repeats, got %d: %v", len(pub.published), pub.published)
	}
	if !strings.Contains(pub.published[1], "still over threshold") {
		t.Errorf("a repeat should read as a reminder, got %q", pub.published[1])
	}
}

// Zero (what every rule written before this field says) keeps the original
// notify-once-per-episode behaviour.
func TestZeroRepeatIntervalNotifiesOnce(t *testing.T) {
	pub := &fakePublisher{}
	e := NewEvaluator(pub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.SetRules([]Rule{{
		Name: "CPU", Metric: MetricCPUPercent, Comparator: ComparatorGreaterThan,
		Threshold: 80, For: 0,
	}}, nil)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, offset := range []time.Duration{0, time.Hour, 2 * time.Hour} {
		e.Handle(collector.Sample{Timestamp: base.Add(offset), CPUPercent: 95})
	}
	if len(pub.published) != 1 {
		t.Fatalf("expected exactly one notification, got %d: %v", len(pub.published), pub.published)
	}
}

// Recovering and breaching again is a new episode: the repeat clock must
// not carry over and suppress the next first-fire.
func TestRecoveryResetsTheRepeatClock(t *testing.T) {
	pub := &fakePublisher{}
	e := NewEvaluator(pub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.SetRules([]Rule{{
		Name: "CPU", Metric: MetricCPUPercent, Comparator: ComparatorGreaterThan,
		Threshold: 80, For: 0, RepeatInterval: time.Hour,
	}}, nil)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e.Handle(collector.Sample{Timestamp: base, CPUPercent: 95})                      // fire
	e.Handle(collector.Sample{Timestamp: base.Add(time.Minute), CPUPercent: 10})     // recover
	e.Handle(collector.Sample{Timestamp: base.Add(2 * time.Minute), CPUPercent: 95}) // fire again

	var fires int
	for _, m := range pub.published {
		if strings.Contains(m, "CPU:") {
			fires++
		}
	}
	if fires != 2 {
		t.Fatalf("expected two first-fires across two episodes, got %d: %v", fires, pub.published)
	}
}

func TestRuleRoundTripsRepeatInterval(t *testing.T) {
	in := Rule{Name: "CPU", Metric: MetricCPUPercent, Comparator: ComparatorGreaterThan,
		Threshold: 80, For: time.Minute, RepeatInterval: 10 * time.Minute}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"repeat_interval":"10m0s"`) {
		t.Fatalf("repeat_interval missing from the wire form: %s", data)
	}
	var out Rule
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.RepeatInterval != 10*time.Minute {
		t.Errorf("expected 10m, got %v", out.RepeatInterval)
	}
}

// A rule from an older app build has no repeat_interval at all.
func TestRuleWithoutRepeatIntervalDecodesToZero(t *testing.T) {
	var r Rule
	if err := json.Unmarshal([]byte(`{"name":"CPU","metric":"cpu_percent","comparator":"gt","threshold":80,"for":"5m0s"}`), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.RepeatInterval != 0 {
		t.Errorf("expected zero, got %v", r.RepeatInterval)
	}
}

// A service that stays down announced itself once and then went quiet,
// exactly like the numeric-threshold case.
func TestServiceRuleRepeatsWhileStillDown(t *testing.T) {
	pub := &fakePublisher{}
	e := NewEvaluator(pub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.SetRules(nil, []ServiceRule{{
		Name: "nginx", ServiceName: "nginx", RepeatInterval: 10 * time.Minute,
	}})

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	down := []collector.ServiceStatus{{Name: "nginx", Running: false}}
	up := []collector.ServiceStatus{{Name: "nginx", Running: true}}

	e.Handle(collector.Sample{Timestamp: base, Services: up})                                     // first observation
	e.Handle(collector.Sample{Timestamp: base.Add(1 * time.Minute), Services: down})              // goes down -> fire
	e.Handle(collector.Sample{Timestamp: base.Add(5 * time.Minute), Services: down})              // too soon
	e.Handle(collector.Sample{Timestamp: base.Add(11 * time.Minute), Services: down})             // repeat
	e.Handle(collector.Sample{Timestamp: base.Add(21*time.Minute + time.Second), Services: down}) // repeat

	if len(pub.published) != 3 {
		t.Fatalf("expected the outage plus two reminders, got %d: %v", len(pub.published), pub.published)
	}
	if !strings.Contains(pub.published[0], "is DOWN") || strings.Contains(pub.published[0], "still") {
		t.Errorf("first message should be the outage: %q", pub.published[0])
	}
	if !strings.Contains(pub.published[1], "still DOWN") {
		t.Errorf("a repeat should read as a reminder: %q", pub.published[1])
	}
}

func TestServiceRuleWithoutRepeatNotifiesOnce(t *testing.T) {
	pub := &fakePublisher{}
	e := NewEvaluator(pub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.SetRules(nil, []ServiceRule{{Name: "nginx", ServiceName: "nginx"}})

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	up := []collector.ServiceStatus{{Name: "nginx", Running: true}}
	down := []collector.ServiceStatus{{Name: "nginx", Running: false}}
	e.Handle(collector.Sample{Timestamp: base, Services: up})
	for _, o := range []time.Duration{time.Minute, time.Hour, 2 * time.Hour} {
		e.Handle(collector.Sample{Timestamp: base.Add(o), Services: down})
	}
	if len(pub.published) != 1 {
		t.Fatalf("expected exactly one notification, got %d: %v", len(pub.published), pub.published)
	}
}

// Recovery must clear the repeat clock so a later outage alerts at once.
func TestServiceRecoveryResetsRepeatClock(t *testing.T) {
	pub := &fakePublisher{}
	e := NewEvaluator(pub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.SetRules(nil, []ServiceRule{{
		Name: "nginx", ServiceName: "nginx", NotifyOnRecovery: true, RepeatInterval: time.Hour,
	}})

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	up := []collector.ServiceStatus{{Name: "nginx", Running: true}}
	down := []collector.ServiceStatus{{Name: "nginx", Running: false}}
	e.Handle(collector.Sample{Timestamp: base, Services: up})
	e.Handle(collector.Sample{Timestamp: base.Add(time.Minute), Services: down})     // DOWN
	e.Handle(collector.Sample{Timestamp: base.Add(2 * time.Minute), Services: up})   // recovered
	e.Handle(collector.Sample{Timestamp: base.Add(3 * time.Minute), Services: down}) // DOWN again

	var downs int
	for _, m := range pub.published {
		if strings.Contains(m, "is DOWN") {
			downs++
		}
	}
	if downs != 2 {
		t.Fatalf("expected two outage alerts, got %d: %v", downs, pub.published)
	}
}

func TestServiceRuleRoundTripsRepeatInterval(t *testing.T) {
	data, err := json.Marshal(ServiceRule{Name: "n", ServiceName: "nginx", RepeatInterval: 30 * time.Minute})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"repeat_interval":"30m0s"`) {
		t.Fatalf("missing repeat_interval: %s", data)
	}
	var out ServiceRule
	if err := json.Unmarshal([]byte(`{"name":"n","service_name":"nginx","notify_on_recovery":true}`), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.RepeatInterval != 0 || !out.NotifyOnRecovery {
		t.Errorf("older payload should decode to zero repeat: %+v", out)
	}
}
