package pushrelay

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Hefty-Innovations/gateshell-go/internal/collector"
)

func sample() collector.Sample {
	return collector.Sample{
		Timestamp:   time.Unix(1_700_000_000, 0),
		CPUPercent:  41.47,
		MemUsedMB:   4000,
		MemTotalMB:  8000,
		DiskUsedGB:  65,
		DiskTotalGB: 100,
	}
}

func TestNotifyDerivesPercentagesFromTheSample(t *testing.T) {
	var got WidgetMetrics
	n := NewWidgetNotifier(func(_ context.Context, m WidgetMetrics) error {
		got = m
		return nil
	}, time.Minute)

	sent, err := n.Notify(context.Background(), "api-prod-01", sample())
	if err != nil || !sent {
		t.Fatalf("Notify() = %v, %v; want true, nil", sent, err)
	}
	if got.ServerName != "api-prod-01" {
		t.Errorf("ServerName = %q", got.ServerName)
	}
	if got.CPUPercent != 41.5 {
		t.Errorf("CPUPercent = %v, want 41.5 (rounded)", got.CPUPercent)
	}
	if got.MemoryPercent == nil || *got.MemoryPercent != 50 {
		t.Errorf("MemoryPercent = %v, want 50", got.MemoryPercent)
	}
	if got.DiskUsePercent == nil || *got.DiskUsePercent != 65 {
		t.Errorf("DiskUsePercent = %v, want 65", got.DiskUsePercent)
	}
	if !got.CapturedAt.Equal(time.Unix(1_700_000_000, 0)) {
		t.Errorf("CapturedAt = %v", got.CapturedAt)
	}
}

func TestNotifyOmitsPercentagesWithoutATotal(t *testing.T) {
	var got WidgetMetrics
	n := NewWidgetNotifier(func(_ context.Context, m WidgetMetrics) error {
		got = m
		return nil
	}, time.Minute)

	s := sample()
	s.MemTotalMB = 0
	s.DiskTotalGB = 0
	if _, err := n.Notify(context.Background(), "srv", s); err != nil {
		t.Fatal(err)
	}
	if got.MemoryPercent != nil || got.DiskUsePercent != nil {
		t.Errorf("want nil percentages when totals are unknown, got %v / %v",
			got.MemoryPercent, got.DiskUsePercent)
	}
}

// Apple budgets background pushes per app per device; a 15s collector must not
// spend that budget every tick.
func TestNotifyThrottlesWithinTheInterval(t *testing.T) {
	calls := 0
	n := NewWidgetNotifier(func(context.Context, WidgetMetrics) error {
		calls++
		return nil
	}, 15*time.Minute)
	base := time.Unix(1_700_000_000, 0)
	n.now = func() time.Time { return base }

	for i := 0; i < 5; i++ {
		if _, err := n.Notify(context.Background(), "srv", sample()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("publish called %d times within one interval; want 1", calls)
	}

	n.now = func() time.Time { return base.Add(16 * time.Minute) }
	sent, err := n.Notify(context.Background(), "srv", sample())
	if err != nil || !sent {
		t.Fatalf("Notify() after the interval = %v, %v; want true, nil", sent, err)
	}
	if calls != 2 {
		t.Fatalf("publish called %d times; want 2 after the interval elapsed", calls)
	}
}

// A relay hiccup must not cost a whole interval of silence.
func TestFailedSendDoesNotConsumeTheInterval(t *testing.T) {
	calls := 0
	fail := true
	n := NewWidgetNotifier(func(context.Context, WidgetMetrics) error {
		calls++
		if fail {
			return errors.New("relay down")
		}
		return nil
	}, 15*time.Minute)
	base := time.Unix(1_700_000_000, 0)
	n.now = func() time.Time { return base }

	if _, err := n.Notify(context.Background(), "srv", sample()); err == nil {
		t.Fatal("want an error from the first send")
	}
	fail = false
	sent, err := n.Notify(context.Background(), "srv", sample())
	if err != nil || !sent {
		t.Fatalf("retry = %v, %v; want true, nil", sent, err)
	}
	if calls != 2 {
		t.Fatalf("publish called %d times; want 2 (the retry must not be throttled)", calls)
	}
}

func TestZeroIntervalFallsBackToTheDefault(t *testing.T) {
	n := NewWidgetNotifier(func(context.Context, WidgetMetrics) error { return nil }, 0)
	if n.interval != DefaultWidgetInterval {
		t.Fatalf("interval = %v, want %v", n.interval, DefaultWidgetInterval)
	}
}
