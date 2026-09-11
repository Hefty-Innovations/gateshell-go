package pushrelay

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/Hefty-Innovations/gateshell-go/internal/collector"
)

// MinWidgetInterval is the floor on how often a silent metrics push goes out,
// regardless of how fast the collector is polling.
//
// Apple budgets background (`content-available`) pushes per app per device and
// throttles an app that spends them faster than the user actually looks at it.
// A 15s collector pushing every sample would burn that budget within minutes
// and get later pushes dropped -- including ones the user would have wanted.
// Ten minutes caps it at six per hour, which a widget can spend honestly.
const MinWidgetInterval = 10 * time.Minute

// WidgetMetrics is the subset of a Sample worth waking a phone for: the three
// numbers the Health widget actually renders, plus when they were taken.
type WidgetMetrics struct {
	ServerName     string
	CPUPercent     float64
	MemoryPercent  *float64
	DiskUsePercent *int
	CapturedAt     time.Time
}

// WidgetNotifier turns collector samples into throttled silent pushes.
//
// The iOS Health widget can only render what the app last wrote to its shared
// store, and the only writer was a foreground metrics tick -- so the widget
// froze the moment the app was closed, regardless of how often this agent
// polled. These pushes let the agent's own cycle drive it.
type WidgetNotifier struct {
	publish func(ctx context.Context, m WidgetMetrics) error
	// Read fresh on every sample so a poll-interval change from the app takes
	// effect without a restart -- the same contract Collector.Run has.
	pollInterval func() time.Duration
	now          func() time.Time

	mu       sync.Mutex
	lastSent time.Time
}

// NewWidgetNotifier follows pollInterval so the widget tracks the cadence the
// user configured, never faster than MinWidgetInterval.
func NewWidgetNotifier(
	publish func(ctx context.Context, m WidgetMetrics) error,
	pollInterval func() time.Duration,
) *WidgetNotifier {
	if pollInterval == nil {
		pollInterval = func() time.Duration { return MinWidgetInterval }
	}
	return &WidgetNotifier{publish: publish, pollInterval: pollInterval, now: time.Now}
}

// Interval is the effective push cadence: the configured poll interval, floored
// at MinWidgetInterval.
func (w *WidgetNotifier) Interval() time.Duration {
	d := w.pollInterval()
	if d < MinWidgetInterval {
		return MinWidgetInterval
	}
	return d
}

// Notify sends at most one push per interval. It reports whether it sent, so
// callers can log or test the throttle; a skipped push is not an error.
func (w *WidgetNotifier) Notify(ctx context.Context, serverName string, s collector.Sample) (bool, error) {
	if w == nil || w.publish == nil {
		return false, nil
	}

	interval := w.Interval()

	w.mu.Lock()
	now := w.now()
	if !w.lastSent.IsZero() && now.Sub(w.lastSent) < interval {
		w.mu.Unlock()
		return false, nil
	}
	// Claim the slot before the network call: a slow relay must not let a
	// second sample slip past the throttle while the first is still in flight.
	previous := w.lastSent
	w.lastSent = now
	w.mu.Unlock()

	err := w.publish(ctx, metricsFrom(serverName, s))
	if err != nil {
		// A failed send should not cost the next interval -- restore the
		// previous stamp so the following sample can try again.
		w.mu.Lock()
		if w.lastSent.Equal(now) {
			w.lastSent = previous
		}
		w.mu.Unlock()
		return false, err
	}
	return true, nil
}

func metricsFrom(serverName string, s collector.Sample) WidgetMetrics {
	m := WidgetMetrics{
		ServerName: serverName,
		CPUPercent: round1(s.CPUPercent),
		CapturedAt: s.Timestamp,
	}
	if s.MemTotalMB > 0 {
		pct := round1(s.MemUsedMB / s.MemTotalMB * 100)
		m.MemoryPercent = &pct
	}
	if s.DiskTotalGB > 0 {
		pct := int(math.Round(s.DiskUsedGB / s.DiskTotalGB * 100))
		m.DiskUsePercent = &pct
	}
	return m
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}
