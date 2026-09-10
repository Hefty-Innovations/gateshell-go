package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Hefty-Innovations/gateshell-go/internal/alerts"
)

// TestSaveRulesPreservesOtherKeys covers the same "preserve unrelated keys"
// requirement SavePollInterval already has -- SaveRules must not clobber
// listen_addr/etc. that happen to already be in the file, including keys
// this build no longer recognises (ntfy_topic, left behind by agents
// predating the removal of ntfy support).
func TestSaveRulesPreservesOtherKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"listen_addr":"127.0.0.1:9999","ntfy_topic":"my-topic"}`), 0o600); err != nil {
		t.Fatalf("seeding config file: %v", err)
	}

	rules := []alerts.Rule{
		{Name: "High CPU", Metric: alerts.MetricCPUPercent, Comparator: alerts.ComparatorGreaterThan, Threshold: 90, For: time.Minute},
	}
	if err := SaveRules(path, rules, nil); err != nil {
		t.Fatalf("SaveRules: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parsing written file: %v", err)
	}
	if raw["listen_addr"] != "127.0.0.1:9999" {
		t.Errorf("expected listen_addr to survive, got %#v", raw["listen_addr"])
	}
	if raw["ntfy_topic"] != "my-topic" {
		t.Errorf("an unrecognised key must survive a rewrite, got %#v", raw["ntfy_topic"])
	}
	if _, ok := raw["rules"]; !ok {
		t.Error("expected a \"rules\" key to have been written")
	}
}

// TestSaveRulesThenLoadFileRoundTrips covers the other half: what SaveRules
// writes, loadFile (via Load) must be able to read back, since that's the
// whole point of persisting -- surviving a restart means the next Load()
// picks it up.
func TestSaveRulesThenLoadFileRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("seeding config file: %v", err)
	}

	rules := []alerts.Rule{
		{Name: "High CPU", Metric: alerts.MetricCPUPercent, Comparator: alerts.ComparatorGreaterThan, Threshold: 90, For: 90 * time.Second},
	}
	serviceRules := []alerts.ServiceRule{
		{Name: "nginx down", ServiceName: "nginx", NotifyOnRecovery: true},
	}
	if err := SaveRules(path, rules, serviceRules); err != nil {
		t.Fatalf("SaveRules: %v", err)
	}

	cfg, err := Load(FlagOverrides{ConfigFile: path, PairingToken: strPtr("tok")})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0] != rules[0] {
		t.Errorf("Rules = %+v, want %+v", cfg.Rules, rules)
	}
	if len(cfg.ServiceRules) != 1 || cfg.ServiceRules[0] != serviceRules[0] {
		t.Errorf("ServiceRules = %+v, want %+v", cfg.ServiceRules, serviceRules)
	}
}

func strPtr(s string) *string { return &s }
