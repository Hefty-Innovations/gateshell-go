package pushrelay

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTokenStore_RoundTripsMultipleDevices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "push-token.json")
	ts, err := NewTokenStore(path)
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	if err := ts.Set("phone", EnvironmentProduction, ""); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// A Mac on a development build alongside a production iPhone is the
	// normal case, not an edge case.
	if err := ts.Set("mac", EnvironmentDevelopment, ""); err != nil {
		t.Fatalf("Set: %v", err)
	}

	reloaded, err := NewTokenStore(path)
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	all := reloaded.All()
	if len(all) != 2 {
		t.Fatalf("expected both devices to survive a restart, got %d", len(all))
	}
	if all[0].Token != "phone" || all[0].Environment != EnvironmentProduction {
		t.Errorf("unexpected first registration: %+v", all[0])
	}
	if all[1].Token != "mac" || all[1].Environment != EnvironmentDevelopment {
		t.Errorf("unexpected second registration: %+v", all[1])
	}
}

// Registering the same device again happens routinely (the app re-registers
// whenever a token arrives) and must not accumulate duplicates.
func TestTokenStore_ReregisteringSameDeviceUpdatesInPlace(t *testing.T) {
	ts, _ := NewTokenStore(filepath.Join(t.TempDir(), "t.json"))
	_ = ts.Set("phone", EnvironmentProduction, "")
	_ = ts.Set("phone", EnvironmentDevelopment, "")

	all := ts.All()
	if len(all) != 1 {
		t.Fatalf("expected one registration, got %d", len(all))
	}
	if all[0].Environment != EnvironmentDevelopment {
		t.Errorf("expected the environment to be updated, got %q", all[0].Environment)
	}
}

// Every agent installed before multi-device support has a single-token file
// on disk; it must keep working and must not lose its device.
func TestTokenStore_MigratesLegacySingleTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "push-token.json")
	if err := os.WriteFile(path, []byte(`{"token":"legacy","environment":"development"}`), 0o600); err != nil {
		t.Fatalf("writing legacy file: %v", err)
	}
	ts, err := NewTokenStore(path)
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	all := ts.All()
	if len(all) != 1 || all[0].Token != "legacy" {
		t.Fatalf("expected the legacy token to migrate, got %+v", all)
	}
	if all[0].Environment != EnvironmentDevelopment {
		t.Errorf("expected the legacy environment to survive, got %q", all[0].Environment)
	}
}

func TestTokenStore_LegacyFileWithoutEnvironmentIsProduction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "push-token.json")
	_ = os.WriteFile(path, []byte(`{"token":"legacy"}`), 0o600)
	ts, _ := NewTokenStore(path)
	if all := ts.All(); len(all) != 1 || all[0].Environment != EnvironmentProduction {
		t.Errorf("expected production, got %+v", all)
	}
}

func TestTokenStore_RemoveDropsOnlyThatDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.json")
	ts, _ := NewTokenStore(path)
	_ = ts.Set("phone", EnvironmentProduction, "")
	_ = ts.Set("mac", EnvironmentDevelopment, "")

	if err := ts.Remove("phone"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	reloaded, _ := NewTokenStore(path)
	all := reloaded.All()
	if len(all) != 1 || all[0].Token != "mac" {
		t.Fatalf("expected only the mac to remain, got %+v", all)
	}
	if reloaded.Count() != 1 {
		t.Errorf("Count disagrees with All: %d", reloaded.Count())
	}
}

func TestTokenStore_NormalizesUnrecognizedEnvironment(t *testing.T) {
	ts, _ := NewTokenStore(filepath.Join(t.TempDir(), "t.json"))
	_ = ts.Set("d", "staging", "")
	if all := ts.All(); all[0].Environment != EnvironmentProduction {
		t.Errorf("expected production fallback, got %q", all[0].Environment)
	}
}
