package pushrelay

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

// EnvironmentProduction and EnvironmentDevelopment are the two APNs
// environments a device token can belong to. A token minted by an app
// signed with aps-environment=development is only valid against Apple's
// sandbox host, and one minted by a production-signed app only against
// the production host -- sending to the wrong one fails with
// BadDeviceToken, so the app reports which one its own signed entitlement
// says it is (POST /api/v1/push-token) and that travels with the token all
// the way to the relay.
const (
	EnvironmentProduction  = "production"
	EnvironmentDevelopment = "development"
)

// NormalizeEnvironment maps an environment string to one of the two valid
// values, defaulting to production. Empty is expected and not an error:
// tokens persisted by agents predating this field, and app builds that
// don't send it, are production (the only environment the relay supported
// before), so that's what they keep meaning.
func NormalizeEnvironment(env string) string {
	if env == EnvironmentDevelopment {
		return EnvironmentDevelopment
	}
	return EnvironmentProduction
}

// Registration is one device that should receive this agent's alerts.
// A Mac and an iPhone paired to the same agent are two registrations, and
// they can legitimately sit in different APNs environments (a Mac running
// a development build alongside a TestFlight iPhone).
type Registration struct {
	Token       string `json:"token"`
	Environment string `json:"environment"`
	// Label names the device ("Anil's Mac"), so an operator can see which
	// devices an agent will notify and a delivery failure can name one
	// instead of a hex blob. Empty for registrations made before labels.
	Label string `json:"label,omitempty"`
}

// DisplayLabel is Label, or a readable stand-in when a device registered
// before labels existed.
func (r Registration) DisplayLabel() string {
	if r.Label != "" {
		return r.Label
	}
	return "Unnamed device"
}

// TokenStore persists every APNs device token registered with this agent
// (POST /api/v1/push-token), across restarts.
//
// This was a single token until multi-device support: registering a second
// device silently replaced the first, so pairing a Mac stopped the iPhone
// receiving anything, with no indication either had happened.
type TokenStore struct {
	path string

	mu            sync.RWMutex
	registrations []Registration
}

// NewTokenStore loads any previously persisted registrations from path
// (which need not exist yet).
func NewTokenStore(path string) (*TokenStore, error) {
	ts := &TokenStore{path: path}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ts, nil
		}
		return nil, err
	}

	var raw struct {
		Registrations []Registration `json:"registrations"`
		// Legacy single-token shape, still on disk for every agent
		// installed before multi-device support.
		Token       string `json:"token"`
		Environment string `json:"environment"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	switch {
	case len(raw.Registrations) > 0:
		for _, r := range raw.Registrations {
			if r.Token == "" {
				continue
			}
			ts.registrations = append(ts.registrations, Registration{
				Token: r.Token, Environment: NormalizeEnvironment(r.Environment), Label: r.Label,
			})
		}
	case raw.Token != "":
		// A file written before this field existed holds a production
		// token -- that was the only environment the relay could reach.
		ts.registrations = []Registration{{
			Token: raw.Token, Environment: NormalizeEnvironment(raw.Environment),
		}}
	}
	return ts, nil
}

// All returns every registered device, newest last.
func (ts *TokenStore) All() []Registration {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	out := make([]Registration, len(ts.registrations))
	copy(out, ts.registrations)
	return out
}

// Labels names every registered device, for display. Never returns tokens.
func (ts *TokenStore) Labels() []string {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	out := make([]string, 0, len(ts.registrations))
	for _, r := range ts.registrations {
		out = append(out, r.DisplayLabel())
	}
	return out
}

// Find returns the registration for a token, if it is registered.
func (ts *TokenStore) Find(token string) (Registration, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	for _, r := range ts.registrations {
		if r.Token == token {
			return r, true
		}
	}
	return Registration{}, false
}

// Count reports how many devices are registered.
func (ts *TokenStore) Count() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return len(ts.registrations)
}

// Set adds a device, or updates its environment if it is already known.
// Re-registering the same device (the app does this whenever a token
// arrives) must not create a duplicate.
func (ts *TokenStore) Set(token, environment, label string) error {
	if token == "" {
		return errors.New("pushrelay: token must not be empty")
	}
	environment = NormalizeEnvironment(environment)

	ts.mu.Lock()
	replaced := false
	for i := range ts.registrations {
		if ts.registrations[i].Token == token {
			ts.registrations[i].Environment = environment
			if label != "" {
				ts.registrations[i].Label = label
			}
			replaced = true
			break
		}
	}
	if !replaced {
		ts.registrations = append(ts.registrations, Registration{Token: token, Environment: environment, Label: label})
	}
	snapshot := make([]Registration, len(ts.registrations))
	copy(snapshot, ts.registrations)
	ts.mu.Unlock()

	return ts.persist(snapshot)
}

// Remove drops a device. Called when the relay reports APNs considers the
// token dead (410 Unregistered): without this, a deleted app's token stays
// forever and every alert keeps paying for a delivery that cannot land.
func (ts *TokenStore) Remove(token string) error {
	ts.mu.Lock()
	kept := ts.registrations[:0]
	for _, r := range ts.registrations {
		if r.Token != token {
			kept = append(kept, r)
		}
	}
	ts.registrations = kept
	snapshot := make([]Registration, len(ts.registrations))
	copy(snapshot, ts.registrations)
	ts.mu.Unlock()

	return ts.persist(snapshot)
}

func (ts *TokenStore) persist(registrations []Registration) error {
	if registrations == nil {
		registrations = []Registration{}
	}
	data, err := json.Marshal(struct {
		Registrations []Registration `json:"registrations"`
	}{Registrations: registrations})
	if err != nil {
		return err
	}

	// Atomic write (temp file + rename), matching config.SavePollInterval.
	tmp := ts.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ts.path)
}
