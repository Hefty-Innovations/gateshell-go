// Package config loads GateShell Agent configuration from flags, environment
// variables, and an optional config file, in that order of precedence
// (flags > env > file > defaults).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Hefty-Innovations/gateshell-go/internal/alerts"
)

// Default values used when a setting is not supplied by any other source.
const (
	DefaultListenAddr   = "127.0.0.1:8443"
	DefaultDBPath       = "gateshell-agent.db"
	DefaultPollInterval = 5 * time.Minute
	DefaultServerName   = "gateshell-agent"
)

// Config holds all runtime configuration for the agent.
//
// Precedence (highest to lowest): CLI flags > environment variables >
// config file (JSON or TOML) > built-in defaults.
type Config struct {
	// ListenAddr is the host:port the REST/WebSocket API binds to.
	// Reachability (port-forwarding, firewalls, reverse proxies) is left
	// entirely to the operator -- the agent does not attempt NAT traversal,
	// UPnP, or tunneling of any kind.
	ListenAddr string `json:"listen_addr" toml:"listen_addr"`

	// DBPath is the filesystem path to the embedded SQLite database file
	// used for metric history. Ignored by the in-memory store build.
	DBPath string `json:"db_path" toml:"db_path"`

	// PollInterval is how often the collector gathers a new Sample.
	PollInterval time.Duration `json:"poll_interval" toml:"poll_interval"`

	// PairingToken is the bearer token the mobile app must present to
	// authenticate against the REST/WebSocket API. Generated once during
	// `pair` / install and persisted by the operator (e.g. in the systemd
	// unit's environment file). See internal/pair for generation helpers.
	PairingToken string `json:"pairing_token" toml:"pairing_token"`

	// PushRelayToken is a high-entropy secret (e.g. `openssl rand -hex 32`)
	// the operator generates once and configures here to enable APNs alert
	// delivery via the GateShell push relay -- see internal/pushrelay.
	// Empty disables it. It authenticates this agent to the relay AND
	// doubles as the relay's lookup key for this agent's registered device
	// token; it is never sent anywhere but the relay, over HTTPS.
	PushRelayToken string `json:"push_relay_token" toml:"push_relay_token"`

	// PushRelayURL overrides the relay this agent talks to (default:
	// pushrelay.DefaultBaseURL, GateShell's own hosted relay) -- for
	// operators running their own. Ignored if PushRelayToken is empty.
	PushRelayURL string `json:"push_relay_url" toml:"push_relay_url"`

	// ServerName is a human-friendly label for this host, included in API
	// responses and alert payloads so a multi-server user can tell agents
	// apart.
	ServerName string `json:"server_name" toml:"server_name"`

	// Rules and ServiceRules are the alert.Evaluator's configured rule set.
	// Empty by default -- no alerts fire until the mobile app configures at
	// least one via PATCH /api/v1/alerts. Persisted like PollInterval (see
	// SaveRules), not merged/overridden by flags or env vars -- there's no
	// sane CLI/env representation for a rule list, so the config file (or
	// the runtime API) is the only way to set these.
	Rules        []alerts.Rule        `json:"rules,omitempty" toml:"-"`
	ServiceRules []alerts.ServiceRule `json:"service_rules,omitempty" toml:"-"`

	// FilePath is the resolved path of the config file this Config was
	// loaded from (empty if none was supplied). It is not itself a
	// persisted setting -- it lets runtime consumers (e.g. the config API
	// persisting an app-driven poll-interval change) know which file to
	// write back to. Never marshaled.
	FilePath string `json:"-" toml:"-"`
}

// Defaults returns a Config populated with built-in defaults.
func Defaults() Config {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = DefaultServerName
	}
	return Config{
		ListenAddr:     DefaultListenAddr,
		DBPath:         DefaultDBPath,
		PollInterval:   DefaultPollInterval,
		PairingToken:   "",
		PushRelayToken: "",
		PushRelayURL:   "",
		ServerName:     hostname,
	}
}

// FlagOverrides carries values parsed from CLI flags. A pointer field left
// nil means "flag not set" and should not override lower-precedence sources.
// cmd/gateshell-agent wires cobra flags into this struct.
type FlagOverrides struct {
	ConfigFile     string
	ListenAddr     *string
	DBPath         *string
	PollInterval   *time.Duration
	PairingToken   *string
	PushRelayToken *string
	PushRelayURL   *string
	ServerName     *string
}

// Load builds the final Config by layering, from lowest to highest
// precedence: built-in defaults, an optional config file, environment
// variables, then CLI flag overrides.
//
// Supported env vars: GATESHELL_AGENT_LISTEN_ADDR, GATESHELL_AGENT_DB_PATH,
// GATESHELL_AGENT_POLL_INTERVAL, GATESHELL_AGENT_PAIRING_TOKEN,
// GATESHELL_AGENT_PUSH_RELAY_TOKEN,
// GATESHELL_AGENT_PUSH_RELAY_URL, GATESHELL_AGENT_SERVER_NAME.
func Load(flags FlagOverrides) (Config, error) {
	cfg := Defaults()

	if flags.ConfigFile != "" {
		fileCfg, err := loadFile(flags.ConfigFile)
		if err != nil {
			return Config{}, fmt.Errorf("config: loading file %q: %w", flags.ConfigFile, err)
		}
		cfg = mergeNonZero(cfg, fileCfg)
	}

	cfg = applyEnv(cfg)
	cfg = applyFlags(cfg, flags)
	cfg.FilePath = flags.ConfigFile

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// SavePollInterval persists the poll interval to the JSON config file at
// path, preserving any other keys already present in the file. It is used
// by the runtime config API (PATCH /api/v1/config) so an app-driven
// interval change survives a restart.
//
// Note on precedence: this writes to the config *file* only. A
// --poll-interval flag or GATESHELL_AGENT_POLL_INTERVAL env var still wins
// over the file on the next start (see Load's precedence). Deployments that
// want app-driven changes to stick should configure the interval via the
// file (as install.sh does), not via a flag/env override.
func SavePollInterval(path string, d time.Duration) error {
	return saveConfigField(path, "poll_interval", d.String())
}

// SaveRules persists the alert rule set to the JSON config file at path,
// the same way SavePollInterval persists an app-driven poll-interval
// change -- preserving every other key already present in the file. Used
// by PATCH /api/v1/alerts so a rule set configured from the mobile app
// survives a restart.
func SaveRules(path string, rules []alerts.Rule, serviceRules []alerts.ServiceRule) error {
	if rules == nil {
		rules = []alerts.Rule{}
	}
	if serviceRules == nil {
		serviceRules = []alerts.ServiceRule{}
	}
	return saveConfigFields(path, map[string]any{
		"rules":         rules,
		"service_rules": serviceRules,
	})
}

// saveConfigField is saveConfigFields for a single key.
func saveConfigField(path, key string, value any) error {
	return saveConfigFields(path, map[string]any{key: value})
}

// saveConfigFields loads the JSON config file at path into a generic map
// (preserving any keys the caller isn't setting -- e.g. listen_addr,
// poll_interval), overlays fields, and writes the result back atomically
// (temp file + rename) so a crash mid-write can't leave a truncated config
// behind.
func saveConfigFields(path string, fields map[string]any) error {
	if path == "" {
		return errors.New("config: no config file path configured; cannot persist setting")
	}
	if ext := strings.ToLower(filepath.Ext(path)); ext != ".json" && ext != "" {
		// loadFile only decodes JSON today; refuse to write a JSON body
		// into a differently-typed file rather than corrupt it.
		return fmt.Errorf("config: cannot persist to non-JSON config file %q", path)
	}

	raw := map[string]any{}
	if data, err := os.ReadFile(path); err == nil {
		if len(data) > 0 {
			if err := json.Unmarshal(data, &raw); err != nil {
				return fmt.Errorf("config: parsing existing file %q: %w", path, err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("config: reading file %q: %w", path, err)
	}

	for key, value := range fields {
		raw[key] = value
	}

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("config: marshaling config: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o600); err != nil {
		return fmt.Errorf("config: writing temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("config: renaming temp file into place: %w", err)
	}
	return nil
}

// loadFile reads a JSON or TOML config file based on its extension.
//
// TODO: wire in a TOML decoder (e.g. github.com/BurntSushi/toml) once a
// dependency budget is agreed for the release build. JSON is fully
// supported today; ".toml" currently returns an error so callers get a
// clear signal instead of silently ignoring the file.
func loadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var raw struct {
		ListenAddr     string               `json:"listen_addr"`
		DBPath         string               `json:"db_path"`
		PollInterval   string               `json:"poll_interval"`
		PairingToken   string               `json:"pairing_token"`
		PushRelayToken string               `json:"push_relay_token"`
		PushRelayURL   string               `json:"push_relay_url"`
		ServerName     string               `json:"server_name"`
		Rules          []alerts.Rule        `json:"rules"`
		ServiceRules   []alerts.ServiceRule `json:"service_rules"`
	}

	switch ext := strings.ToLower(filepath.Ext(path)); ext {
	case ".json", "":
		if err := json.Unmarshal(data, &raw); err != nil {
			return Config{}, fmt.Errorf("parsing JSON: %w", err)
		}
	case ".toml":
		// TODO(toml): decode TOML here. See doc comment above.
		return Config{}, errors.New("TOML config files are not yet supported; use JSON")
	default:
		return Config{}, fmt.Errorf("unrecognized config file extension %q", ext)
	}

	var cfg Config
	cfg.ListenAddr = raw.ListenAddr
	cfg.DBPath = raw.DBPath
	cfg.PairingToken = raw.PairingToken
	cfg.PushRelayToken = raw.PushRelayToken
	cfg.PushRelayURL = raw.PushRelayURL
	cfg.ServerName = raw.ServerName
	cfg.Rules = raw.Rules
	cfg.ServiceRules = raw.ServiceRules
	if raw.PollInterval != "" {
		d, err := time.ParseDuration(raw.PollInterval)
		if err != nil {
			return Config{}, fmt.Errorf("parsing poll_interval: %w", err)
		}
		cfg.PollInterval = d
	}
	return cfg, nil
}

// mergeNonZero overlays non-zero-valued fields from override onto base.
func mergeNonZero(base, override Config) Config {
	if override.ListenAddr != "" {
		base.ListenAddr = override.ListenAddr
	}
	if override.DBPath != "" {
		base.DBPath = override.DBPath
	}
	if override.PollInterval != 0 {
		base.PollInterval = override.PollInterval
	}
	if override.PairingToken != "" {
		base.PairingToken = override.PairingToken
	}
	if override.PushRelayToken != "" {
		base.PushRelayToken = override.PushRelayToken
	}
	if override.PushRelayURL != "" {
		base.PushRelayURL = override.PushRelayURL
	}
	if override.ServerName != "" {
		base.ServerName = override.ServerName
	}
	if override.Rules != nil {
		base.Rules = override.Rules
	}
	if override.ServiceRules != nil {
		base.ServiceRules = override.ServiceRules
	}
	return base
}

func applyEnv(cfg Config) Config {
	if v := os.Getenv("GATESHELL_AGENT_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("GATESHELL_AGENT_DB_PATH"); v != "" {
		cfg.DBPath = v
	}
	if v := os.Getenv("GATESHELL_AGENT_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.PollInterval = d
		}
	}
	if v := os.Getenv("GATESHELL_AGENT_PAIRING_TOKEN"); v != "" {
		cfg.PairingToken = v
	}
	if v := os.Getenv("GATESHELL_AGENT_PUSH_RELAY_TOKEN"); v != "" {
		cfg.PushRelayToken = v
	}
	if v := os.Getenv("GATESHELL_AGENT_PUSH_RELAY_URL"); v != "" {
		cfg.PushRelayURL = v
	}
	if v := os.Getenv("GATESHELL_AGENT_SERVER_NAME"); v != "" {
		cfg.ServerName = v
	}
	return cfg
}

func applyFlags(cfg Config, flags FlagOverrides) Config {
	if flags.ListenAddr != nil && *flags.ListenAddr != "" {
		cfg.ListenAddr = *flags.ListenAddr
	}
	if flags.DBPath != nil && *flags.DBPath != "" {
		cfg.DBPath = *flags.DBPath
	}
	if flags.PollInterval != nil && *flags.PollInterval != 0 {
		cfg.PollInterval = *flags.PollInterval
	}
	if flags.PairingToken != nil && *flags.PairingToken != "" {
		cfg.PairingToken = *flags.PairingToken
	}
	if flags.PushRelayToken != nil && *flags.PushRelayToken != "" {
		cfg.PushRelayToken = *flags.PushRelayToken
	}
	if flags.PushRelayURL != nil && *flags.PushRelayURL != "" {
		cfg.PushRelayURL = *flags.PushRelayURL
	}
	if flags.ServerName != nil && *flags.ServerName != "" {
		cfg.ServerName = *flags.ServerName
	}
	return cfg
}

// Validate performs basic sanity checks on the config. It intentionally does
// NOT require a PairingToken -- `gateshell-agent pair` may be used to
// generate one interactively after first boot -- but `serve` should refuse
// to start without one (see cmd/gateshell-agent).
func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return errors.New("config: listen address must not be empty")
	}
	if c.PollInterval <= 0 {
		return errors.New("config: poll interval must be positive")
	}
	if c.DBPath == "" {
		return errors.New("config: db path must not be empty")
	}
	return nil
}

// ParsePollIntervalFlag is a small helper for CLI wiring that needs to parse
// a duration-like flag value (e.g. "15s", "1m") with a friendlier error.
func ParsePollIntervalFlag(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	// Allow bare integers to mean seconds, matching common CLI conventions.
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(s)
}
