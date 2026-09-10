// Command gateshell-agent is the optional, self-hosted binary that runs ON
// a user's server: it collects local metrics + service health on an
// interval, stores them (embedded SQLite with tiered retention, when built
// with `-tags sqlite`), serves them to the GateShell mobile app over a
// token-authed REST + SSE API, and pushes threshold alerts as Apple Push
// notifications through the GateShell push relay (see internal/pushrelay --
// this agent never holds an Apple credential itself).
//
// It has NO web UI. Reachability (port-forwarding, reverse proxy, VPN,
// Tailscale, etc.) is entirely the operator's concern -- this binary just
// binds ListenAddr and serves.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	mosh "github.com/unixshells/mosh-go"

	"github.com/Hefty-Innovations/gateshell-go/internal/alerts"
	"github.com/Hefty-Innovations/gateshell-go/internal/api"
	"github.com/Hefty-Innovations/gateshell-go/internal/collector"
	"github.com/Hefty-Innovations/gateshell-go/internal/config"
	"github.com/Hefty-Innovations/gateshell-go/internal/pair"
	"github.com/Hefty-Innovations/gateshell-go/internal/pushrelay"
	"github.com/Hefty-Innovations/gateshell-go/internal/securityaudit"
)

// version is overridden at build time via:
//
//	go build -ldflags "-X main.version=v1.2.3"
//
// See .goreleaser.yaml for the release wiring.
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var (
		configFile     string
		listenAddr     string
		dbPath         string
		pollInterval   string
		pairingToken   string
		pushRelayToken string
		pushRelayURL   string
		serverName     string
	)

	root := &cobra.Command{
		Use:   "gateshell-agent",
		Short: "GateShell Agent: optional self-hosted metrics + alerting sidecar",
		Long: `GateShell Agent is an OPTIONAL, self-hosted binary that runs on your own
server. It collects local metrics and service health on an interval,
stores them locally, and serves them to the GateShell mobile app over a
token-authenticated REST + streaming API. It pushes threshold alerts to your
devices as Apple Push notifications through the GateShell relay. It has no web
UI, and network reachability is entirely up to you.`,
	}

	root.PersistentFlags().StringVar(&configFile, "config", "", "path to JSON config file (optional)")
	root.PersistentFlags().StringVar(&listenAddr, "listen-addr", "", "address to bind the API on (default \""+config.DefaultListenAddr+"\")")
	root.PersistentFlags().StringVar(&dbPath, "db-path", "", "path to the sqlite database file (default \""+config.DefaultDBPath+"\")")
	root.PersistentFlags().StringVar(&pollInterval, "poll-interval", "", "how often to collect metrics, e.g. \"15s\" (default 15s)")
	root.PersistentFlags().StringVar(&pairingToken, "token", "", "pairing token the mobile app must present (required for `serve`)")
	root.PersistentFlags().StringVar(&pushRelayToken, "push-relay-token", "",
		"secret enabling APNs alerts via the GateShell push relay, e.g. from `openssl rand -hex 32` (optional)")
	root.PersistentFlags().StringVar(&pushRelayURL, "push-relay-url", "",
		"push relay base URL, must be https:// (default \""+pushrelay.DefaultBaseURL+"\")")
	root.PersistentFlags().StringVar(&serverName, "server-name", "", "human-friendly name for this host (default: hostname)")

	loadConfig := func() (config.Config, error) {
		flags := config.FlagOverrides{ConfigFile: configFile}
		if listenAddr != "" {
			flags.ListenAddr = &listenAddr
		}
		if dbPath != "" {
			flags.DBPath = &dbPath
		}
		if pollInterval != "" {
			d, err := config.ParsePollIntervalFlag(pollInterval)
			if err != nil {
				return config.Config{}, fmt.Errorf("invalid --poll-interval: %w", err)
			}
			flags.PollInterval = &d
		}
		if pairingToken != "" {
			flags.PairingToken = &pairingToken
		}
		if pushRelayToken != "" {
			flags.PushRelayToken = &pushRelayToken
		}
		if pushRelayURL != "" {
			flags.PushRelayURL = &pushRelayURL
		}
		if serverName != "" {
			flags.ServerName = &serverName
		}
		return config.Load(flags)
	}

	root.AddCommand(newServeCmd(loadConfig))
	root.AddCommand(newVersionCmd())
	root.AddCommand(newPairCmd())
	root.AddCommand(newSecurityScanCmd())
	root.AddCommand(newMoshServerCmd())

	return root
}

// newMoshServerCmd provides a wire-compatible Mosh server from the same Go
// binary. It is intentionally a local CLI command rather than an API endpoint:
// SSH launches it as the authenticated user so the PTY has that user's shell,
// home directory, permissions, and environment.
func newMoshServerCmd() *cobra.Command {
	var shell, connectFile string
	var portLow, portHigh int
	command := &cobra.Command{
		Use:   "mosh-server",
		Short: "Start an encrypted Mosh terminal server for the current user",
		RunE: func(cmd *cobra.Command, args []string) error {
			if portLow < 1 || portHigh > 65535 || portLow > portHigh {
				return fmt.Errorf("invalid UDP port range %d:%d", portLow, portHigh)
			}
			// The SSH bootstrap script backgrounds this with `nohup … &`, but
			// nohup only blocks SIGHUP — it does not remove the process from
			// the SSH login session's systemd-logind scope. Most modern
			// distros default to `KillUserProcesses=yes`, which terminates
			// every process still in that scope, nohup'd or not, the moment
			// the bootstrap's own SSH session ends (which happens almost
			// immediately, once it's written the connect file and exited).
			// That kills this server a second or two after the client
			// finishes its UDP handshake, which is indistinguishable from a
			// real network drop on the client side. Setsid moves this
			// process into its own session, detached from the SSH login
			// session, so it survives that session ending.
			if _, err := syscall.Setsid(); err != nil && err != syscall.EPERM {
				return fmt.Errorf("detaching mosh server from session: %w", err)
			}
			server, err := mosh.NewServer(shell, portLow, portHigh)
			if err != nil {
				return fmt.Errorf("starting mosh server: %w", err)
			}
			line := server.ConnectLine()
			if connectFile != "" {
				if !filepath.IsAbs(connectFile) {
					return fmt.Errorf("--connect-file must be an absolute path")
				}
				file, err := os.OpenFile(connectFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
				if err != nil {
					return fmt.Errorf("creating connect file: %w", err)
				}
				if _, err = fmt.Fprintln(file, line); err != nil {
					file.Close()
					return fmt.Errorf("writing connect file: %w", err)
				}
				if err = file.Close(); err != nil {
					return fmt.Errorf("closing connect file: %w", err)
				}
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), line)
			}

			// mosh-go's Serve() blocks on cmd.Wait() for the shell it spawned,
			// and its own shutdown paths (notably the 60s timeout for a client
			// that never associates) only close Done() -- they never terminate
			// that shell. Nobody is attached to it, so it waits on its PTY
			// forever: Serve() never returns, and the UDP port plus the PTY
			// and shell are never released, because those closes sit after
			// cmd.Wait(). Each failed setup then leaked a process holding one
			// of the 1001 ports in the range until none were left and every
			// later bootstrap failed. Exiting when Done() fires releases the
			// port; the shell follows on its own once our PTY master closes.
			serveResult := make(chan error, 1)
			go func() { serveResult <- server.Serve() }()

			select {
			case err := <-serveResult:
				return err
			case <-server.Done():
				// Let a normal shutdown (shell exited, so Serve() is already
				// unwinding) report its own error rather than racing it.
				select {
				case err := <-serveResult:
					return err
				case <-time.After(2 * time.Second):
					return nil
				}
			}
		},
	}
	command.Flags().StringVar(&shell, "shell", "", "shell executable (default: $SHELL or /bin/sh)")
	command.Flags().StringVar(&connectFile, "connect-file", "", "secure absolute file used by a detached SSH bootstrap")
	command.Flags().IntVar(&portLow, "port-low", 60000, "lowest UDP port to bind")
	command.Flags().IntVar(&portHigh, "port-high", 61000, "highest UDP port to bind")
	return command
}

// newServeCmd wires config -> store -> collector -> alerts -> api and runs
// until SIGINT/SIGTERM.
func newServeCmd(loadConfig func() (config.Config, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the metrics collector and API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if cfg.PairingToken == "" {
				return fmt.Errorf("no pairing token configured; pass --token, set GATESHELL_AGENT_PAIRING_TOKEN, " +
					"or run `gateshell-agent pair` to generate one")
			}

			logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
			logger.Info("starting gateshell-agent",
				"version", version, "listen_addr", cfg.ListenAddr, "server_name", cfg.ServerName)

			st, err := newStore(cfg, logger)
			if err != nil {
				return fmt.Errorf("initializing store: %w", err)
			}
			defer st.Close()

			coll := collector.New(cfg.PollInterval, logger)

			// persistInterval writes an app-driven poll-interval change
			// (PATCH /api/v1/config) back to the config file so it
			// survives a restart. If no config file is in use, the change
			// still applies at runtime but can't be persisted.
			persistInterval := func(d time.Duration) error {
				if cfg.FilePath == "" {
					logger.Warn("poll interval changed at runtime but no --config file is set; " +
						"the change will not survive a restart")
					return nil
				}
				return config.SavePollInterval(cfg.FilePath, d)
			}

			// Push delivery via the GateShell push relay -- this agent
			// never holds an Apple credential itself, see internal/pushrelay.
			var publisher alerts.Publisher
			var pushTokens api.PushTokenStore
			var pushTester api.PushTester
			if cfg.PushRelayToken != "" {
				relayClient, err := pushrelay.NewClient(cfg.PushRelayURL, cfg.PushRelayToken)
				if err != nil {
					return fmt.Errorf("configuring push relay: %w", err)
				}
				tokenStore, err := pushrelay.NewTokenStore(cfg.DBPath + ".push-token.json")
				if err != nil {
					return fmt.Errorf("initializing push token store: %w", err)
				}
				relayPublisher := pushrelay.NewPublisher(
					relayClient, cfg.ServerName, tokenStore.All, tokenStore.Remove, tokenStore.Find)
				publisher = relayPublisher
				pushTokens = tokenStore
				pushTester = relayPublisher
			}

			evaluator := alerts.NewEvaluator(publisher, logger)
			// Loaded from the config file via config.Load; empty (nil) by
			// default until PATCH /api/v1/alerts configures at least one.
			evaluator.SetRules(cfg.Rules, cfg.ServiceRules)

			// persistRules writes an app-driven alert-rules change (PATCH
			// /api/v1/alerts) back to the config file so it survives a
			// restart -- same "runtime-first, persistence best-effort"
			// shape as persistInterval above.
			persistRules := func(rules []alerts.Rule, serviceRules []alerts.ServiceRule) error {
				if cfg.FilePath == "" {
					logger.Warn("alert rules changed at runtime but no --config file is set; " +
						"the change will not survive a restart")
					return nil
				}
				return config.SaveRules(cfg.FilePath, rules, serviceRules)
			}

			auditScanner := securityaudit.NewCachedScanner(securityaudit.NewSystemScanner(), 5*time.Minute)

			apiServer := api.NewServer(
				st, cfg.PairingToken, cfg.ServerName, version, coll, persistInterval,
				evaluator, persistRules, auditScanner, pushTokens, publisher, pushTester, logger,
			)

			coll.AddSink(collector.SinkFunc(func(sample collector.Sample) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := st.SaveSample(ctx, sample); err != nil {
					logger.Error("saving sample failed", "error", err)
				}
			}))
			coll.AddSink(collector.SinkFunc(apiServer.BroadcastSample))
			coll.AddSink(evaluator)

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			errCh := make(chan error, 2)
			go func() {
				errCh <- coll.Run(ctx)
			}()
			go func() {
				errCh <- api.ListenAndServe(ctx, cfg.ListenAddr, apiServer)
			}()

			<-ctx.Done()
			logger.Info("shutting down")

			// Drain the two goroutines' exit errors (both should return
			// promptly now that ctx is canceled); context.Canceled from the
			// collector is expected, not an error worth surfacing.
			for i := 0; i < 2; i++ {
				if err := <-errCh; err != nil && err != context.Canceled {
					logger.Error("component exited with error", "error", err)
				}
			}
			return nil
		},
	}
}

// newSecurityScanCmd exposes the same deterministic read-only assessment as
// the API for diagnostics and for app fallback when the HTTP tunnel is not
// available. It never requires the pairing token because invoking the binary
// already requires local shell access.
func newSecurityScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "security-scan",
		Short: "Print a read-only host security assessment as JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(securityaudit.NewSystemScanner().Scan())
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the gateshell-agent version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), version)
			return nil
		},
	}
}

// newPairCmd generates a new pairing token for the operator to hand to the
// config file / systemd environment / `--token` flag. It does not persist
// anything itself -- see internal/pair's package doc for the v1 design.
func newPairCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pair",
		Short: "Generate a new pairing token for the mobile app",
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := pair.GenerateToken()
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), token)
			return nil
		},
	}
}
