// Package securityaudit performs deterministic, read-only security checks on
// the host running gateshell-agent. It never accepts commands from clients and
// never mutates host state.
package securityaudit

import "time"

type Status string

const (
	StatusPass    Status = "pass"
	StatusWarning Status = "warning"
	StatusFail    Status = "fail"
	StatusUnknown Status = "unknown"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Remediation describes a reviewable next step. Dashboard is a stable app
// destination; Command is informational and is never executed by the agent.
//
// Commands are written in the interactive form (plain `sudo`, never
// `sudo -n`): the app copies them for a human to paste into their own
// terminal, and `-n` makes sudo fail rather than prompt, so the pasted
// command would refuse to run on any host where sudo needs a password.
// The app also allow-lists these exact strings before offering a Fix
// button, so they must match on both sides.
type Remediation struct {
	Summary   string `json:"summary"`
	Dashboard string `json:"dashboard,omitempty"`
	Command   string `json:"command,omitempty"`
}

type Finding struct {
	ID          string       `json:"id"`
	Category    string       `json:"category"`
	Status      Status       `json:"status"`
	Severity    Severity     `json:"severity"`
	Title       string       `json:"title"`
	Summary     string       `json:"summary"`
	Evidence    string       `json:"evidence,omitempty"`
	Remediation *Remediation `json:"remediation,omitempty"`
}

type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Source      string    `json:"source"`
	Platform    string    `json:"platform"`
	Findings    []Finding `json:"findings"`
}

type Scanner interface {
	Scan() Report
}
