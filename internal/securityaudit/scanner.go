package securityaudit

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const commandTimeout = 12 * time.Second

type commandResult struct {
	output string
	err    error
}

type commandRunner interface {
	run(name string, args ...string) commandResult
}

type systemRunner struct{}

func (systemRunner) run(name string, args ...string) commandResult {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	output, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return commandResult{output: string(output), err: ctx.Err()}
	}
	return commandResult{output: string(output), err: err}
}

type SystemScanner struct {
	runner   commandRunner
	now      func() time.Time
	readFile func(string) ([]byte, error)
	glob     func(string) ([]string, error)
}

func NewSystemScanner() *SystemScanner {
	return &SystemScanner{
		runner: systemRunner{}, now: time.Now, readFile: os.ReadFile, glob: filepath.Glob,
	}
}

func (s *SystemScanner) Scan() Report {
	findings := []Finding{
		s.checkUpdates(),
		s.checkListeningPorts(),
		s.checkSSHConfiguration(),
		s.checkFirewall(),
		s.checkBackups(),
	}
	findings = append(findings, s.checkCertificates()...)
	return Report{
		GeneratedAt: s.now().UTC(), Source: "gateshell-agent", Platform: runtime.GOOS,
		Findings: findings,
	}
}

func (s *SystemScanner) checkUpdates() Finding {
	base := Finding{ID: "system-updates", Category: "updates", Title: "System updates", Severity: SeverityHigh}
	osRelease, _ := s.readFile("/etc/os-release")
	distro := strings.ToLower(string(osRelease))
	var result commandResult
	var command string
	switch {
	case strings.Contains(distro, "debian") || strings.Contains(distro, "ubuntu"):
		result = s.runner.run("apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade")
		command = "sudo apt-get update && sudo apt-get upgrade -y"
		count := countPrefixedLines(result.output, "Inst ")
		if result.err == nil {
			if count == 0 {
				return pass(base, "No pending package upgrades were found.", "apt simulation reported 0 upgrades")
			}
			base.Status, base.Summary, base.Evidence = StatusFail, fmt.Sprintf("%d package upgrades are pending.", count), fmt.Sprintf("apt simulation reported %d upgrades", count)
			base.Remediation = &Remediation{Summary: "Review and install system package updates.", Command: command}
			return base
		}
	case strings.Contains(distro, "fedora") || strings.Contains(distro, "rhel") || strings.Contains(distro, "centos"):
		result = s.runner.run("dnf", "check-update", "-q")
		command = "sudo dnf upgrade -y"
		if result.err == nil && strings.TrimSpace(result.output) == "" {
			return pass(base, "No pending package upgrades were found.", "dnf reported no upgrades")
		}
		if exitCode(result.err) == 100 {
			count := countDNFPackages(result.output)
			base.Status, base.Summary, base.Evidence = StatusFail, fmt.Sprintf("%d package upgrades are pending.", count), fmt.Sprintf("dnf reported %d upgrades", count)
			base.Remediation = &Remediation{Summary: "Review and install system package updates.", Command: command}
			return base
		}
	case strings.Contains(distro, "alpine"):
		result = s.runner.run("apk", "version", "-l", "<")
		command = "sudo apk upgrade"
		if result.err == nil {
			count := nonEmptyLineCount(result.output)
			if count == 0 {
				return pass(base, "No pending package upgrades were found.", "apk reported 0 upgrades")
			}
			base.Status, base.Summary, base.Evidence = StatusFail, fmt.Sprintf("%d package upgrades are pending.", count), fmt.Sprintf("apk reported %d upgrades", count)
			base.Remediation = &Remediation{Summary: "Review and install system package updates.", Command: command}
			return base
		}
	default:
		return unknown(base, "Package update status is unsupported on this operating system.")
	}
	return unknown(base, conciseError("Could not read package update status", result))
}

func (s *SystemScanner) checkListeningPorts() Finding {
	base := Finding{ID: "public-listeners", Category: "network", Title: "Publicly bound services", Severity: SeverityHigh}
	result := s.runner.run("ss", "-H", "-lntu")
	if result.err != nil {
		return unknown(base, conciseError("Could not inspect listening ports", result))
	}
	ports := publicPorts(result.output)
	if len(ports) == 0 {
		return pass(base, "No services are listening on all network interfaces.", "ss found no 0.0.0.0, ::, or wildcard listeners")
	}
	base.Status = StatusWarning
	base.Summary = fmt.Sprintf("%d port(s) listen on all network interfaces.", len(ports))
	base.Evidence = "Public ports: " + joinInts(ports)
	base.Remediation = &Remediation{Summary: "Confirm every public listener is required and restrict it with the firewall.", Dashboard: "firewall"}
	return base
}

func (s *SystemScanner) checkSSHConfiguration() Finding {
	base := Finding{ID: "ssh-hardening", Category: "ssh", Title: "SSH authentication policy", Severity: SeverityCritical}
	result := s.runner.run("sshd", "-T")
	config := strings.ToLower(result.output)
	if result.err != nil || strings.TrimSpace(config) == "" {
		data, err := s.readFile("/etc/ssh/sshd_config")
		if err != nil {
			return unknown(base, "Could not read the effective SSH daemon configuration.")
		}
		config = strings.ToLower(string(data))
	}
	password := configValue(config, "passwordauthentication")
	root := configValue(config, "permitrootlogin")
	risks := make([]string, 0, 2)
	if password == "yes" {
		risks = append(risks, "password authentication is enabled")
	}
	if root == "yes" {
		risks = append(risks, "direct root login is enabled")
	}
	if len(risks) == 0 {
		evidence := fmt.Sprintf("PasswordAuthentication=%s; PermitRootLogin=%s", valueOrUnknown(password), valueOrUnknown(root))
		if password == "" || root == "" {
			return unknownWithEvidence(base, "Some effective SSH settings could not be determined.", evidence)
		}
		return pass(base, "SSH avoids password authentication and direct root login.", evidence)
	}
	base.Status, base.Summary = StatusFail, strings.Join(risks, "; ")+"."
	base.Evidence = fmt.Sprintf("PasswordAuthentication=%s; PermitRootLogin=%s", valueOrUnknown(password), valueOrUnknown(root))
	base.Remediation = &Remediation{Summary: "Review SSH access before changing authentication settings to avoid lockout."}
	return base
}

func (s *SystemScanner) checkFirewall() Finding {
	base := Finding{ID: "host-firewall", Category: "firewall", Title: "Host firewall", Severity: SeverityHigh}
	if result := s.runner.run("ufw", "status"); result.err == nil {
		if strings.Contains(strings.ToLower(result.output), "status: active") {
			return pass(base, "UFW is active.", firstLine(result.output))
		}
		base.Status, base.Summary, base.Evidence = StatusFail, "UFW is installed but inactive.", firstLine(result.output)
		base.Remediation = &Remediation{Summary: "Review allowed SSH access, then enable the firewall.", Dashboard: "firewall"}
		return base
	}
	if result := s.runner.run("firewall-cmd", "--state"); result.err == nil {
		if strings.TrimSpace(result.output) == "running" {
			return pass(base, "firewalld is active.", "firewall-cmd: running")
		}
	}
	if result := s.runner.run("nft", "list", "ruleset"); result.err == nil && strings.TrimSpace(result.output) != "" {
		base.Status, base.Severity = StatusWarning, SeverityMedium
		base.Summary = "An nftables ruleset is loaded, but its enforcement policy needs review."
		base.Evidence = "nftables returned a non-empty ruleset"
		base.Remediation = &Remediation{Summary: "Review the nftables ruleset and confirm required inbound traffic is restricted."}
		return base
	}
	base.Status, base.Summary = StatusUnknown, "No active supported host firewall could be confirmed."
	base.Evidence = "The agent is unprivileged; firewall inspection may require additional read permission."
	base.Remediation = &Remediation{Summary: "Open the Firewall dashboard to verify and configure UFW.", Dashboard: "firewall"}
	return base
}

func (s *SystemScanner) checkBackups() Finding {
	base := Finding{ID: "backup-schedule", Category: "backups", Title: "Backup schedule", Severity: SeverityHigh}
	var combined strings.Builder
	for _, call := range []struct {
		name string
		args []string
	}{
		{"systemctl", []string{"list-timers", "--all", "--no-legend", "--no-pager"}},
		{"crontab", []string{"-l"}},
	} {
		result := s.runner.run(call.name, call.args...)
		if result.err == nil {
			combined.WriteString(result.output)
			combined.WriteByte('\n')
		}
	}
	lower := strings.ToLower(combined.String())
	keywords := []string{"backup", "restic", "borg", "duplicity", "snapshot", "rclone"}
	matches := make([]string, 0)
	for _, line := range strings.Split(lower, "\n") {
		for _, keyword := range keywords {
			if strings.Contains(line, keyword) {
				matches = append(matches, strings.TrimSpace(line))
				break
			}
		}
	}
	if len(matches) > 0 {
		return pass(base, "A likely backup or snapshot schedule was detected.", strings.Join(limit(matches, 3), "; "))
	}
	base.Status, base.Summary = StatusWarning, "No recognizable backup schedule was detected."
	base.Evidence = "Checked systemd timers and the agent user's crontab for common backup tools."
	base.Remediation = &Remediation{Summary: "Verify backups and test a restore; schedules owned by other users may not be visible."}
	return base
}

func (s *SystemScanner) checkCertificates() []Finding {
	base := Finding{ID: "certificate-health", Category: "certificates", Title: "TLS certificates", Severity: SeverityHigh}
	paths, err := s.glob("/etc/letsencrypt/live/*/fullchain.pem")
	if err != nil || len(paths) == 0 {
		return []Finding{unknown(base, "No readable Let's Encrypt certificates were found on this host.")}
	}
	now := s.now()
	var expired, expiring []string
	readable := 0
	for _, path := range paths {
		data, readErr := s.readFile(path)
		if readErr != nil {
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			continue
		}
		readable++
		name := cert.Subject.CommonName
		if name == "" {
			name = filepath.Base(filepath.Dir(path))
		}
		days := int(cert.NotAfter.Sub(now).Hours() / 24)
		if cert.NotAfter.Before(now) {
			expired = append(expired, name)
		} else if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
			expiring = append(expiring, fmt.Sprintf("%s (%dd)", name, days))
		}
	}
	if len(expired) > 0 {
		base.Status, base.Severity, base.Summary, base.Evidence = StatusFail, SeverityCritical, "One or more TLS certificates have expired.", "Expired: "+strings.Join(expired, ", ")
		base.Remediation = &Remediation{Summary: "Renew expired certificates and confirm the served certificate.", Dashboard: "certbot", Command: "sudo certbot renew"}
		return []Finding{base}
	}
	if len(expiring) > 0 {
		base.Status, base.Summary, base.Evidence = StatusWarning, "One or more TLS certificates expire within 30 days.", "Expiring: "+strings.Join(expiring, ", ")
		base.Remediation = &Remediation{Summary: "Review renewal status before these certificates expire.", Dashboard: "certbot", Command: "sudo certbot renew --dry-run"}
		return []Finding{base}
	}
	if readable == 0 {
		return []Finding{unknown(base, "Let's Encrypt certificate files were found but could not be read or parsed.")}
	}
	return []Finding{pass(base, "Readable Let's Encrypt certificates are valid for at least 30 days.", fmt.Sprintf("Checked %d certificate(s)", readable))}
}

func pass(base Finding, summary, evidence string) Finding {
	base.Status, base.Severity, base.Summary, base.Evidence = StatusPass, SeverityInfo, summary, evidence
	return base
}
func unknown(base Finding, summary string) Finding {
	base.Status, base.Severity, base.Summary = StatusUnknown, SeverityInfo, summary
	return base
}
func unknownWithEvidence(base Finding, summary, evidence string) Finding {
	base = unknown(base, summary)
	base.Evidence = evidence
	return base
}
func valueOrUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
func firstLine(s string) string {
	if line, _, ok := strings.Cut(strings.TrimSpace(s), "\n"); ok {
		return line
	}
	return strings.TrimSpace(s)
}
func countPrefixedLines(s, prefix string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, prefix) {
			n++
		}
	}
	return n
}
func nonEmptyLineCount(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}
func countDNFPackages(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && strings.Contains(f[0], ".") {
			n++
		}
	}
	return n
}
func exitCode(err error) int {
	var e *exec.ExitError
	if errors.As(err, &e) {
		return e.ExitCode()
	}
	return -1
}
func configValue(config, key string) string {
	value := ""
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 && strings.EqualFold(f[0], key) {
			value = strings.ToLower(f[1])
		}
	}
	return value
}
func conciseError(prefix string, result commandResult) string {
	detail := strings.TrimSpace(result.output)
	if detail == "" && result.err != nil {
		detail = result.err.Error()
	}
	if detail == "" {
		return prefix + "."
	}
	return prefix + ": " + firstLine(detail)
}
func limit(values []string, n int) []string {
	if len(values) <= n {
		return values
	}
	return values[:n]
}
func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ", ")
}

func publicPorts(output string) []int {
	set := map[int]struct{}{}
	for _, line := range strings.Split(output, "\n") {
		for _, field := range strings.Fields(line) {
			if !(strings.HasPrefix(field, "0.0.0.0:") || strings.HasPrefix(field, "[::]:") || strings.HasPrefix(field, "*:") || strings.HasPrefix(field, ":::")) {
				continue
			}
			_, port, err := net.SplitHostPort(field)
			if err != nil {
				port = field[strings.LastIndex(field, ":")+1:]
			}
			if number, err := strconv.Atoi(port); err == nil {
				set[number] = struct{}{}
			}
		}
	}
	ports := make([]int, 0, len(set))
	for port := range set {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

// CachedScanner keeps expensive package/firewall checks off the request path
// for repeated app refreshes while still allowing an explicit refresh.
type CachedScanner struct {
	scanner Scanner
	ttl     time.Duration
	mu      sync.Mutex
	report  Report
}

func NewCachedScanner(scanner Scanner, ttl time.Duration) *CachedScanner {
	return &CachedScanner{scanner: scanner, ttl: ttl}
}
func (s *CachedScanner) Scan(refresh bool) Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !refresh && !s.report.GeneratedAt.IsZero() && time.Since(s.report.GeneratedAt) < s.ttl {
		return s.report
	}
	s.report = s.scanner.Scan()
	return s.report
}
