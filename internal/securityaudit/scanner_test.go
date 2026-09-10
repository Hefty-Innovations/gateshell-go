package securityaudit

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

type fakeRunner map[string]commandResult

func (r fakeRunner) run(name string, args ...string) commandResult {
	key := name
	for _, arg := range args {
		key += " " + arg
	}
	if result, ok := r[key]; ok {
		return result
	}
	return commandResult{err: errors.New("not installed")}
}

func newTestScanner(runner fakeRunner, files map[string]string) *SystemScanner {
	return &SystemScanner{
		runner: runner,
		now:    func() time.Time { return time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC) },
		readFile: func(path string) ([]byte, error) {
			if value, ok := files[path]; ok {
				return []byte(value), nil
			}
			return nil, errors.New("not found")
		},
		glob: func(string) ([]string, error) { return nil, nil },
	}
}

func TestScanProducesStableChecksAndActionableEvidence(t *testing.T) {
	runner := fakeRunner{
		"apt-get -s -o Debug::NoLocking=1 upgrade": {output: "Inst openssl [1] (2 repo)\nInst curl [1] (2 repo)\n"},
		"ss -H -lntu": {output: "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:*\n"},
		"sshd -T":     {output: "passwordauthentication yes\npermitrootlogin no\n"},
		"ufw status":  {output: "Status: inactive\n"},
		"systemctl list-timers --all --no-legend --no-pager": {output: "Mon backup.timer backup.service\n"},
		"crontab -l": {output: ""},
	}
	scanner := newTestScanner(runner, map[string]string{"/etc/os-release": "ID=ubuntu\nID_LIKE=debian\n"})
	report := scanner.Scan()
	if report.Source != "gateshell-agent" || len(report.Findings) != 6 {
		t.Fatalf("unexpected report: %#v", report)
	}

	byID := map[string]Finding{}
	for _, finding := range report.Findings {
		byID[finding.ID] = finding
	}
	// Interactive `sudo`, not `sudo -n`: the app copies this for a human to
	// paste into their own terminal, where -n makes sudo fail rather than
	// prompt. The app also allow-lists this exact string before offering a
	// Fix button, and the -n form matched nothing -- so the button never
	// appeared on an agent-paired server.
	if byID["system-updates"].Status != StatusFail || byID["system-updates"].Remediation.Command != "sudo apt-get update && sudo apt-get upgrade -y" {
		t.Fatalf("updates finding is not actionable: %#v", byID["system-updates"])
	}
	if byID["public-listeners"].Evidence != "Public ports: 22" {
		t.Fatalf("unexpected public listener evidence: %q", byID["public-listeners"].Evidence)
	}
	if byID["ssh-hardening"].Severity != SeverityCritical {
		t.Fatalf("unexpected SSH severity: %s", byID["ssh-hardening"].Severity)
	}
	if byID["host-firewall"].Remediation.Dashboard != "firewall" {
		t.Fatalf("firewall dashboard missing: %#v", byID["host-firewall"])
	}
	if byID["backup-schedule"].Status != StatusPass {
		t.Fatalf("backup should pass: %#v", byID["backup-schedule"])
	}
}

func TestUnknownIsNotReportedAsPassWhenAgentLacksPermission(t *testing.T) {
	scanner := newTestScanner(fakeRunner{
		"apt-get -s -o Debug::NoLocking=1 upgrade": {output: "permission denied", err: errors.New("exit 1")},
		"ss -H -lntu":          {output: "permission denied", err: errors.New("exit 1")},
		"sshd -T":              {output: "permission denied", err: errors.New("exit 1")},
		"ufw status":           {output: "permission denied", err: errors.New("exit 1")},
		"firewall-cmd --state": {err: errors.New("not installed")},
		"nft list ruleset":     {output: "permission denied", err: errors.New("exit 1")},
	}, map[string]string{"/etc/os-release": "ID=ubuntu"})
	report := scanner.Scan()
	for _, id := range []string{"system-updates", "public-listeners", "ssh-hardening", "host-firewall"} {
		var got Status
		for _, finding := range report.Findings {
			if finding.ID == id {
				got = finding.Status
			}
		}
		if got == StatusPass {
			t.Fatalf("%s must not pass when unreadable", id)
		}
	}
}

func TestPublicPortsAreSortedAndDeduplicated(t *testing.T) {
	got := publicPorts("tcp LISTEN 0 1 [::]:443 [::]:*\ntcp LISTEN 0 1 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 1 *:443 *:*\ntcp LISTEN 0 1 127.0.0.1:8080 0.0.0.0:*\n")
	if !reflect.DeepEqual(got, []int{22, 443}) {
		t.Fatalf("got %v", got)
	}
}

func TestUnreadableCertificatesNeverPass(t *testing.T) {
	scanner := newTestScanner(fakeRunner{}, nil)
	scanner.glob = func(string) ([]string, error) { return []string{"/etc/letsencrypt/live/example/fullchain.pem"}, nil }
	finding := scanner.checkCertificates()[0]
	if finding.Status != StatusUnknown {
		t.Fatalf("unreadable certificate status=%s", finding.Status)
	}
}

func TestSSHConfigUsesLastActiveValueAndIgnoresComments(t *testing.T) {
	config := "# PasswordAuthentication yes\nPasswordAuthentication yes\nPasswordAuthentication no\nPermitRootLogin no\n"
	if got := configValue(config, "passwordauthentication"); got != "no" {
		t.Fatalf("got %q", got)
	}
}

type countingScanner struct {
	calls int
	now   time.Time
}

func (s *countingScanner) Scan() Report {
	s.calls++
	return Report{GeneratedAt: s.now, Source: "gateshell-agent"}
}

func TestCachedScannerReusesReportUntilRefresh(t *testing.T) {
	inner := &countingScanner{now: time.Now()}
	cached := NewCachedScanner(inner, time.Hour)
	first := cached.Scan(false)
	second := cached.Scan(false)
	if inner.calls != 1 || first.GeneratedAt != second.GeneratedAt {
		t.Fatalf("cache missed: calls=%d", inner.calls)
	}
	cached.Scan(true)
	if inner.calls != 2 {
		t.Fatalf("refresh did not rescan: calls=%d", inner.calls)
	}
}
