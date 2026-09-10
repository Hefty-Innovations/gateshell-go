package collector

import "testing"

func TestParseProcStat(t *testing.T) {
	// Real shape: pid (comm) state ppid ... utime stime ... rss ...
	line := "1234 (nginx) S 1 1234 1234 0 -1 4194560 1000 0 0 0 " +
		"150 50 0 0 20 0 4 0 900 12345678 2048 " +
		"18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0"
	s, err := parseProcStat(line)
	if err != nil {
		t.Fatalf("parseProcStat: %v", err)
	}
	if s.pid != 1234 || s.name != "nginx" {
		t.Errorf("pid/name wrong: %+v", s)
	}
	if s.cpuTicks != 200 { // utime 150 + stime 50
		t.Errorf("expected 200 ticks, got %d", s.cpuTicks)
	}
	if s.rssBytes != 2048*bytesPerPage {
		t.Errorf("expected rss in bytes, got %d", s.rssBytes)
	}
}

// A process can rename itself to anything, including something with
// spaces and parentheses. Splitting the line on whitespace would
// misattribute every field after comm.
func TestParseProcStatHandlesCommWithSpacesAndParens(t *testing.T) {
	line := "77 (my weird (app)) S 1 77 77 0 -1 0 0 0 0 0 " +
		"10 5 0 0 20 0 1 0 1 0 512 " +
		"0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
	s, err := parseProcStat(line)
	if err != nil {
		t.Fatalf("parseProcStat: %v", err)
	}
	if s.name != "my weird (app)" {
		t.Errorf("comm mis-parsed: %q", s.name)
	}
	if s.cpuTicks != 15 {
		t.Errorf("fields after comm misattributed: %d ticks", s.cpuTicks)
	}
}

func TestParseProcStatRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "not a stat line", "12 (short) S 1 2 3"} {
		if _, err := parseProcStat(in); err == nil {
			t.Errorf("expected an error for %q", in)
		}
	}
}

// The reason for the whole delta: ps reports CPU time over a process's
// lifetime, so a burst at boot ranks high forever. A delta reports what
// happened during the window.
func TestCPUPercentBetween(t *testing.T) {
	// 100 ticks over 1s on a 100Hz clock is one core fully busy.
	if got := cpuPercentBetween(0, 100, 1); got != 100 {
		t.Errorf("expected 100%%, got %v", got)
	}
	// Half a core over two seconds.
	if got := cpuPercentBetween(1000, 1100, 2); got != 50 {
		t.Errorf("expected 50%%, got %v", got)
	}
	// A long-lived idle process accrues nothing in the window, however
	// much lifetime CPU it has behind it.
	if got := cpuPercentBetween(999_999, 999_999, 60); got != 0 {
		t.Errorf("expected 0%%, got %v", got)
	}
}

// Counters can only go up; a pid being reused after a process exits would
// otherwise produce a nonsense negative-turned-huge percentage.
func TestCPUPercentBetweenIgnoresGoingBackwards(t *testing.T) {
	if got := cpuPercentBetween(500, 100, 1); got != 0 {
		t.Errorf("expected 0%% for a reused pid, got %v", got)
	}
	if got := cpuPercentBetween(0, 100, 0); got != 0 {
		t.Errorf("expected 0%% for a zero window, got %v", got)
	}
}
