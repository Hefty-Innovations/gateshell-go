package collector

import (
	"fmt"
	"strconv"
	"strings"
)

// clockTicksPerSecond is USER_HZ, the unit /proc/<pid>/stat reports CPU
// time in. It is 100 on every Linux platform this agent targets; reading
// it properly needs sysconf(_SC_CLK_TCK) via cgo, which this build avoids.
const clockTicksPerSecond = 100

// bytesPerPage is the page size /proc/<pid>/stat's rss field counts in.
// 4KiB on x86_64 and on arm64 Linux distributions in general use.
const bytesPerPage = 4096

// procSample is one process's cumulative CPU time and current memory, as
// of a single read of /proc.
type procSample struct {
	pid      int
	name     string
	cpuTicks uint64 // utime + stime, cumulative since the process started
	rssBytes uint64
}

// parseProcStat parses one /proc/<pid>/stat line.
//
// The comm field is wrapped in parentheses and may itself contain spaces
// and parentheses (a process can rename itself to anything), so fields are
// located relative to the *last* ')' rather than by splitting the whole
// line -- splitting on whitespace misattributes every subsequent field for
// a process named e.g. "(my app)".
func parseProcStat(data string) (procSample, error) {
	open := strings.IndexByte(data, '(')
	close := strings.LastIndexByte(data, ')')
	if open < 0 || close < 0 || close < open {
		return procSample{}, fmt.Errorf("collector: /proc stat line has no comm field")
	}

	pid, err := strconv.Atoi(strings.TrimSpace(data[:open]))
	if err != nil {
		return procSample{}, fmt.Errorf("collector: parsing pid: %w", err)
	}
	name := data[open+1 : close]

	// After comm, field 3 is state; utime is field 14 and stime 15, i.e.
	// offsets 11 and 12 in what follows.
	rest := strings.Fields(data[close+1:])
	const (
		utimeOffset = 11
		stimeOffset = 12
		rssOffset   = 21 // field 24
	)
	if len(rest) <= rssOffset {
		return procSample{}, fmt.Errorf("collector: /proc stat line has %d fields after comm, need %d", len(rest), rssOffset+1)
	}

	utime, err := strconv.ParseUint(rest[utimeOffset], 10, 64)
	if err != nil {
		return procSample{}, fmt.Errorf("collector: parsing utime: %w", err)
	}
	stime, err := strconv.ParseUint(rest[stimeOffset], 10, 64)
	if err != nil {
		return procSample{}, fmt.Errorf("collector: parsing stime: %w", err)
	}
	rssPages, err := strconv.ParseUint(rest[rssOffset], 10, 64)
	if err != nil {
		return procSample{}, fmt.Errorf("collector: parsing rss: %w", err)
	}

	return procSample{
		pid: pid, name: name,
		cpuTicks: utime + stime,
		rssBytes: rssPages * bytesPerPage,
	}, nil
}

// cpuPercentBetween converts a CPU-tick delta over an elapsed wall-clock
// period into a percentage of one core.
//
// This is the whole point of sampling twice: `ps %cpu` reports CPU time
// divided by the process's *lifetime*, so a process that was busy at boot
// reads high forever and one busy right now reads low if it is long-lived.
// A delta between two reads reports what the process actually did during
// that window.
func cpuPercentBetween(previousTicks, currentTicks uint64, elapsedSeconds float64) float64 {
	if elapsedSeconds <= 0 || currentTicks < previousTicks {
		return 0
	}
	deltaTicks := float64(currentTicks - previousTicks)
	return (deltaTicks / (clockTicksPerSecond * elapsedSeconds)) * 100
}
