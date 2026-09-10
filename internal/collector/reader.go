package collector

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// This file is the landing spot for ports of the iOS Swift local health
// parsers (GateShell/Services/Parsers/*.swift and friends) down to a
// Linux-first, /proc-based implementation.
//
// Linux is the primary target (the agent runs on user servers, which are
// overwhelmingly Linux). macOS support below is a best-effort fallback for
// local development only -- it is NOT a target deployment platform for v1.
// Every reader below follows the same shape: real work gated behind
// `runtime.GOOS == "linux"`, zero/empty values (no error) otherwise, so the
// package builds and runs end-to-end on a macOS dev machine too. The raw
// text/JSON parsing for each reader lives in its own file (meminfo.go,
// cpustat.go, netdev.go, psparse.go, diskusage.go) as pure functions so it
// can be unit-tested against captured sample output without touching the
// filesystem or shelling out.

// LoadAvgReader reads system load averages (1/5/15 min).
type LoadAvgReader struct{}

// Read returns load1, load5, load15. On Linux it parses /proc/loadavg. On
// other platforms (macOS dev machines) it falls back to zero values rather
// than shelling out, keeping this package dependency-free; a real macOS
// fallback would use the getloadavg(3) syscall via cgo or golang.org/x/sys,
// which is deliberately out of scope for a server-targeted agent.
func (LoadAvgReader) Read() (load1, load5, load15 float64, err error) {
	if runtime.GOOS != "linux" {
		return 0, 0, 0, nil // TODO: macOS dev fallback via getloadavg(3) if ever needed
	}

	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, fmt.Errorf("reading /proc/loadavg: %w", err)
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0, fmt.Errorf("unexpected /proc/loadavg format: %q", string(data))
	}

	load1, err = strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("parsing load1: %w", err)
	}
	load5, err = strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("parsing load5: %w", err)
	}
	load15, err = strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("parsing load15: %w", err)
	}
	return load1, load5, load15, nil
}

// UptimeReader reads system uptime.
type UptimeReader struct{}

// Read returns uptime as a time.Duration. On Linux it parses /proc/uptime
// (first field, seconds as a float). On other platforms it returns 0 with
// no error -- see LoadAvgReader.Read for rationale.
func (UptimeReader) Read() (time.Duration, error) {
	if runtime.GOOS != "linux" {
		return 0, nil // TODO: macOS dev fallback (sysctl kern.boottime) if ever needed
	}

	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, fmt.Errorf("reading /proc/uptime: %w", err)
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, fmt.Errorf("unexpected /proc/uptime format: %q", string(data))
	}

	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("parsing uptime seconds: %w", err)
	}
	return time.Duration(seconds * float64(time.Second)), nil
}

// MemoryReader reads memory usage (used/total, MB) from /proc/meminfo.
type MemoryReader struct{}

// Read returns usedMB, totalMB. On Linux it parses /proc/meminfo, using
// MemTotal and MemAvailable (used = total - available); MemAvailable is a
// kernel-computed "truly free for a new workload" figure, closer to what
// users mean by "used" than MemTotal-MemFree (which ignores reclaimable
// caches). See meminfo.go for the pure parser.
func (MemoryReader) Read() (usedMB, totalMB float64, err error) {
	if runtime.GOOS != "linux" {
		return 0, 0, nil
	}

	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, fmt.Errorf("reading /proc/meminfo: %w", err)
	}

	totalKB, availKB, err := parseMemInfo(string(data))
	if err != nil {
		return 0, 0, err
	}

	totalMB = float64(totalKB) / 1024
	usedKB := int64(totalKB) - int64(availKB)
	if usedKB < 0 {
		usedKB = 0
	}
	usedMB = float64(usedKB) / 1024
	return usedMB, totalMB, nil
}

// DiskReader reads disk usage for a given mount point (used/total, GB) via
// the statfs(2) syscall.
type DiskReader struct{}

// Read returns usedGB, totalGB for the given mount path (e.g. "/"). An
// empty path defaults to "/". See diskusage.go for the pure GB conversion.
func (DiskReader) Read(path string) (usedGB, totalGB float64, err error) {
	if runtime.GOOS != "linux" {
		return 0, 0, nil
	}
	if path == "" {
		path = "/"
	}

	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, 0, fmt.Errorf("statfs %s: %w", path, err)
	}

	usedGB, totalGB = calcDiskUsage(uint64(stat.Bsize), stat.Blocks, stat.Bavail)
	return usedGB, totalGB, nil
}

// CPUReader reads aggregate CPU utilization as a percentage (0-100).
type CPUReader struct {
	// SampleInterval is the delay between the two /proc/stat samples used
	// to compute the delta-based CPU percentage. Zero uses
	// defaultCPUSampleInterval; tests override this to avoid slow runs.
	SampleInterval time.Duration
}

// Read samples /proc/stat twice, SampleInterval apart, and returns the
// busy percentage across that window (busy = total ticks - idle ticks).
// See cpustat.go for the pure parsing/percentage math.
func (r CPUReader) Read() (percent float64, err error) {
	if runtime.GOOS != "linux" {
		return 0, nil
	}

	interval := r.SampleInterval
	if interval <= 0 {
		interval = defaultCPUSampleInterval
	}

	first, err := readProcStatCPU()
	if err != nil {
		return 0, err
	}
	time.Sleep(interval)
	second, err := readProcStatCPU()
	if err != nil {
		return 0, err
	}

	return cpuPercent(first, second), nil
}

func readProcStatCPU() (cpuStat, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuStat{}, fmt.Errorf("reading /proc/stat: %w", err)
	}
	stat, err := parseCPUStatLine(string(data))
	if err != nil {
		return cpuStat{}, err
	}
	return stat, nil
}

// NetReader reads network throughput (bytes/sec) on the primary
// non-loopback interface.
type NetReader struct {
	// SampleInterval is the delay between the two /proc/net/dev samples
	// used to compute a bytes/sec rate. Zero uses
	// defaultNetSampleInterval; tests override this to avoid slow runs.
	SampleInterval time.Duration
}

// Read samples /proc/net/dev twice, SampleInterval apart, and returns the
// rx/tx byte-rate delta over that window for the first non-loopback
// interface found. If no such interface is present, it returns 0, 0, nil
// (nothing to report, not an error). See netdev.go for the pure parser.
func (r NetReader) Read() (rxBytesPerSec, txBytesPerSec float64, err error) {
	if runtime.GOOS != "linux" {
		return 0, 0, nil
	}

	interval := r.SampleInterval
	if interval <= 0 {
		interval = defaultNetSampleInterval
	}

	first, ok, err := readProcNetDev()
	if err != nil {
		return 0, 0, err
	}
	if !ok {
		return 0, 0, nil
	}
	time.Sleep(interval)
	second, ok, err := readProcNetDev()
	if err != nil {
		return 0, 0, err
	}
	if !ok {
		return 0, 0, nil
	}

	elapsed := interval.Seconds()
	if elapsed <= 0 {
		return 0, 0, nil
	}
	rxBytesPerSec = nonNegativeDelta(second.rxBytes, first.rxBytes) / elapsed
	txBytesPerSec = nonNegativeDelta(second.txBytes, first.txBytes) / elapsed
	return rxBytesPerSec, txBytesPerSec, nil
}

func readProcNetDev() (netIface, bool, error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return netIface{}, false, fmt.Errorf("reading /proc/net/dev: %w", err)
	}
	iface, ok := parseNetDev(string(data))
	return iface, ok, nil
}

// nonNegativeDelta returns curr-prev, floored at 0 -- counters can appear
// to go backward across a sample window if the interface was reset.
func nonNegativeDelta(curr, prev uint64) float64 {
	if curr < prev {
		return 0
	}
	return float64(curr - prev)
}

// TopProcessesReader reads the top-N processes by CPU usage.
//
// Stateful on purpose: CPU percentage is a delta between two reads, and
// the previous read is the one from the last poll. That gives usage over
// the poll interval with no added latency, and avoids `ps %cpu`, which is
// CPU time over the process's whole lifetime -- a number that keeps a
// long-finished burst at the top of the list forever.
type TopProcessesReader struct {
	mu       sync.Mutex
	previous map[int]uint64
	readAt   time.Time
}

// Read shells out to `ps -eo pid,comm,%cpu,rss --sort=-%cpu` (already
// sorted CPU-descending by the kernel/ps, not re-sorted here) and returns
// the first n rows. rss (resident set size, KB) is used instead of %mem so
// ProcessInfo.MemMB is a direct unit conversion rather than a
// percent-of-total that would need a second RAM lookup to convert. See
// psparse.go for the pure parser.
func (r *TopProcessesReader) Read(n int) ([]ProcessInfo, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}
	if n <= 0 {
		n = 5
	}

	samples, readAt, err := readProcSamples()
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	previous, previousAt := r.previous, r.readAt
	current := make(map[int]uint64, len(samples))
	for _, s := range samples {
		current[s.pid] = s.cpuTicks
	}
	r.previous, r.readAt = current, readAt
	r.mu.Unlock()

	// The first read of the agent's life has no baseline to subtract, so
	// there is no honest CPU number yet. Report the processes with their
	// memory and a zero CPU rather than inventing a lifetime average that
	// would rank the list wrongly.
	elapsed := readAt.Sub(previousAt).Seconds()
	haveBaseline := previous != nil && elapsed > 0

	procs := make([]ProcessInfo, 0, len(samples))
	for _, s := range samples {
		cpu := 0.0
		if haveBaseline {
			if prev, ok := previous[s.pid]; ok {
				cpu = cpuPercentBetween(prev, s.cpuTicks, elapsed)
			}
		}
		procs = append(procs, ProcessInfo{
			PID: s.pid, Name: s.name,
			CPUPercent: cpu,
			MemMB:      float64(s.rssBytes) / (1024 * 1024),
		})
	}

	// Rank by CPU when there is a real delta to rank by; by memory on the
	// very first read, so the list is still meaningful rather than
	// arbitrary /proc ordering.
	sort.Slice(procs, func(i, j int) bool {
		if haveBaseline && procs[i].CPUPercent != procs[j].CPUPercent {
			return procs[i].CPUPercent > procs[j].CPUPercent
		}
		return procs[i].MemMB > procs[j].MemMB
	})
	if len(procs) > n {
		procs = procs[:n]
	}
	return procs, nil
}

// readProcSamples reads every /proc/<pid>/stat currently present. A
// process exiting mid-scan is expected, not an error -- its file simply
// disappears -- so unreadable entries are skipped.
func readProcSamples() ([]procSample, time.Time, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("collector: reading /proc: %w", err)
	}
	readAt := time.Now()

	samples := make([]procSample, 0, 128)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue // not a pid directory
		}
		data, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if err != nil {
			continue
		}
		sample, err := parseProcStat(string(data))
		if err != nil {
			continue
		}
		samples = append(samples, sample)
	}
	return samples, readAt, nil
}

// ServiceChecker probes the health of external service supervisors
// (docker, systemd, pm2, cron). Concrete implementations live in
// docker.go, systemd.go, pm2.go, and cron.go respectively -- each shells
// out to the corresponding local tool and reports an empty slice (not an
// error) when that tool isn't installed or reachable.
type ServiceChecker interface {
	Kind() ServiceKind
	Check() ([]ServiceStatus, error)
}
