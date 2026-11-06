package budget

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, root, p, s string) {
	t.Helper()
	f := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMeasuresItselfAndBacksOffNearItsLimit(t *testing.T) {
	root := t.TempDir()
	Root = root
	defer func() { Root = "/" }()
	write(t, root, "proc/self/status", "Name:\tkiyesi\nVmRSS:\t   51200 kB\n")
	write(t, root, "proc/self/stat", "42 (kiyesi agent) S 1 2 3 4 5 6 7 8 9 10 100 50 0 0")
	write(t, root, "proc/self/cgroup", "0::/system.slice/kiyesi.service\n")
	write(t, root, "sys/fs/cgroup/system.slice/kiyesi.service/memory.max", "268435456\n")
	write(t, root, "sys/fs/cgroup/system.slice/kiyesi.service/memory.stat", "anon 62914560\nfile 180000000\nshmem 0\n")
	t0 := time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
	u := Measure(t0)
	if u.MemoryBytes != 50<<20 || u.ServiceBytes != 60<<20 || u.ServiceMaxBytes != 256<<20 || Tight() {
		t.Fatalf("use = %+v, tight = %v", u, Tight())
	}
	// Cached files (file) never count: only what cannot be freed.
	// A minute later, 6 seconds of CPU: 10%.
	write(t, root, "proc/self/stat", "42 (kiyesi agent) S 1 2 3 4 5 6 7 8 9 10 400 350 0 0")
	u = Measure(t0.Add(time.Minute))
	if u.CPUPercent == nil || *u.CPUPercent != 10 {
		t.Errorf("cpu = %v", u.CPUPercent)
	}
	if Skip(Languages) {
		t.Error("skipped while comfortable")
	}
	// Close to its service's limit: optional work skips its turn, and says so.
	write(t, root, "sys/fs/cgroup/system.slice/kiyesi.service/memory.stat", "anon 214748364\n")
	Measure(t0.Add(2 * time.Minute))
	if !Tight() || !Skip(Languages) || !Skip(Logs) {
		t.Fatal("not tight near the limit")
	}
	u = Measure(t0.Add(3 * time.Minute))
	if len(u.Skipped) != 2 {
		t.Errorf("skipped = %v", u.Skipped)
	}
	// Its own memory alone over budget is tight too; back to comfortable after.
	write(t, root, "sys/fs/cgroup/system.slice/kiyesi.service/memory.stat", "anon 1000\n")
	write(t, root, "proc/self/status", "VmRSS:\t200000 kB\n")
	Measure(t0.Add(4 * time.Minute))
	if !Tight() {
		t.Error("its own memory over budget is not tight")
	}
	write(t, root, "proc/self/status", "VmRSS:\t40000 kB\n")
	Measure(t0.Add(5 * time.Minute))
	if Tight() {
		t.Error("still tight once comfortable")
	}
}

func TestNoSystemdNoLimit(t *testing.T) {
	Root = t.TempDir()
	defer func() { Root = "/" }()
	u := Measure(time.Now())
	if u.ServiceMaxBytes != 0 || Tight() {
		t.Errorf("use = %+v", u)
	}
}

func TestTheServiceCanPauseOptionalWork(t *testing.T) {
	Root = t.TempDir()
	defer func() { Root = "/" }()
	Measure(time.Now())
	Pause([]string{Vulnerabilities, "something-unknown"})
	if !Skip(Vulnerabilities) || Skip(Languages) {
		t.Error("the pause is not followed")
	}
	if u := Measure(time.Now()); len(u.Skipped) != 1 || u.Skipped[0] != Vulnerabilities {
		t.Errorf("skipped = %v", u.Skipped)
	}
	Pause(nil)
	if Skip(Vulnerabilities) {
		t.Error("still paused after the service took it off")
	}
}

func TestTheWholeServiceIsMeasuredAsSystemdShowsIt(t *testing.T) {
	root := t.TempDir()
	Root = root
	defer func() { Root = "/" }()
	dir := "sys/fs/cgroup/system.slice/kiyesi.service/"
	write(t, root, "proc/self/cgroup", "0::/system.slice/kiyesi.service\n")
	write(t, root, "proc/self/status", "VmRSS:\t4096 kB\n")
	write(t, root, dir+"memory.stat", "anon 163840\nfile 202223616\n")
	write(t, root, dir+"memory.current", "202387456\n")
	write(t, root, dir+"cpu.stat", "usage_usec 1000000\nuser_usec 600000\n")
	t0 := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	Measure(t0)
	// A minute later the service, with what it runs, used 11.4 seconds: 19%.
	write(t, root, dir+"cpu.stat", "usage_usec 12400000\n")
	u := Measure(t0.Add(time.Minute))
	if u.ServiceTotalBytes != 202387456 || u.ServiceBytes != 163840 {
		t.Errorf("memory = %+v", u)
	}
	if u.ServiceCPUPercent == nil || *u.ServiceCPUPercent != 19 {
		t.Errorf("service cpu = %v", u.ServiceCPUPercent)
	}
	// Mostly cached files: not tight, as the cache is the system's to free.
	if Tight() {
		t.Error("tight on cache alone")
	}
}
