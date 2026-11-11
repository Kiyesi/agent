package collect

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/budget"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// The agent's service CPU is the CPU used between two readings over the time
// between those readings. A minute whose checks ran slower than the last
// must not make a service held at its 20% cap look over it.
func TestServiceCPUOverTheTimeBetweenReadings(t *testing.T) {
	root := t.TempDir()
	budget.Root = root
	t.Cleanup(func() { budget.Root = "/" })
	put := func(p, s string) {
		f := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("proc/self/cgroup", "0::/system.slice/kiyesi.service\n")
	stat := "sys/fs/cgroup/system.slice/kiyesi.service/cpu.stat"
	put(stat, "usage_usec 1000000\n")

	// Each round's checks start on the minute; the first takes 2 s, the
	// second 11 s, so the two CPU readings are 69 s apart.
	start := time.Date(2026, 11, 11, 20, 40, 0, 0, time.UTC)
	clock := []time.Time{start, start.Add(2 * time.Second), start.Add(time.Minute), start.Add(time.Minute + 11*time.Second)}
	sys := &system.System{FS: files("100", "900", "1000", "2000", "3", "1000000", ""), Now: func() time.Time {
		at := clock[0]
		if len(clock) > 1 {
			clock = clock[1:]
		}
		return at
	}}
	c := &Collector{Sys: sys}
	c.Collect(context.Background())
	// At its cap: 20% of the 69 s between the readings, 13.8 s of CPU.
	put(stat, "usage_usec 14800000\n")
	m, _ := c.Collect(context.Background())
	if m.Agent == nil || m.Agent.ServiceCPUPercent == nil {
		t.Fatal("no service CPU")
	}
	if got := *m.Agent.ServiceCPUPercent; got != 20 {
		t.Fatalf("service CPU = %v%%, want 20%%", got)
	}
}
