package collect

import (
	"context"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

type fakeDocker struct {
	list  []system.Container
	lines map[string][]system.LogLine
}

func (f *fakeDocker) Containers(context.Context) ([]system.Container, error) { return f.list, nil }
func (f *fakeDocker) DiskUsage(context.Context) (system.DiskUsage, error) {
	return system.DiskUsage{}, nil
}

func (f *fakeDocker) Dies(context.Context, time.Time, time.Time) (map[string]int, error) {
	return nil, nil
}
func (f *fakeDocker) Logs(_ context.Context, id string, since time.Time) ([]system.LogLine, error) {
	var out []system.LogLine
	for _, l := range f.lines[id] {
		if l.At.After(since) {
			out = append(out, l)
		}
	}
	return out, nil
}

const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func files(cpuBusy, cpuIdle, rx, tx, oom, usageUsec string, access string) fstest.MapFS {
	return fstest.MapFS{
		"proc/stat":        {Data: []byte("cpu  " + cpuBusy + " 0 0 " + cpuIdle + " 0 0 0 0 0 0\ncpu0 1 0 0 1 0 0 0 0 0 0\ncpu1 1 0 0 1 0 0 0 0 0 0\n")},
		"proc/loadavg":     {Data: []byte("0.42 0.30 0.20 1/100 1234\n")},
		"proc/meminfo":     {Data: []byte("MemTotal:  2000000 kB\nMemFree: 100000 kB\nMemAvailable: 1500000 kB\nSwapTotal: 2097152 kB\nSwapFree: 2000000 kB\n")},
		"proc/net/dev":     {Data: []byte("Inter-|   Receive\n face |bytes packets\n    lo: 999 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0\n  eth0: " + rx + " 10 0 0 0 0 0 0 " + tx + " 10 0 0 0 0 0 0\nveth1: 5000 1 0 0 0 0 0 0 5000 1 0 0 0 0 0 0\n")},
		"proc/vmstat":      {Data: []byte("nr_free_pages 1\noom_kill " + oom + "\n")},
		"proc/self/mounts": {Data: []byte("/dev/vda1 / ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n")},
		"sys/fs/cgroup/system.slice/docker-" + id + ".scope/cpu.stat":       {Data: []byte("usage_usec " + usageUsec + "\nuser_usec 1\n")},
		"sys/fs/cgroup/system.slice/docker-" + id + ".scope/memory.current": {Data: []byte("314572800\n")},
		"sys/fs/cgroup/system.slice/docker-" + id + ".scope/memory.stat":    {Data: []byte("anon 1\ninactive_file 104857600\n")},
		"sys/fs/cgroup/system.slice/docker-" + id + ".scope/memory.max":     {Data: []byte("max\n")},
		"var/log/nginx/access.log":                                          {Data: []byte(access)},
	}
}

func TestCollectWorksOutRatesFromTwoMinutes(t *testing.T) {
	start := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	now := start
	line := `203.0.113.9 - - [10/Oct/2026:10:00:30 +0000] "GET /api/users/7 HTTP/1.1" 200 5 "-" "ua" 0.040` + "\n"
	docker := &fakeDocker{
		list: []system.Container{{ID: id, Name: "checkout-api", Image: "checkout-api:3.8.0", ImageID: "sha256:a", Status: "running", StartedAt: "t1"},
			{ID: "c2", Name: "caddy", Image: "caddy:2.11.6-alpine", ImageID: "sha256:c", Status: "running", StartedAt: "t1"}},
		lines: map[string][]system.LogLine{"c2": {
			{At: start.Add(30 * time.Second), Text: `{"msg":"handled request","request":{"method":"POST","uri":"/checkout?card=4111"},"duration":0.5,"status":502}`},
		}},
	}
	statfs := func(string) (system.Usage, error) {
		return system.Usage{TotalBytes: 100, FreeBytes: 40, AvailBytes: 30}, nil
	}
	sys := &system.System{FS: files("100", "900", "1000", "2000", "3", "1000000", "old line\n"), Docker: docker, Statfs: statfs, Now: func() time.Time { return now }}
	c := &Collector{Sys: sys}

	m, events := c.Collect(context.Background())
	if m.CPUPercent != nil || m.Net != nil || len(events) != 0 || len(m.HTTP) != 0 {
		t.Fatalf("the first minute has nothing to compare with: %+v %v", m, events)
	}
	if m.Memory.UsedBytes != 500000*1024 || m.Disks[0].UsedBytes != 60 || m.Disks[0].TotalBytes != 90 {
		t.Errorf("memory or disk: %+v %+v", m.Memory, m.Disks)
	}

	now = start.Add(time.Minute)
	sys.FS = files("400", "1600", "61000", "122000", "4", "7000000", "old line\n"+line)
	docker.list[0].ImageID, docker.list[0].Image = "sha256:b", "checkout-api:3.8.1"
	m, events = c.Collect(context.Background())
	if m.CPUPercent == nil || *m.CPUPercent != 30 {
		t.Errorf("cpu = %v, want 30 (300 busy of 1000)", m.CPUPercent)
	}
	if m.Net == nil || m.Net.RxBytesPerSec != 1000 || m.Net.TxBytesPerSec != 2000 {
		t.Errorf("net = %+v, want 1000 and 2000 bytes a second, without lo and veth", m.Net)
	}
	var api Container
	for _, ct := range m.Containers {
		if ct.Name == "checkout-api" {
			api = ct
		}
	}
	// 6 seconds of CPU in 60 seconds on 2 cores is 5% of the server.
	if api.CPUPercent == nil || *api.CPUPercent != 5 || *api.MemBytes != 200*1024*1024 || api.MemLimitBytes != nil {
		t.Errorf("container = %+v", api)
	}
	kinds := map[string]string{}
	for _, e := range events {
		kinds[e.Kind] = e.Subject + " " + e.Detail
	}
	if kinds["image_changed"] != "checkout-api checkout-api:3.8.1" || kinds["oom_kill"] == "" {
		t.Errorf("events = %+v", events)
	}
	got := map[string]EndpointStats{}
	for _, e := range m.HTTP {
		got[e.Endpoint] = e
	}
	if got["GET /api/users/:id"].Requests != 1 || *got["GET /api/users/:id"].P95Ms != 40 {
		t.Errorf("nginx file: %+v", m.HTTP)
	}
	if got["POST /checkout"].Errors != 1 {
		t.Errorf("caddy container: %+v", m.HTTP)
	}
	if m.HTTPSource != "/var/log/nginx/access.log, caddy (container)" {
		t.Errorf("source = %q", m.HTTPSource)
	}

	// Nothing new: no requests counted twice.
	now = start.Add(2 * time.Minute)
	m, _ = c.Collect(context.Background())
	if len(m.HTTP) != 0 {
		t.Errorf("counted again: %+v", m.HTTP)
	}
}

func TestReadContainerCgroupV1(t *testing.T) {
	fsys := fstest.MapFS{
		"sys/fs/cgroup/cpuacct/docker/x/cpuacct.usage":        {Data: []byte("5000000000\n")},
		"sys/fs/cgroup/memory/docker/x/memory.usage_in_bytes": {Data: []byte("1000\n")},
		"sys/fs/cgroup/memory/docker/x/memory.stat":           {Data: []byte("total_inactive_file 200\n")},
		"sys/fs/cgroup/memory/docker/x/memory.limit_in_bytes": {Data: []byte("9223372036854771712\n")},
	}
	u := readContainer(fsys, "x")
	if !u.hasCPU || u.cpuUsec != 5000000 || u.memBytes != 800 || u.memLimit != 0 {
		t.Errorf("v1 = %+v", u)
	}
}
