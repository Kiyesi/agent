package collect

import (
	"context"
	"fmt"
	"strings"
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

func TestNginxLogsListsEveryLogButOldOnes(t *testing.T) {
	fsys := fstest.MapFS{}
	for _, n := range []string{
		"access.log", "error.log",
		"shop.example.com.access.log", "shop.example.com.error.log",
		"blog-access.log", "access_api.example.com.log",
		// Rotated, compressed or dated: old lines, never read.
		"access.log.1", "access.log.2.gz", "access.log-20261019", "shop.example.com.access.log.1",
		"access-2026-10-19.log", "access.20261019.log", "access.3.log",
		// Not an access or error log.
		"nginx.pid", "notes.txt", "upstream.log",
	} {
		fsys["var/log/nginx/"+n] = &fstest.MapFile{Data: []byte("x\n")}
	}
	fsys["var/log/nginx/old-access.log/inside"] = &fstest.MapFile{}
	access, errs := nginxLogs(fsys)
	if strings.Join(access, " ") != "var/log/nginx/access.log var/log/nginx/access_api.example.com.log var/log/nginx/blog-access.log var/log/nginx/shop.example.com.access.log" {
		t.Errorf("access logs = %v", access)
	}
	if strings.Join(errs, " ") != "var/log/nginx/error.log var/log/nginx/shop.example.com.error.log" {
		t.Errorf("error logs = %v", errs)
	}
	if a, e := nginxLogs(fstest.MapFS{}); a != nil || e != nil {
		t.Errorf("no nginx: %v %v", a, e)
	}
}

func TestNginxLogsReadsAtMostMaxLogFiles(t *testing.T) {
	fsys := fstest.MapFS{"var/log/nginx/access.log": {}}
	for i := 0; i < MaxLogFiles+20; i++ {
		fsys[fmt.Sprintf("var/log/nginx/site%03d.example.com.access.log", i)] = &fstest.MapFile{}
	}
	access, _ := nginxLogs(fsys)
	if len(access) != MaxLogFiles || access[0] != "var/log/nginx/access.log" {
		t.Errorf("read %d files, first %q", len(access), access[0])
	}
}

func TestSiteAndSourceFromTheFileName(t *testing.T) {
	cases := []struct {
		file, site, source string
		errorLog           bool
	}{
		{"access.log", "", "nginx", false},
		{"error.log", "", "nginx error", true},
		{"shop.example.com.access.log", "shop.example.com", "nginx shop.example.com", false},
		{"shop.example.com.error.log", "shop.example.com", "nginx shop.example.com error", true},
		{"shop-access.log", "shop", "nginx shop", false},
		{"shop_error.log", "shop", "nginx shop error", true},
		{"access_api.example.com.log", "api.example.com", "nginx api.example.com", false},
		{"Blog.Example.com-access.log", "blog.example.com", "nginx blog.example.com", false},
		{"ssl_access.log", "", "nginx", false},
		{"default.access.log", "", "nginx", false},
		{"203.0.113.9.access.log", "", "nginx", false},
	}
	for _, c := range cases {
		p := "var/log/nginx/" + c.file
		if got := fileSite(p); got != c.site {
			t.Errorf("fileSite(%q) = %q, want %q", c.file, got, c.site)
		}
		if got := fileSource(p, c.errorLog); got != c.source {
			t.Errorf("fileSource(%q) = %q, want %q", c.file, got, c.source)
		}
	}
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + ".example.com"
	if got := fileSource("var/log/nginx/"+long+".error.log", true); len(got) != 200 || !strings.HasPrefix(got, "nginx aaa") {
		t.Errorf("a long name gives %d characters: %q", len(got), got)
	}
}

func TestCollectNamesTheSiteOfEachRequest(t *testing.T) {
	start := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	now := start
	logs := func(shop, blog, plain, shopErr string) fstest.MapFS {
		fsys := files("100", "900", "1000", "2000", "3", "1000000", plain)
		fsys["var/log/nginx/shop.example.com.access.log"] = &fstest.MapFile{Data: []byte(shop)}
		fsys["var/log/nginx/blog-access.log"] = &fstest.MapFile{Data: []byte(blog)}
		fsys["var/log/nginx/shop.example.com.error.log"] = &fstest.MapFile{Data: []byte(shopErr)}
		fsys["var/log/nginx/access.log.1"] = &fstest.MapFile{Data: []byte("old\n")}
		return fsys
	}
	health := `203.0.113.9 - - [10/Oct/2026:10:00:30 +0000] "GET /health HTTP/1.1" 200 2 "-" "ua" 0.002` + "\n"
	sys := &system.System{FS: logs("old\n", "old\n", "old\n", "old\n"), Now: func() time.Time { return now }}
	c := &Collector{Sys: sys, Logs: true}
	c.Collect(context.Background())
	c.TakeLogs()

	now = start.Add(time.Minute)
	// The plain log says the site on the line; the per-site files do not.
	vhost := `api.example.com:443 203.0.113.9 - - [10/Oct/2026:10:00:40 +0000] "GET /health HTTP/1.1" 200 2 "-" "ua"` + "\n"
	sys.FS = logs("old\n"+health+health, "old\n"+health, "old\n"+health+vhost, "old\n2026/10/10 10:00:41 [error] 12#12: upstream timed out\n")
	sys.FS.(fstest.MapFS)["var/log/nginx/access.log.1"] = &fstest.MapFile{Data: []byte("old\n" + health + health + health)}
	m, _ := c.Collect(context.Background())
	got := map[string]int{}
	for _, e := range m.HTTP {
		got[e.Site+" "+e.Endpoint] = e.Requests
	}
	want := map[string]int{"shop.example.com GET /health": 2, "blog GET /health": 1, "api.example.com GET /health": 1, " GET /health": 1}
	if len(got) != len(want) {
		t.Errorf("http = %v, want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%q: %d requests, want %d (all: %v)", k, got[k], n, got)
		}
	}
	if m.HTTPSource != "/var/log/nginx/access.log, /var/log/nginx/blog-access.log, /var/log/nginx/shop.example.com.access.log" {
		t.Errorf("source = %q", m.HTTPSource)
	}
	sources := map[string]int{}
	for _, l := range c.TakeLogs().Lines {
		sources[l.Source]++
	}
	if sources["nginx"] != 2 || sources["nginx shop.example.com"] != 2 || sources["nginx blog"] != 1 || sources["nginx shop.example.com error"] != 1 || len(sources) != 4 {
		t.Errorf("log sources = %v", sources)
	}

	// A site's log that goes away is forgotten.
	delete(sys.FS.(fstest.MapFS), "var/log/nginx/blog-access.log")
	now = start.Add(2 * time.Minute)
	c.Collect(context.Background())
	if _, ok := c.fileOffset["var/log/nginx/blog-access.log"]; ok || len(c.fileOffset) != 3 {
		t.Errorf("offsets = %v", c.fileOffset)
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
