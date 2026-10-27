package checks

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

const fourCores = "processor\t: 0\nmodel name\t: x\n\nprocessor\t: 1\n\nprocessor\t: 2\n\nprocessor\t: 3\n"

func TestLoad(t *testing.T) {
	ok := run(t, loadCheck{}, newTestEnv().file("proc/loadavg", "0.52 0.61 0.80 2/411 48211\n").file("proc/cpuinfo", fourCores))
	wantStatus(t, ok, StatusPass)
	if ok.Vars["load"] != "0.20" {
		t.Errorf("load per core = %q, want 0.20", ok.Vars["load"])
	}
	high := run(t, loadCheck{}, newTestEnv().file("proc/loadavg", "5.10 4.80 3.90 9/411 48211\n").file("proc/cpuinfo", fourCores))
	wantStatus(t, high, StatusFail, "high")
	if high.Findings[0].Vars["load"] != "0.97" || high.Findings[0].Vars["limit"] != "0.85" {
		t.Errorf("vars = %v", high.Findings[0].Vars)
	}
	wantStatus(t, run(t, loadCheck{}, newTestEnv()), StatusSkip)
}

func TestMemory(t *testing.T) {
	small := run(t, memoryCheck{}, newTestEnv().saved(t, "proc/meminfo", "meminfo-1gb-noswap"))
	wantStatus(t, small, StatusFail, "high", "no-swap")
	if small.Findings[0].Vars["percent"] != "93" || small.Findings[1].Vars["total"] != "974 MB" {
		t.Errorf("vars = %v / %v", small.Findings[0].Vars, small.Findings[1].Vars)
	}
	big := run(t, memoryCheck{}, newTestEnv().saved(t, "proc/meminfo", "meminfo-8gb-swap"))
	wantStatus(t, big, StatusPass)
	if big.Vars["total"] != "7.8 GB" || big.Vars["percent"] != "27" {
		t.Errorf("vars = %v", big.Vars)
	}
}

func TestDisk(t *testing.T) {
	gb := uint64(1 << 30)
	e := newTestEnv().saved(t, "proc/self/mounts", "mounts")
	e.usage["/"] = system.Usage{TotalBytes: 25 * gb, FreeBytes: 9 * gb, AvailBytes: 8 * gb, TotalInodes: 1000, FreeInodes: 600}
	e.usage["/boot/efi"] = system.Usage{TotalBytes: 100 << 20, FreeBytes: 90 << 20, AvailBytes: 90 << 20}
	e.usage["/mnt/volume data"] = system.Usage{TotalBytes: 100 * gb, FreeBytes: 5 * gb, AvailBytes: 5 * gb, TotalInodes: 1000, FreeInodes: 150}
	r := run(t, diskCheck{}, e)
	wantStatus(t, r, StatusFail, "space-critical", "inodes-warning")
	if r.Findings[0].Vars["mount"] != "/mnt/volume data" || r.Findings[0].Vars["percent"] != "95" {
		t.Errorf("vars = %v", r.Findings[0].Vars)
	}
	// "/" is 16 of 24 GB a user can fill: 66%, under the warning.
	delete(e.usage, "/mnt/volume data")
	wantStatus(t, run(t, diskCheck{}, e), StatusPass)
}

func TestContainers(t *testing.T) {
	e := newTestEnv()
	e.docker = fakeDocker{
		cs: []system.Container{
			{ID: "1", Name: "checkout-api", Status: "running", Health: "healthy"},
			{ID: "2", Name: "worker", Status: "running", Health: "unhealthy"},
			{ID: "3", Name: "migrate", Status: "exited", ExitCode: 0, RestartPolicy: "no"},
			{ID: "4", Name: "queue", Status: "exited", ExitCode: 137, RestartPolicy: "unless-stopped"},
		},
		dies: map[string]int{"1": 3},
	}
	wantStatus(t, run(t, containersCheck{}, e), StatusFail, "restarts", "unhealthy", "exited")

	healthy := newTestEnv()
	healthy.docker = fakeDocker{cs: []system.Container{{ID: "1", Name: "a", Status: "running"}}}
	r := run(t, containersCheck{}, healthy)
	wantStatus(t, r, StatusPass)
	if r.Vars["count"] != "1" {
		t.Errorf("vars = %v", r.Vars)
	}
	if r := run(t, containersCheck{}, newTestEnv()); r.Status != StatusPass || !r.None {
		t.Errorf("no Docker should pass with nothing to check: %+v", r)
	}
	denied := newTestEnv()
	denied.docker = fakeDocker{err: system.ErrNeedsRoot}
	denied.root = false
	if r := run(t, containersCheck{}, denied); r.Status != StatusSkip || r.SkipKey != "needs-root" {
		t.Errorf("no access to Docker: %+v", r)
	}
}

func TestOOM(t *testing.T) {
	e := newTestEnv().saved(t, "proc/meminfo", "meminfo-1gb-noswap").command("journalctl -k --since -24h --no-pager -q -o short-iso", mustRead(t, "journal-k.txt"))
	r := run(t, oomCheck{}, e)
	wantStatus(t, r, StatusFail, "killed-no-swap")
	if v := r.Findings[0].Vars; v["process"] != "node" || v["time"] != "10:41" {
		t.Errorf("vars = %v", v)
	}
	// Without root, kern.log is read; the kill from two days ago is left out.
	nr := newTestEnv().saved(t, "proc/meminfo", "meminfo-8gb-swap").saved(t, "var/log/kern.log", "kern.log")
	nr.root = false
	r = run(t, oomCheck{}, nr)
	wantStatus(t, r, StatusFail, "killed")
	// Without root and without kern.log, an empty answer would be a lie.
	blind := newTestEnv()
	blind.root = false
	if r := run(t, oomCheck{}, blind); r.SkipKey != "needs-root" {
		t.Errorf("want needs-root, got %+v", r)
	}
	// As root with no journald and no kern.log, as in a minimal container.
	if r := run(t, oomCheck{}, newTestEnv()); r.SkipKey != "no-kernel-log" {
		t.Errorf("want no-kernel-log, got %+v", r)
	}
	quiet := newTestEnv().command("journalctl -k --since -24h --no-pager -q -o short-iso", "")
	wantStatus(t, run(t, oomCheck{}, quiet), StatusPass)
}

// Kills made by the kiyesi service's own memory limit (apt-get run by a
// check, or the agent itself) do not count against the server; a
// container's own limit still does.
func TestOOMLeavesOutKiyesisOwnLimit(t *testing.T) {
	e := newTestEnv().saved(t, "proc/meminfo", "meminfo-1gb-noswap").command("journalctl -k --since -24h --no-pager -q -o short-iso", mustRead(t, "journal-k-own-limit.txt"))
	r := run(t, oomCheck{}, e)
	wantStatus(t, r, StatusFail, "killed-no-swap")
	if len(r.Findings) != 1 || r.Findings[0].Vars["process"] != "node" {
		t.Errorf("findings = %+v", r.Findings)
	}
	only := strings.Join(strings.Split(mustRead(t, "journal-k-own-limit.txt"), "\n")[:5], "\n")
	wantStatus(t, run(t, oomCheck{}, newTestEnv().command("journalctl -k --since -24h --no-pager -q -o short-iso", only)), StatusPass)
}

func mustRead(tb testing.TB, name string) string {
	tb.Helper()
	e := newTestEnv().saved(tb, "x", name)
	return string(e.fs["x"].Data)
}

// No backup folder named means different things by where the data lives.
func TestBackupsNotNamed(t *testing.T) {
	// A server with no database anywhere: nothing for this check to look at.
	r := run(t, backupsCheck{}, newTestEnv())
	if r.Status != StatusSkip || r.SkipKey != "no-data" {
		t.Errorf("no data: %+v", r)
	}
	// A database installed here, with no backup anywhere: the warning.
	e := newTestEnv()
	e.fs["var/lib/postgresql/16/main/PG_VERSION"] = &fstest.MapFile{Data: []byte("16\n")}
	wantStatus(t, run(t, backupsCheck{}, e), StatusFail, "not-set")
	// The owner's server: its only database is MongoDB Atlas, from the
	// app's settings. Backups are Atlas's, by its plan: no warning.
	e = newTestEnv()
	e.fs["opt/appstack/.env"] = &fstest.MapFile{Data: []byte("MONGODB_URI=mongodb+srv://app:" + "s3cret@cluster0.ab1cd.mongodb.net/test\n"), Mode: 0o600}
	e.cfg.Secrets.Paths = []string{"/opt"}
	r = run(t, backupsCheck{}, e)
	if r.Status != StatusSkip || r.SkipKey != "elsewhere" || !strings.Contains(r.SkipVars["where"], "cluster0.ab1cd.mongodb.net") || strings.Contains(r.SkipVars["where"], "s3cret") {
		t.Errorf("hosted only: %+v", r)
	}
	// A database here, backed up off the server by restic: named, not "none".
	e = appEnv(t)
	e.fs["var/lib/mysql/ibdata1"] = &fstest.MapFile{Data: []byte("x")}
	r = run(t, backupsCheck{}, e)
	if r.Status != StatusSkip || r.SkipKey != "offsite" || !strings.Contains(r.SkipVars["to"], "restic") {
		t.Errorf("offsite: %+v", r)
	}
}

func TestBackups(t *testing.T) {

	e := newTestEnv()
	e.cfg.Backups.Paths = []string{"/var/backups/db"}
	e.fs["var/backups/db/2026-10-07.sql.gz"] = &fstest.MapFile{Data: []byte("x"), ModTime: now.Add(-31 * time.Hour)}
	r := run(t, backupsCheck{}, e)
	wantStatus(t, r, StatusFail, "old")
	if v := r.Findings[0].Vars; v["age"] != "31 hours" || v["when"] != "Wed 7 Oct at 08:00" {
		t.Errorf("vars = %v", v)
	}
	e.fs["var/backups/db/2026-10-08.sql.gz"] = &fstest.MapFile{Data: []byte("x"), ModTime: now.Add(-3 * time.Hour)}
	wantStatus(t, run(t, backupsCheck{}, e), StatusPass)

	missing := newTestEnv()
	missing.cfg.Backups.Paths = []string{"/srv/none"}
	wantStatus(t, run(t, backupsCheck{}, missing), StatusFail, "empty")
}

func TestUpdatesRemembersWhenEachWasFirstSeen(t *testing.T) {
	e := newTestEnv().command("apt-get -s -o Debug::NoLocking=1 upgrade", mustRead(t, "apt-upgrade-security.txt"))
	// First scan: two security updates, first seen now. No warning yet.
	wantStatus(t, run(t, updatesCheck{}, e), StatusPass)
	if e.state.M["security-update/openssl"] != now.Format(time.RFC3339) {
		t.Fatalf("state = %v", e.state.M)
	}
	// Eight days later, both are still waiting.
	e.state.M["security-update/openssl"] = now.Add(-8 * 24 * time.Hour).Format(time.RFC3339)
	e.state.M["security-update/libssl3"] = now.Add(-8 * 24 * time.Hour).Format(time.RFC3339)
	e.state.M["security-update/removed"] = now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	r := run(t, updatesCheck{}, e)
	wantStatus(t, r, StatusFail, "waiting")
	if r.Findings[0].Vars["count"] != "2" {
		t.Errorf("vars = %v", r.Findings[0].Vars)
	}
	if _, ok := e.state.M["security-update/removed"]; ok {
		t.Error("an update no longer waiting should be forgotten")
	}
	if r := run(t, updatesCheck{}, newTestEnv()); r.SkipKey != "no-apt" {
		t.Errorf("no apt: %+v", r)
	}
}

// Under the old 64 MB service limit apt-get is never started: the kernel
// would kill it. 256 MB, no limit, or a limit that cannot be read all run it.
func TestUpdatesWaitsForRoomForApt(t *testing.T) {
	apt := mustRead(t, "apt-upgrade-security.txt")
	limited := func(max string) *testEnv {
		return newTestEnv().command("apt-get -s -o Debug::NoLocking=1 upgrade", apt).
			file("proc/self/cgroup", "0::/system.slice/kiyesi.service\n").
			file("sys/fs/cgroup/system.slice/kiyesi.service/memory.max", max+"\n")
	}
	if r := run(t, updatesCheck{}, limited("67108864")); r.SkipKey != "memory-limit" {
		t.Errorf("64 MB: %+v", r)
	}
	for _, e := range []*testEnv{
		limited("268435456"),
		limited("max"),
		newTestEnv().command("apt-get -s -o Debug::NoLocking=1 upgrade", apt),
		newTestEnv().command("apt-get -s -o Debug::NoLocking=1 upgrade", apt).file("proc/self/cgroup", "0::/user.slice\n"),
	} {
		if r := run(t, updatesCheck{}, e); r.Status != StatusPass {
			t.Errorf("should run apt: %+v", r)
		}
	}
}

func TestCertificates(t *testing.T) {
	e := newTestEnv()
	e.fs["etc/letsencrypt/live/api.example.com/cert.pem"] = &fstest.MapFile{Data: testCert(t, "api.example.com", now.Add(9*24*time.Hour+time.Hour))}
	e.fs["var/lib/docker/volumes/caddy_data/_data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/shop.example.com/shop.example.com.crt"] = &fstest.MapFile{Data: testCert(t, "shop.example.com", now.Add(-2*24*time.Hour))}
	e.file("etc/nginx/sites-enabled/old", "server {\n  ssl_certificate /etc/ssl/old.pem;\n}\n")
	e.fs["etc/ssl/old.pem"] = &fstest.MapFile{Data: testCert(t, "old.example.com", now.Add(200*24*time.Hour))}
	r := run(t, certificatesCheck{}, e)
	wantStatus(t, r, StatusFail, "expired", "expiring")
	if v := r.Findings[1].Vars; v["host"] != "api.example.com" || v["days"] != "9" || r.Findings[1].Variant != "" {
		t.Errorf("expiring = %+v", r.Findings[1])
	}
	if r.Findings[0].Variant != "caddy" || r.Findings[0].Vars["days"] != "2" {
		t.Errorf("expired = %+v", r.Findings[0])
	}
	if r := run(t, certificatesCheck{}, newTestEnv()); !r.None {
		t.Errorf("no certificates: %+v", r)
	}
}

func TestCertificatesWithoutRoot(t *testing.T) {
	e := newTestEnv()
	e.root = false
	e.fs = fstest.MapFS{}
	sys := e.env()
	sys.Sys.FS = deniedFS{fstest.MapFS{"etc/letsencrypt/live/x": {Mode: fs.ModeDir}}, "etc/letsencrypt/live"}
	if r := (certificatesCheck{}).Run(t.Context(), sys); r.SkipKey != "needs-root" {
		t.Errorf("want needs-root, got %+v", r)
	}
}

// deniedFS refuses to read one folder, as Linux does for /etc/letsencrypt/live.
type deniedFS struct {
	fstest.MapFS
	denied string
}

func (d deniedFS) Open(name string) (fs.File, error) {
	if name == d.denied {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return d.MapFS.Open(name)
}

func (d deniedFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == d.denied {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return d.MapFS.ReadDir(name)
}

var _ = errors.New
