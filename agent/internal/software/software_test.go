package software

import (
	"context"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

const dpkgStatus = `Package: libssl3
Status: install ok installed
Architecture: amd64
Source: openssl
Version: 3.0.2-0ubuntu1.15

Package: openssh-server
Status: install ok installed
Source: openssh (1:8.9p1-3ubuntu0.10)
Version: 1:8.9p1-3ubuntu0.10

Package: old-thing
Status: deinstall ok config-files
Version: 1.0

Package: unattended-upgrades
Status: install ok installed
Version: 2.8ubuntu1
`

func TestReadsPackagesBySourceAndTheSettingsTheTipsUse(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/os-release":                            {Data: []byte("ID=ubuntu\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\nPRETTY_NAME=\"Ubuntu 22.04.5 LTS\"\n")},
		"proc/sys/kernel/osrelease":                 {Data: []byte("5.15.0-1\n")},
		"var/lib/dpkg/status":                       {Data: []byte(dpkgStatus)},
		"proc/meminfo":                              {Data: []byte("MemTotal:  2014832 kB\nSwapTotal: 0 kB\n")},
		"etc/apt/apt.conf.d/20auto-upgrades":        {Data: []byte("APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n")},
		"etc/apt/apt.conf.d/99local-no-auto-update": {Data: []byte("APT::Periodic::Unattended-Upgrade \"0\";\n")},
	}
	l := Read(context.Background(), &system.System{FS: fsys})
	if l.OS.ID != "ubuntu" || l.OS.VersionID != "22.04" || l.OS.Codename != "jammy" || l.Kernel != "5.15.0-1" {
		t.Errorf("os = %+v %q", l.OS, l.Kernel)
	}
	want := map[string]string{"libssl3": "openssl 3.0.2-0ubuntu1.15", "openssh-server": "openssh 1:8.9p1-3ubuntu0.10", "unattended-upgrades": "unattended-upgrades 2.8ubuntu1"}
	if len(l.Packages) != 3 {
		t.Fatalf("packages = %+v", l.Packages)
	}
	for _, p := range l.Packages {
		if want[p.Name] != p.Source+" "+p.Version || p.Manager != "dpkg" {
			t.Errorf("package %+v", p)
		}
	}
	if l.MemoryBytes != 2014832*1024 || l.SwapBytes != 0 {
		t.Errorf("memory %d swap %d", l.MemoryBytes, l.SwapBytes)
	}
	// The later file turns automatic updates off again.
	if l.AutoUpdates == nil || *l.AutoUpdates {
		t.Errorf("auto updates = %v", l.AutoUpdates)
	}
	if l.Print() == "" || l.Print() != Read(context.Background(), &system.System{FS: fsys}).Print() {
		t.Error("the same system should give the same print")
	}
}

func TestReadsAlpinePackagesByOrigin(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/os-release":       {Data: []byte("ID=alpine\nVERSION_ID=3.20.3\n")},
		"lib/apk/db/installed": {Data: []byte("C:Q1abc\nP:libcrypto3\nV:3.3.2-r0\no:openssl\n\nP:busybox\nV:1.36.1-r29\n")},
	}
	l := Read(context.Background(), &system.System{FS: fsys})
	if len(l.Packages) != 2 || l.Packages[1].Source != "openssl" || l.Packages[0].Source != "busybox" || l.AutoUpdates != nil {
		t.Errorf("%+v", l)
	}
}

type fakeRpm struct{ runs int }

func (f *fakeRpm) Has(name string) bool { return name == "rpm" }
func (f *fakeRpm) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.runs++
	return []byte("openssl-libs\topenssl-3.0.7-28.el9_4.src.rpm\t1\t3.0.7-28.el9_4\n" +
		"bash\tbash-5.1.8-9.el9.src.rpm\t0\t5.1.8-9.el9\n" +
		"gpg-pubkey\t(none)\t0\t350d275d-6279f4a2\n"), nil
}

func TestReadsRedHatFamilyPackagesWithRpmAtMostEverySixHours(t *testing.T) {
	rpmCache.at = time.Time{}
	now := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	runner := &fakeRpm{}
	fsys := fstest.MapFS{
		"etc/os-release":           {Data: []byte("ID=\"rocky\"\nVERSION_ID=\"9.4\"\n")},
		"var/lib/rpm/rpmdb.sqlite": {Data: []byte("x"), ModTime: now},
	}
	sys := &system.System{FS: fsys, Exec: runner, Now: func() time.Time { return now }}
	l := Read(context.Background(), sys)
	want := []Package{
		{Name: "bash", Source: "bash", Version: "5.1.8-9.el9", Manager: "rpm"},
		{Name: "openssl-libs", Source: "openssl", Version: "1:3.0.7-28.el9_4", Manager: "rpm"},
	}
	if len(l.Packages) != 2 || l.Packages[0] != want[0] || l.Packages[1] != want[1] {
		t.Fatalf("packages = %+v", l.Packages)
	}
	// The database changed an hour later: still not run again before six hours.
	fsys["var/lib/rpm/rpmdb.sqlite"] = &fstest.MapFile{Data: []byte("y"), ModTime: now.Add(time.Hour)}
	now = now.Add(time.Hour)
	Read(context.Background(), sys)
	if runner.runs != 1 {
		t.Errorf("rpm ran %d times within six hours", runner.runs)
	}
	now = now.Add(6 * time.Hour)
	Read(context.Background(), sys)
	if runner.runs != 2 {
		t.Errorf("rpm ran %d times after the database changed and six hours passed", runner.runs)
	}
	// Unchanged database: not run again, however long it has been.
	now = now.Add(24 * time.Hour)
	Read(context.Background(), sys)
	if runner.runs != 2 {
		t.Errorf("rpm ran again with no change: %d", runner.runs)
	}
}

func TestSourceOfRpm(t *testing.T) {
	for in, want := range map[string]string{
		"openssl-3.0.7-28.el9_4.src.rpm":            "openssl",
		"python3.11-3.11.7-1.el9.src.rpm":           "python3.11",
		"kernel-5.14.0-427.13.1.el9_4.src.rpm":      "kernel",
		"glibc-2.34-100.el9_4.2.src.rpm":            "glibc",
		"java-17-openjdk-17.0.11.0.9-2.el9.src.rpm": "java-17-openjdk",
	} {
		if got := sourceOfRpm(in); got != want {
			t.Errorf("%s = %s, want %s", in, got, want)
		}
	}
}
