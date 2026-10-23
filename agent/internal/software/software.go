// Package software lists what is installed on a server, for the service's
// end-of-life and vulnerability advisories (PRD feature 15): the system and
// its version, its packages with their source and version, each
// container's image, and a few settings the tips read. It reads files only
// and runs nothing; the service compares the list with public data.
package software

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// MaxPackages caps the list, far above a usual server's.
const MaxPackages = 5000

// List is what is installed.
type List struct {
	OS          OS          `json:"os"`
	Kernel      string      `json:"kernel,omitempty"`
	Packages    []Package   `json:"packages"`
	Containers  []Container `json:"containers"`
	Docker      *Docker     `json:"docker,omitempty"`
	MemoryBytes int64       `json:"memory_bytes"`
	SwapBytes   int64       `json:"swap_bytes"`
	// AutoUpdates is set on Debian and Ubuntu: whether security updates install by themselves.
	AutoUpdates *bool `json:"auto_updates,omitempty"`
	// Settings are a few of the server's settings, for comparing two
	// servers that should be alike: names and values, never a secret.
	Settings *Settings `json:"settings,omitempty"`
}

// Settings are what kiyesi compare sets side by side, beside the packages.
type Settings struct {
	// Ports are the TCP ports listening on a public address.
	Ports []int `json:"ports"`
	// Services are the systemd services running, by unit name.
	Services []string `json:"services"`
	// SSH is how SSH lets people in, when it runs.
	SSH *SSHSettings `json:"ssh,omitempty"`
	// Firewall is ufw, firewalld, nftables or iptables when one is on,
	// "off" when none is, or "" when it could not be read.
	Firewall string `json:"firewall,omitempty"`
	// Timezone is the system's time zone, such as Etc/UTC.
	Timezone string `json:"timezone,omitempty"`
}

// SSHSettings are SSH's login settings.
type SSHSettings struct {
	PasswordLogin bool  `json:"password_login"`
	RootLogin     bool  `json:"root_login"`
	Ports         []int `json:"ports"`
}

// ParseRunning reads systemctl list-units --type=service --state=running
// --plain --no-legend: one unit name per line, sorted, at most 300.
func ParseRunning(out string) []string {
	var units []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.HasSuffix(f[0], ".service") && len(f[0]) <= 120 {
			units = append(units, f[0])
		}
	}
	sort.Strings(units)
	if len(units) > 300 {
		units = units[:300]
	}
	return units
}

// Timezone reads the system's time zone from /etc/timezone, or from where
// /etc/localtime points.
func Timezone(fsys fs.FS) string {
	if b, err := fs.ReadFile(fsys, "etc/timezone"); err == nil {
		if tz := strings.TrimSpace(string(b)); tz != "" && len(tz) <= 60 {
			return tz
		}
	}
	if l, ok := fsys.(fs.ReadLinkFS); ok {
		if t, err := l.ReadLink("etc/localtime"); err == nil {
			if _, tz, ok := strings.Cut(t, "zoneinfo/"); ok && len(tz) <= 60 {
				return tz
			}
		}
	}
	return ""
}

// OS is the system from os-release.
type OS struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
	Codename  string `json:"codename,omitempty"`
	Name      string `json:"name"`
}

// Package is one installed package, named by its source as the advisories are.
type Package struct {
	Name    string `json:"name"`
	Source  string `json:"source"`
	Version string `json:"version"`
	Manager string `json:"manager"` // dpkg, apk or rpm
}

// Container is one container's image and the settings the tips read.
type Container struct {
	Name          string `json:"name"`
	Image         string `json:"image"`
	MemoryLimit   int64  `json:"memory_limit"`
	RestartPolicy string `json:"restart_policy"`
	// The container's own log settings, which override the daemon's.
	LogDriver  string `json:"log_driver,omitempty"`
	LogMaxSize string `json:"log_max_size,omitempty"`
}

// Docker is the daemon's log settings.
type Docker struct {
	LogDriver  string `json:"log_driver"`
	LogMaxSize string `json:"log_max_size,omitempty"`
}

// Read lists what is installed on the system.
func Read(ctx context.Context, sys *system.System) List {
	out := List{Packages: []Package{}, Containers: []Container{}}
	fsys := sys.FS
	out.OS = readOS(fsys)
	if b, err := fs.ReadFile(fsys, "proc/sys/kernel/osrelease"); err == nil {
		out.Kernel = strings.TrimSpace(string(b))
	}
	out.Packages = append(readDpkg(fsys), readApk(fsys)...)
	if rpmFamily[out.OS.ID] {
		out.Packages = append(out.Packages, readRpm(ctx, sys)...)
	}
	sort.Slice(out.Packages, func(i, j int) bool { return out.Packages[i].Name < out.Packages[j].Name })
	if len(out.Packages) > MaxPackages {
		out.Packages = out.Packages[:MaxPackages]
	}
	out.MemoryBytes, out.SwapBytes = readMem(fsys)
	if out.OS.ID == "ubuntu" || out.OS.ID == "debian" {
		on := autoUpdates(fsys, out.Packages)
		out.AutoUpdates = &on
	}
	if sys.Docker != nil {
		if cs, err := sys.Docker.Containers(ctx); err == nil {
			for _, c := range cs {
				out.Containers = append(out.Containers, Container{
					Name: c.Name, Image: c.Image, MemoryLimit: c.MemoryLimit, RestartPolicy: c.RestartPolicy,
					LogDriver: c.LogDriver, LogMaxSize: c.LogMaxSize,
				})
			}
			d := readDocker(fsys)
			out.Docker = &d
		}
	}
	return out
}

// Print is a short fingerprint, so the list is sent only when it changed.
func (l List) Print() string {
	b, _ := json.Marshal(l)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func readOS(fsys fs.FS) OS {
	data, err := fs.ReadFile(fsys, "etc/os-release")
	if err != nil {
		data, _ = fs.ReadFile(fsys, "usr/lib/os-release")
	}
	vals := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			vals[k] = strings.Trim(v, `"'`)
		}
	}
	return OS{ID: vals["ID"], VersionID: vals["VERSION_ID"], Codename: vals["VERSION_CODENAME"], Name: vals["PRETTY_NAME"]}
}

// sourceField is "openssl" or "openssl (3.0.2-0ubuntu1)".
var sourceField = regexp.MustCompile(`^(\S+)(?: \(([^)]+)\))?$`)

// readDpkg reads Debian and Ubuntu's package database: each installed
// package, by its source package and the source's version, as the
// distributions' advisories name them.
func readDpkg(fsys fs.FS) []Package {
	data, err := fs.ReadFile(fsys, "var/lib/dpkg/status")
	if err != nil {
		return nil
	}
	var out []Package
	seen := map[string]bool{}
	for _, stanza := range strings.Split(string(data), "\n\n") {
		f := map[string]string{}
		for _, line := range strings.Split(stanza, "\n") {
			if k, v, ok := strings.Cut(line, ": "); ok && !strings.HasPrefix(line, " ") {
				f[k] = v
			}
		}
		if f["Package"] == "" || !strings.HasSuffix(f["Status"], " installed") || f["Version"] == "" {
			continue
		}
		p := Package{Name: f["Package"], Source: f["Package"], Version: f["Version"], Manager: "dpkg"}
		if m := sourceField.FindStringSubmatch(f["Source"]); m != nil {
			p.Source = m[1]
			if m[2] != "" {
				p.Version = m[2]
			}
		}
		key := p.Name + " " + p.Version
		if !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}

// readApk reads Alpine's package database.
func readApk(fsys fs.FS) []Package {
	data, err := fs.ReadFile(fsys, "lib/apk/db/installed")
	if err != nil {
		return nil
	}
	var out []Package
	for _, stanza := range strings.Split(string(data), "\n\n") {
		p := Package{Manager: "apk"}
		for _, line := range strings.Split(stanza, "\n") {
			if len(line) < 3 || line[1] != ':' {
				continue
			}
			switch line[0] {
			case 'P':
				p.Name = line[2:]
			case 'V':
				p.Version = line[2:]
			case 'o':
				p.Source = line[2:]
			}
		}
		if p.Name == "" || p.Version == "" {
			continue
		}
		if p.Source == "" {
			p.Source = p.Name
		}
		out = append(out, p)
	}
	return out
}

func readMem(fsys fs.FS) (mem, swap int64) {
	data, err := fs.ReadFile(fsys, "proc/meminfo")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			mem = kb * 1024
		case "SwapTotal:":
			swap = kb * 1024
		}
	}
	return mem, swap
}

var periodic = regexp.MustCompile(`APT::Periodic::Unattended-Upgrade\s+"(\d+)"`)

// autoUpdates is whether unattended-upgrades is installed and turned on.
func autoUpdates(fsys fs.FS, pkgs []Package) bool {
	installed := false
	for _, p := range pkgs {
		if p.Name == "unattended-upgrades" {
			installed = true
		}
	}
	if !installed {
		return false
	}
	entries, err := fs.ReadDir(fsys, "etc/apt/apt.conf.d")
	if err != nil {
		return false
	}
	on := false
	// Later files override earlier ones, as apt reads them in order.
	for _, e := range entries {
		b, err := fs.ReadFile(fsys, "etc/apt/apt.conf.d/"+e.Name())
		if err != nil {
			continue
		}
		if m := periodic.FindSubmatch(b); m != nil {
			on = string(m[1]) != "0"
		}
	}
	return on
}

// readDocker reads the daemon's log settings; json-file with no limit is Docker's default.
func readDocker(fsys fs.FS) Docker {
	d := Docker{LogDriver: "json-file"}
	b, err := fs.ReadFile(fsys, "etc/docker/daemon.json")
	if err != nil {
		return d
	}
	var conf struct {
		LogDriver string            `json:"log-driver"`
		LogOpts   map[string]string `json:"log-opts"`
	}
	if json.Unmarshal(b, &conf) != nil {
		return d
	}
	if conf.LogDriver != "" {
		d.LogDriver = conf.LogDriver
	}
	d.LogMaxSize = conf.LogOpts["max-size"]
	return d
}

// rpmFamily are the systems whose packages rpm lists.
var rpmFamily = map[string]bool{"rhel": true, "rocky": true, "almalinux": true, "centos": true, "ol": true, "amzn": true, "fedora": true}

// The rpm database's files, newest layout first.
var rpmDBFiles = []string{"var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/rpm/Packages"}

// rpmEvery is the least time between two runs of rpm -qa: it takes a
// second or two, so it runs only when the package database changed, and
// not more often than this.
const rpmEvery = 6 * time.Hour

var rpmCache struct {
	sync.Mutex
	stamp string
	at    time.Time
	pkgs  []Package
}

// readRpm lists the installed packages of a Red Hat family system with
// rpm -qa, which only reads, each by its source package as the
// distributions' advisories name them.
func readRpm(ctx context.Context, sys *system.System) []Package {
	if sys.Exec == nil || !sys.Exec.Has("rpm") {
		return nil
	}
	stamp := ""
	for _, f := range rpmDBFiles {
		if info, err := fs.Stat(sys.FS, f); err == nil {
			stamp = f + info.ModTime().String()
			break
		}
	}
	now := time.Now()
	if sys.Now != nil {
		now = sys.Now()
	}
	rpmCache.Lock()
	defer rpmCache.Unlock()
	if rpmCache.at.IsZero() || (stamp != rpmCache.stamp && now.Sub(rpmCache.at) >= rpmEvery) {
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		out, err := sys.Exec.Run(ctx, "rpm", "-qa", "--qf", "%{NAME}\\t%{SOURCERPM}\\t%{EPOCHNUM}\\t%{VERSION}-%{RELEASE}\\n")
		if err != nil {
			return rpmCache.pkgs
		}
		rpmCache.stamp, rpmCache.at, rpmCache.pkgs = stamp, now, parseRpm(out)
	}
	return rpmCache.pkgs
}

// parseRpm reads rpm -qa's lines: name, source rpm, epoch, version-release.
func parseRpm(out []byte) []Package {
	var pkgs []Package
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 4 || f[0] == "" || f[0] == "gpg-pubkey" || f[1] == "(none)" {
			continue
		}
		version := f[3]
		if f[2] != "" && f[2] != "0" && f[2] != "(none)" {
			version = f[2] + ":" + version
		}
		pkgs = append(pkgs, Package{Name: f[0], Source: sourceOfRpm(f[1]), Version: version, Manager: "rpm"})
	}
	return pkgs
}

// sourceOfRpm is a source rpm's package name: openssl-3.0.7-28.el9_4.src.rpm is openssl.
func sourceOfRpm(srpm string) string {
	base := strings.TrimSuffix(strings.TrimSuffix(srpm, ".rpm"), ".src")
	for range 2 {
		if i := strings.LastIndex(base, "-"); i > 0 {
			base = base[:i]
		}
	}
	return base
}
