package checks

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// breachCheck looks for signs that someone already got in: system programs
// that no longer match their packages, programs started from temporary
// folders, crypto miners, autostart entries that download and run code, a
// second all-powerful account, a preloaded library, and logs or history
// turned off. It only reads, and sends names and paths, never a command
// line or a file's contents, which may hold secrets.
type breachCheck struct{}

func (breachCheck) ID() string { return "break-in" }

// verifyEvery is how long the background agent reuses the package
// comparison, which reads every installed program and can take minutes.
const verifyEvery = 24 * time.Hour

// recentChange is how long a new login key or account is pointed out.
const recentChange = 7 * 24 * time.Hour

// tempDirs are the folders anyone may write to. A program started from one
// is the usual mark of a break-in.
var tempDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

// minerNames are the process names of common crypto miners, including the
// ones known malware runs under (kdevtmpfsi, kinsing).
var minerNames = map[string]bool{
	"xmrig": true, "xmr-stak": true, "xmr-stak-cpu": true, "minerd": true, "cpuminer": true,
	"kdevtmpfsi": true, "kinsing": true, "nbminer": true, "t-rex": true, "lolminer": true,
	"ethminer": true, "phoenixminer": true, "srbminer": true, "srbminer-multi": true,
	"teamredminer": true, "gminer": true, "xmrigdaemon": true, "c3pool": true,
}

// minerWords in a command line mean a miner whatever it is called.
var minerWords = []string{"stratum+tcp://", "stratum+ssl://", "stratum2+tcp://", "--donate-level", "--coin=monero", "cryptonight"}

// downloadRun is code fetched and run in one go, or a shell handed to
// another machine: never part of a normal autostart entry.
var downloadRun = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(curl|wget|fetch)\b[^|;&\n]*\|\s*(sudo\s+)?(ba|da|z|k)?sh\b`),
	regexp.MustCompile(`(?i)base64\s+(-d|--decode)[^|;&\n]*\|\s*(ba|da|z|k)?sh\b`),
	regexp.MustCompile(`/dev/tcp/\d`),
	regexp.MustCompile(`(?i)\bnc(at)?\b[^\n]*\s-e\s`),
	regexp.MustCompile(`(?i)\bbash\s+-i\s*>&`),
}

// programDirs are where system programs live; a changed file there is
// what a rootkit or a backdoor leaves.
var programDirs = []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/x86_64-linux-gnu/security/", "/usr/lib/aarch64-linux-gnu/security/", "/lib/x86_64-linux-gnu/security/", "/lib/aarch64-linux-gnu/security/", "/usr/lib64/security/", "/lib64/security/"}

func (c breachCheck) Run(ctx context.Context, env *Env) Result {
	if !env.Sys.Root {
		// Other users' keys, schedules and programs can be read only by
		// root; saying "no signs" without them would mislead.
		return NeedsRoot()
	}
	var found []Finding
	found = append(found, changedPrograms(ctx, env)...)
	found = append(found, oddProcesses(env.Sys.FS)...)
	found = append(found, autostarts(env.Sys.FS)...)
	found = append(found, accounts(env)...)
	found = append(found, preloaded(env.Sys.FS)...)
	found = append(found, quietLogs(env)...)
	if len(found) == 0 {
		return Pass(nil)
	}
	return Fail(found...)
}

// ---- Programs that differ from their packages. ----

type verified struct {
	Count int    `json:"count"`
	First string `json:"first"`
	At    string `json:"at"`
}

// changedPrograms compares installed programs with the package database's
// checksums. Settings files are left out: changing those is normal.
func changedPrograms(ctx context.Context, env *Env) []Finding {
	v, ok := lastVerify(env)
	if !ok {
		var err error
		v, err = verifyPackages(ctx, env)
		if err != nil {
			return nil
		}
		saveVerify(env, v)
	}
	if v.Count == 0 {
		return nil
	}
	return []Finding{Found("changed-program", map[string]string{"count": strconv.Itoa(v.Count), "path": safePath(v.First)})}
}

func lastVerify(env *Env) (verified, bool) {
	if env.ReuseSlowFor <= 0 || env.Sys.State == nil {
		return verified{}, false
	}
	state, err := env.Sys.State.Load()
	if err != nil {
		return verified{}, false
	}
	var v verified
	if json.Unmarshal([]byte(state["break-in/verify"]), &v) != nil {
		return verified{}, false
	}
	at, err := time.Parse(time.RFC3339, v.At)
	if err != nil || env.Sys.Now().Sub(at) > verifyEvery {
		return verified{}, false
	}
	return v, true
}

func saveVerify(env *Env, v verified) {
	if env.Sys.State == nil {
		return
	}
	v.At = env.Sys.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	_ = env.EditState(func(state map[string]string) { state["break-in/verify"] = string(data) })
}

var errNoVerifier = errors.New("no package manager to compare with")

func verifyPackages(ctx context.Context, env *Env) (verified, error) {
	var out []byte
	var err error
	switch {
	case env.Sys.Exec.Has("dpkg"):
		out, err = env.Sys.Exec.Run(ctx, "dpkg", "--verify")
	case env.Sys.Exec.Has("rpm"):
		out, err = env.Sys.Exec.Run(ctx, "rpm", "-Va", "--nomtime", "--nosize", "--nouser", "--nogroup", "--nomode", "--nordev", "--nocaps")
	default:
		return verified{}, errNoVerifier
	}
	// Both exit non-zero when anything differs; what they printed is the answer.
	var ce *system.CommandError
	if err != nil && (!errors.As(err, &ce) || len(out) == 0) {
		return verified{}, err
	}
	return parseVerify(string(out)), nil
}

// parseVerify reads dpkg --verify and rpm -V lines: nine flags, an optional
// file type ("c" for a settings file), and the path. A 5 in the third place
// is a checksum that differs.
func parseVerify(out string) verified {
	var paths []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || len(fields[0]) != 9 || fields[0][2] != '5' {
			continue
		}
		if len(fields) >= 3 && len(fields[1]) == 1 {
			continue // c, d, g, l or r: a settings, docs or ghost file
		}
		p := fields[len(fields)-1]
		if underAny(p, programDirs) {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	v := verified{Count: len(paths)}
	if len(paths) > 0 {
		v.First = paths[0]
	}
	return v
}

// ---- Running programs. ----

// oddProcesses finds miners and programs started from temporary folders.
// Only each process's name and program path are kept; the command line is
// read only to look for a miner's words, and never sent.
func oddProcesses(fsys fs.FS) []Finding {
	entries, err := fs.ReadDir(fsys, "proc")
	if err != nil {
		return nil
	}
	var found []Finding
	seen := map[string]bool{}
	for _, e := range entries {
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		comm := strings.TrimSpace(readSmall(fsys, "proc/"+pid+"/comm", 64))
		cmdline := strings.ReplaceAll(readSmall(fsys, "proc/"+pid+"/cmdline", 4096), "\x00", " ")
		if comm == "" {
			continue
		}
		name := safeName(comm)
		if isMiner(comm, cmdline) {
			if !seen["miner/"+name] {
				seen["miner/"+name] = true
				found = append(found, Found("miner", map[string]string{"name": name, "pid": pid}))
			}
			continue
		}
		prog := programOf(fsys, pid, cmdline)
		if dir := tempDirOf(prog); dir != "" && !seen["temp/"+name] {
			seen["temp/"+name] = true
			found = append(found, Found("temp-program", map[string]string{"name": name, "pid": pid, "folder": strings.TrimSuffix(dir, "/")}))
		}
	}
	return found
}

func isMiner(comm, cmdline string) bool {
	if minerNames[strings.ToLower(comm)] {
		return true
	}
	lower := strings.ToLower(cmdline)
	for _, w := range minerWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// programOf is the process's program: its exe link when root may read it,
// else the first word of its command line.
func programOf(fsys fs.FS, pid, cmdline string) string {
	if target, err := readLink(fsys, "proc/"+pid+"/exe"); err == nil && target != "" {
		return strings.TrimSuffix(target, " (deleted)")
	}
	first, _, _ := strings.Cut(strings.TrimSpace(cmdline), " ")
	return first
}

func tempDirOf(p string) string {
	for _, d := range tempDirs {
		if strings.HasPrefix(p, d) {
			return d
		}
	}
	return ""
}

// ---- Autostart entries. ----

// autostarts reads the places a program can start itself again after a
// restart: the cron tables, systemd's units and rc.local.
func autostarts(fsys fs.FS) []Finding {
	var found []Finding
	add := func(p, kind string) {
		found = append(found, Found("autostart-"+kind, map[string]string{"path": safePath("/" + p)}))
	}
	cronTables := []struct {
		dir  string
		user bool // system tables name the user after the time
	}{
		{"etc/cron.d", true}, {"var/spool/cron/crontabs", false}, {"var/spool/cron", false},
	}
	if data, ok := readText(fsys, "etc/crontab"); ok {
		if k := cronProblem(data, true); k != "" {
			add("etc/crontab", k)
		}
	}
	for _, t := range cronTables {
		for _, name := range plainFiles(fsys, t.dir) {
			if data, ok := readText(fsys, name); ok {
				if k := cronProblem(data, t.user); k != "" {
					add(name, k)
				}
			}
		}
	}
	for _, d := range []string{"etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly"} {
		for _, name := range plainFiles(fsys, d) {
			if data, ok := readText(fsys, name); ok && fetchesAndRuns(data) {
				add(name, "download")
			}
		}
	}
	units := plainFiles(fsys, "etc/systemd/system")
	for _, home := range homes(fsys) {
		units = append(units, plainFiles(fsys, home+"/.config/systemd/user")...)
	}
	for _, name := range units {
		if !strings.HasSuffix(name, ".service") {
			continue
		}
		if data, ok := readText(fsys, name); ok {
			if k := unitProblem(data); k != "" {
				add(name, k)
			}
		}
	}
	if data, ok := readText(fsys, "etc/rc.local"); ok {
		if k := scriptProblem(data); k != "" {
			add("etc/rc.local", k)
		}
	}
	return found
}

// cronProblem says what is wrong with a cron table, if anything: a job
// started from a temporary folder ("temp"), or one that fetches and runs
// code ("download").
func cronProblem(data string, withUser bool) string {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		skip := 5
		if strings.HasPrefix(fields[0], "@") {
			skip = 1
		} else if strings.Contains(fields[0], "=") {
			continue // a setting such as MAILTO=
		}
		if withUser {
			skip++
		}
		if len(fields) <= skip {
			continue
		}
		command := strings.Join(fields[skip:], " ")
		if fetchesAndRuns(command) {
			return "download"
		}
		if tempDirOf(fields[skip]) != "" {
			return "temp"
		}
	}
	return ""
}

// unitProblem reads a systemd unit's ExecStart lines.
func unitProblem(data string) string {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(strings.TrimSpace(key), "Exec") {
			continue
		}
		value = strings.TrimLeft(strings.TrimSpace(value), "-@:+!")
		if fetchesAndRuns(value) {
			return "download"
		}
		first, _, _ := strings.Cut(value, " ")
		if tempDirOf(first) != "" {
			return "temp"
		}
	}
	return ""
}

// scriptProblem reads a shell script run at start, such as rc.local.
func scriptProblem(data string) string {
	if fetchesAndRuns(data) {
		return "download"
	}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		first, _, _ := strings.Cut(line, " ")
		if tempDirOf(first) != "" {
			return "temp"
		}
	}
	return ""
}

func fetchesAndRuns(s string) bool {
	for _, re := range downloadRun {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// ---- Accounts and login keys. ----

type account struct {
	name, home, shell string
	uid               int
}

func readAccounts(fsys fs.FS) []account {
	data, ok := readText(fsys, "etc/passwd")
	if !ok {
		return nil
	}
	var out []account
	for _, line := range strings.Split(data, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || strings.HasPrefix(f[0], "#") {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		out = append(out, account{name: f[0], uid: uid, home: f[5], shell: f[6]})
	}
	return out
}

// canLogIn is an account with a real shell.
func canLogIn(a account) bool {
	s := path.Base(a.shell)
	return a.shell != "" && s != "nologin" && s != "false" && s != "sync" && s != "halt" && s != "shutdown"
}

// accounts finds a second account with root's powers, login accounts made
// since the last scan, and login keys changed in the last 7 days.
func accounts(env *Env) []Finding {
	fsys := env.Sys.FS
	all := readAccounts(fsys)
	var found []Finding
	var logins []string
	for _, a := range all {
		if a.uid == 0 && a.name != "root" {
			found = append(found, Found("extra-root", map[string]string{"user": safeName(a.name)}))
		}
		if canLogIn(a) {
			logins = append(logins, a.name)
		}
	}
	found = append(found, newAccounts(env, logins)...)
	for _, a := range all {
		if !canLogIn(a) || !strings.HasPrefix(a.home, "/") {
			continue
		}
		for _, f := range []string{".ssh/authorized_keys", ".ssh/authorized_keys2"} {
			info, err := fs.Stat(fsys, strings.TrimPrefix(path.Join(a.home, f), "/"))
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if env.Sys.Now().Sub(info.ModTime()) < recentChange {
				found = append(found, Found("new-key", map[string]string{
					"user": safeName(a.name), "date": info.ModTime().UTC().Format("2 Jan 2006"),
				}))
				break
			}
		}
	}
	return found
}

// newAccounts compares the login accounts with those the last scan saw.
// The first scan only remembers them.
func newAccounts(env *Env, logins []string) []Finding {
	if env.Sys.State == nil {
		return nil
	}
	sort.Strings(logins)
	var found []Finding
	_ = env.EditState(func(state map[string]string) {
		before, had := state["break-in/accounts"]
		known := map[string]bool{}
		for _, n := range strings.Split(before, ",") {
			known[n] = true
		}
		// A new one is pointed out for 7 days from when it was first seen.
		since := map[string]string{}
		_ = json.Unmarshal([]byte(state["break-in/new-accounts"]), &since)
		now := env.Sys.Now().UTC()
		for _, n := range logins {
			if had && !known[n] {
				if _, ok := since[n]; !ok {
					since[n] = now.Format(time.RFC3339)
				}
			}
		}
		for n, at := range since {
			t, err := time.Parse(time.RFC3339, at)
			if err != nil || now.Sub(t) >= recentChange || !hasName(logins, n) {
				delete(since, n)
				continue
			}
			found = append(found, Found("new-account", map[string]string{"user": safeName(n), "date": t.Format("2 Jan 2006")}))
		}
		sort.Slice(found, func(i, j int) bool { return found[i].Vars["user"] < found[j].Vars["user"] })
		state["break-in/accounts"] = strings.Join(logins, ",")
		if data, err := json.Marshal(since); err == nil {
			state["break-in/new-accounts"] = string(data)
		}
	})
	return found
}

func homes(fsys fs.FS) []string {
	var out []string
	for _, a := range readAccounts(fsys) {
		if canLogIn(a) && strings.HasPrefix(a.home, "/") && a.home != "/" {
			out = append(out, strings.TrimPrefix(a.home, "/"))
		}
	}
	return out
}

// ---- A library loaded into every program. ----

func preloaded(fsys fs.FS) []Finding {
	data, ok := readText(fsys, "etc/ld.so.preload")
	if !ok {
		return nil
	}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			first, _, _ := strings.Cut(line, " ")
			return []Finding{Found("preload", map[string]string{"path": safePath(first)})}
		}
	}
	return nil
}

// ---- Logs and history turned off. ----

// quietLogs finds shell history sent to /dev/null, and a sign-in log that
// stopped while the rest of the logging goes on.
func quietLogs(env *Env) []Finding {
	fsys := env.Sys.FS
	var found []Finding
	seenHome := map[string]bool{}
	for _, a := range readAccounts(fsys) {
		if !canLogIn(a) || !strings.HasPrefix(a.home, "/") || seenHome[a.home] {
			continue
		}
		seenHome[a.home] = true
		name := strings.TrimPrefix(path.Join(a.home, ".bash_history"), "/")
		info, err := lstat(fsys, name)
		if err != nil || info.Mode()&fs.ModeSymlink == 0 {
			continue
		}
		if target, err := readLink(fsys, name); err == nil && target == "/dev/null" {
			found = append(found, Found("history-off", map[string]string{"user": safeName(a.name)}))
		}
	}
	now := env.Sys.Now()
	for _, pair := range [][2]string{{"var/log/auth.log", "var/log/syslog"}, {"var/log/secure", "var/log/messages"}} {
		auth, err := fs.Stat(fsys, pair[0])
		if err != nil || auth.Size() != 0 || now.Sub(auth.ModTime()) < 24*time.Hour {
			continue
		}
		rest, err := fs.Stat(fsys, pair[1])
		if err != nil || now.Sub(rest.ModTime()) > time.Hour {
			continue
		}
		// A quiet server nobody signs in to keeps an empty auth log after
		// its weekly rotation: only sign-ins recorded since (wtmp) while the
		// auth log stayed empty say it was wiped or stopped.
		wtmp, err := fs.Stat(fsys, "var/log/wtmp")
		if err != nil || !wtmp.ModTime().After(auth.ModTime().Add(time.Hour)) {
			continue
		}
		found = append(found, Found("auth-log-empty", map[string]string{
			"path": "/" + pair[0], "date": auth.ModTime().UTC().Format("2 Jan 2006"),
		}))
	}
	return found
}

// ---- Small helpers. ----

func readSmall(fsys fs.FS, name string, max int) string {
	f, err := fsys.Open(name)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, max)
	n, _ := f.Read(buf)
	return string(buf[:n])
}

// readText reads a settings file, never through a link and at most readCap.
func readText(fsys fs.FS, name string) (string, bool) {
	data, err := readUserFile(fsys, name)
	if err != nil {
		return "", false
	}
	return string(data), true
}

// plainFiles lists the plain files in a folder, by path from the root.
func plainFiles(fsys fs.FS, dir string) []string {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			out = append(out, dir+"/"+e.Name())
		}
	}
	return out
}

func readLink(fsys fs.FS, name string) (string, error) {
	if l, ok := fsys.(fs.ReadLinkFS); ok {
		return l.ReadLink(name)
	}
	return "", errors.ErrUnsupported
}

func lstat(fsys fs.FS, name string) (fs.FileInfo, error) {
	if l, ok := fsys.(fs.ReadLinkFS); ok {
		return l.Lstat(name)
	}
	return nil, errors.ErrUnsupported
}

func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

func hasName(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// safeName keeps a process or account name short and printable, since it
// comes from whoever started the process.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 32 {
			break
		}
		if r >= 0x20 && r < 0x7f && r != '{' && r != '}' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "?"
	}
	return b.String()
}

// safePath is a path from the server's own files, kept printable and short.
func safePath(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 200 {
			break
		}
		if r > 0x20 && r < 0x7f && r != '{' && r != '}' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
