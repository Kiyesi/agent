package checks

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/config"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// now is the fixed time every test runs at.
var now = time.Date(2026, 10, 8, 15, 0, 0, 0, time.UTC)

// fakeRunner answers allowlisted commands from a table.
type fakeRunner struct {
	has  map[string]bool
	outs map[string]string // "name arg arg" -> stdout
	errs map[string]error
	ran  []string
}

func (f *fakeRunner) Has(name string) bool { return f.has[name] }

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	f.ran = append(f.ran, key)
	if err, ok := f.errs[key]; ok {
		return []byte(f.outs[key]), err
	}
	for k, v := range f.outs {
		if k == key || (strings.HasSuffix(k, "*") && strings.HasPrefix(key, strings.TrimSuffix(k, "*"))) {
			return []byte(v), nil
		}
	}
	return nil, &system.CommandError{Name: name, Code: 1}
}

type fakeDocker struct {
	cs    []system.Container
	dies  map[string]int
	usage system.DiskUsage
	err   error
}

func (f fakeDocker) DiskUsage(context.Context) (system.DiskUsage, error) { return f.usage, f.err }

func (f fakeDocker) Containers(context.Context) ([]system.Container, error) { return f.cs, f.err }
func (f fakeDocker) Logs(context.Context, string, time.Time) ([]system.LogLine, error) {
	return nil, nil
}

func (f fakeDocker) Dies(context.Context, time.Time, time.Time) (map[string]int, error) {
	return f.dies, f.err
}

// testEnv builds an Env from saved files. Options change the defaults:
// a root scan on Ubuntu with no Docker and nothing installed.
type testEnv struct {
	fs     fstest.MapFS
	runner *fakeRunner
	docker system.Docker
	usage  map[string]system.Usage
	root   bool
	cfg    config.Config
	state  *system.MemState
}

// newTestEnv is a server whose team is in Nigeria, the first country with
// a rule pack; tests of a team with no home country clear it.
func newTestEnv() *testEnv {
	cfg := config.Default()
	cfg.HomeCountry = "NG"
	return &testEnv{
		fs:     fstest.MapFS{},
		runner: &fakeRunner{has: map[string]bool{}, outs: map[string]string{}, errs: map[string]error{}},
		usage:  map[string]system.Usage{},
		root:   true,
		cfg:    cfg,
		state:  &system.MemState{M: map[string]string{}},
	}
}

func (t *testEnv) file(name string, data string) *testEnv {
	t.fs[name] = &fstest.MapFile{Data: []byte(data), Mode: 0o644}
	return t
}

func (t *testEnv) saved(tb testing.TB, name, testdata string) *testEnv {
	tb.Helper()
	data, err := os.ReadFile("testdata/" + testdata)
	if err != nil {
		tb.Fatal(err)
	}
	return t.file(name, string(data))
}

func (t *testEnv) command(cmd, out string) *testEnv {
	name, _, _ := strings.Cut(cmd, " ")
	t.runner.has[name] = true
	t.runner.outs[cmd] = out
	return t
}

func (t *testEnv) env() *Env {
	sys := &system.System{
		FS:     t.fs,
		Exec:   t.runner,
		Docker: t.docker,
		Statfs: func(p string) (system.Usage, error) {
			if u, ok := t.usage[p]; ok {
				return u, nil
			}
			return system.Usage{}, errors.New("not mounted")
		},
		State:    t.state,
		Now:      func() time.Time { return now },
		Root:     t.root,
		OS:       system.OSInfo{Name: "Ubuntu 22.04", Tested: true},
		Hostname: "checkout-api-prod",
	}
	return NewEnv(sys, t.cfg)
}

func run(tb testing.TB, c Check, t *testEnv) Result {
	tb.Helper()
	return c.Run(context.Background(), t.env())
}

// wantStatus fails the test unless r has the status and finding keys given.
func wantStatus(tb testing.TB, r Result, status Status, keys ...string) {
	tb.Helper()
	if r.Status != status {
		tb.Fatalf("status = %s (skip %q %v), want %s; findings %+v", r.Status, r.SkipKey, r.SkipVars, status, r.Findings)
	}
	if len(r.Findings) != len(keys) {
		tb.Fatalf("findings = %+v, want keys %v", r.Findings, keys)
	}
	for i, k := range keys {
		if r.Findings[i].Key != k {
			tb.Errorf("finding %d key = %q, want %q", i, r.Findings[i].Key, k)
		}
	}
}
