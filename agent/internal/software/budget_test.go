package software

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// A busy small server, as a 1 GB machine with one CPU might carry: large
// lockfiles, thousands of installed packages, many containers. The agent
// reads all of it under its own memory limit, and must stay within budget.
func TestTheAgentStaysWithinItsBudgetOnABusyServer(t *testing.T) {
	if testing.Short() {
		t.Skip("reads a large made-up server")
	}
	fsys := fstest.MapFS{"etc/os-release": {Data: []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n")}}
	lock := func(n, size int) []byte {
		var b strings.Builder
		b.WriteString(`{"lockfileVersion":3,"packages":{`)
		for i := 0; b.Len() < size; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `"node_modules/pkg-%d-%d":{"version":"1.%d.0","resolved":"https://registry.npmjs.org/p/-/p.tgz","integrity":"sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}`, n, i, i)
		}
		b.WriteString("}}")
		return []byte(b.String())
	}
	// Twelve projects with lockfiles just under the 8 MB cap.
	for n := 0; n < 12; n++ {
		fsys[fmt.Sprintf("srv/app%d/package-lock.json", n)] = &fstest.MapFile{Data: lock(n, 7<<20)}
	}
	// Twenty containers, each with an app of 600 packages and no lockfile.
	for c := 0; c < 20; c++ {
		for i := 0; i < 600; i++ {
			fsys[fmt.Sprintf("var/lib/docker/overlay2/c%d/merged/app/node_modules/m%d/package.json", c, i)] =
				&fstest.MapFile{Data: []byte(fmt.Sprintf(`{"name":"m%d","version":"2.%d.0"}`, i, i))}
		}
	}
	// Python with 2,000 installed distributions.
	for i := 0; i < 2000; i++ {
		fsys[fmt.Sprintf("usr/lib/python3.12/site-packages/dist%d-1.%d.dist-info/METADATA", i, i)] = &fstest.MapFile{Data: []byte("x")}
	}
	old := debug.SetMemoryLimit(150 << 20)
	defer debug.SetMemoryLimit(old)

	stop := make(chan struct{})
	peak := uint64(0)
	go func() {
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			default:
			}
			runtime.ReadMemStats(&m)
			peak = max(peak, m.HeapInuse)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	// The made-up server itself takes room in this test; measured on top of it.
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	start := time.Now()
	sys := &system.System{FS: fsys}
	for range 3 {
		_ = Read(context.Background(), sys)
		r := ReadLanguages(context.Background(), sys)
		if len(r.Sources) == 0 {
			t.Fatal("read nothing")
		}
	}
	took := time.Since(start)
	close(stop)
	used := (peak - min(peak, base.HeapInuse)) >> 20
	t.Logf("peak %d MB above the made-up server, %s for three reads", used, took.Round(time.Millisecond))
	if used > 100 {
		t.Errorf("the agent used %d MB reading a busy server: over its budget", used)
	}
	if took > 3*LangBudget {
		t.Errorf("three reads took %s", took)
	}
}
