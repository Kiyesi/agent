package system

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// A fake Docker API on a unix socket, answering like Docker 29.
func TestDockerClientReadsContainers(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("unix sockets not available:", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"Id":"abc"}]`))
	})
	mux.HandleFunc("GET /containers/abc/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Id":"abc","Name":"/redis","State":{"Status":"running","ExitCode":0,"Health":{"Status":"unhealthy"}},
		"Config":{"Image":"redis:7.0","User":"","Labels":{"com.docker.compose.service":"redis"}},
		"HostConfig":{"Privileged":true,"Memory":268435456,"RestartPolicy":{"Name":"unless-stopped"},"LogConfig":{"Type":"json-file","Config":{"max-size":"20m"}}},
		"Mounts":[{"Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock"}],
		"NetworkSettings":{"Ports":{"6379/tcp":[{"HostIp":"0.0.0.0","HostPort":"6379"},{"HostIp":"::","HostPort":"6379"}]}}}`))
	})
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, _ *http.Request) {
		enc := json.NewEncoder(w)
		for range 3 {
			_ = enc.Encode(map[string]any{"Actor": map[string]string{"ID": "abc"}})
		}
	})
	// Two unused images, one sharing a layer with a used one; build cache
	// in use is not counted.
	mux.HandleFunc("GET /system/df", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Images":[{"Size":500,"SharedSize":0,"Containers":1},{"Size":300,"SharedSize":100,"Containers":0},{"Size":200,"SharedSize":-1,"Containers":0}],
		"BuildCache":[{"Size":1000,"InUse":false,"Shared":false},{"Size":50,"InUse":true,"Shared":false},{"Size":70,"InUse":false,"Shared":true}]}`))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	d := NewDocker(sock)
	if d == nil {
		t.Fatal("NewDocker returned nil for an existing socket")
	}
	cs, err := d.Containers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 {
		t.Fatalf("got %d containers", len(cs))
	}
	c := cs[0]
	if c.Name != "redis" || c.Health != "unhealthy" || !c.Privileged || c.ComposeService != "redis" || len(c.Ports) != 2 || c.Mounts[0] != "/var/run/docker.sock" ||
		c.MemoryLimit != 268435456 || c.LogDriver != "json-file" || c.LogMaxSize != "20m" {
		t.Errorf("unexpected container: %+v", c)
	}
	dies, err := d.Dies(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if dies["abc"] != 3 {
		t.Errorf("dies = %v", dies)
	}
	u, err := d.DiskUsage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if u != (DiskUsage{UnusedImages: 400, UnusedImageCount: 2, BuildCache: 1000}) || u.Reclaimable() != 1400 {
		t.Errorf("disk usage = %+v", u)
	}
}

func TestNewDockerWithoutSocket(t *testing.T) {
	if NewDocker(filepath.Join(t.TempDir(), "none.sock")) != nil {
		t.Error("expected nil when Docker is not installed")
	}
}
