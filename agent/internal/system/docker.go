package system

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Docker reads containers. Every call is an HTTP GET: the scan never
// changes a container.
type Docker interface {
	Containers(ctx context.Context) ([]Container, error)
	// Dies counts, per container id, the times each container stopped
	// between since and until.
	Dies(ctx context.Context, since, until time.Time) (map[string]int, error)
	// Logs returns a container's output lines written after since, oldest
	// first, each with the time Docker recorded it.
	Logs(ctx context.Context, id string, since time.Time) ([]LogLine, error)
}

// LogLine is one line a container wrote.
type LogLine struct {
	At   time.Time
	Text string
}

// Container is what the checks need from docker inspect.
type Container struct {
	ID             string
	Name           string
	Image          string
	Status         string // running, exited, restarting, ...
	ExitCode       int
	Health         string // healthy, unhealthy, starting, or empty
	RestartPolicy  string
	Privileged     bool
	User           string
	Mounts         []string // sources and destinations
	Ports          []PublishedPort
	ComposeService string
	// Pid is the container's main process on the host, or 0 when stopped.
	Pid int
	// ImageID is the image the container runs, by digest; it changes on a deploy.
	ImageID string
	// StartedAt is when the container last started, as Docker writes it.
	StartedAt    string
	RestartCount int
	// OOMKilled is true when the container's last stop was for memory.
	OOMKilled bool
	// MemoryLimit is the container's memory limit in bytes, 0 when it has none.
	MemoryLimit int64
	// LogDriver and LogMaxSize are the container's own log settings.
	LogDriver  string
	LogMaxSize string
	// Env is the container's environment, KEY=value, as Compose gave it from
	// its env files. Read for database and service addresses only; values
	// stay in memory and never reach a report.
	Env []string
}

// PublishedPort is a container port published on the host.
type PublishedPort struct {
	HostIP   string
	HostPort int
	Proto    string
}

// DockerSocket is where the Docker API listens.
const DockerSocket = "/var/run/docker.sock"

// NewDocker returns a client for the socket, or nil when Docker is not installed.
func NewDocker(socket string) Docker {
	if _, err := os.Stat(socket); err != nil {
		return nil
	}
	return &dockerClient{http: &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}},
	}}
}

type dockerClient struct{ http *http.Client }

func (c *dockerClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, syscall.EACCES) || errors.Is(err, fs.ErrPermission) || strings.Contains(err.Error(), "permission denied") {
			return ErrNeedsRoot
		}
		return fmt.Errorf("cannot reach Docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("docker answered %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *dockerClient) Containers(ctx context.Context) ([]Container, error) {
	var list []struct {
		ID string `json:"Id"`
	}
	if err := c.get(ctx, "/containers/json?all=1", &list); err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(list))
	for _, item := range list {
		var in inspect
		if err := c.get(ctx, "/containers/"+url.PathEscape(item.ID)+"/json", &in); err != nil {
			return nil, err
		}
		out = append(out, in.container())
	}
	return out, nil
}

type inspect struct {
	ID           string `json:"Id"`
	Name         string `json:"Name"`
	ImageID      string `json:"Image"`
	RestartCount int    `json:"RestartCount"`
	State        struct {
		Status    string `json:"Status"`
		ExitCode  int    `json:"ExitCode"`
		Pid       int    `json:"Pid"`
		StartedAt string `json:"StartedAt"`
		OOMKilled bool   `json:"OOMKilled"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		User   string            `json:"User"`
		Env    []string          `json:"Env"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		Privileged bool  `json:"Privileged"`
		Memory     int64 `json:"Memory"`
		LogConfig  struct {
			Type   string            `json:"Type"`
			Config map[string]string `json:"Config"`
		} `json:"LogConfig"`
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

func (in inspect) container() Container {
	c := Container{
		ID:             in.ID,
		Name:           strings.TrimPrefix(in.Name, "/"),
		Image:          in.Config.Image,
		Status:         in.State.Status,
		ExitCode:       in.State.ExitCode,
		RestartPolicy:  in.HostConfig.RestartPolicy.Name,
		Privileged:     in.HostConfig.Privileged,
		MemoryLimit:    in.HostConfig.Memory,
		Env:            in.Config.Env,
		LogDriver:      in.HostConfig.LogConfig.Type,
		LogMaxSize:     in.HostConfig.LogConfig.Config["max-size"],
		User:           in.Config.User,
		ComposeService: in.Config.Labels["com.docker.compose.service"],
		Pid:            in.State.Pid,
		ImageID:        in.ImageID,
		StartedAt:      in.State.StartedAt,
		RestartCount:   in.RestartCount,
		OOMKilled:      in.State.OOMKilled,
	}
	if in.State.Health != nil {
		c.Health = in.State.Health.Status
	}
	for _, m := range in.Mounts {
		c.Mounts = append(c.Mounts, m.Source, m.Destination)
	}
	for key, bindings := range in.NetworkSettings.Ports {
		_, proto, _ := strings.Cut(key, "/")
		for _, b := range bindings {
			port, err := strconv.Atoi(b.HostPort)
			if err != nil {
				continue
			}
			c.Ports = append(c.Ports, PublishedPort{HostIP: b.HostIP, HostPort: port, Proto: proto})
		}
	}
	return c
}

func (c *dockerClient) Dies(ctx context.Context, since, until time.Time) (map[string]int, error) {
	filters := `{"type":["container"],"event":["die"]}`
	path := fmt.Sprintf("/events?since=%d&until=%d&filters=%s", since.Unix(), until.Unix(), url.QueryEscape(filters))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			return nil, ErrNeedsRoot
		}
		return nil, fmt.Errorf("cannot reach Docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker answered %d to the events request", resp.StatusCode)
	}
	counts := map[string]int{}
	dec := json.NewDecoder(resp.Body)
	for {
		var ev struct {
			Actor struct {
				ID string `json:"ID"`
			} `json:"Actor"`
		}
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) {
				return counts, nil
			}
			return counts, err
		}
		counts[ev.Actor.ID]++
	}
}

// Logs reads a container's output since a time. Without a terminal, Docker
// sends each line in a frame: 8 bytes of header (stream, then the length),
// then the line. With timestamps on, each line starts with the time.
func (c *dockerClient) Logs(ctx context.Context, id string, since time.Time) ([]LogLine, error) {
	path := fmt.Sprintf("/containers/%s/logs?stdout=1&stderr=1&timestamps=1&since=%d", url.PathEscape(id), since.Unix())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			return nil, ErrNeedsRoot
		}
		return nil, fmt.Errorf("cannot reach Docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker answered %d to the logs request", resp.StatusCode)
	}
	// At most 8 MB a minute from one container; the rest waits for next time.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	return parseLogStream(body, since), nil
}

// parseLogStream reads Docker's log stream, framed or plain, and keeps the
// lines written after since.
func parseLogStream(body []byte, since time.Time) []LogLine {
	var raw []string
	framed := len(body) >= 8 && (body[0] == 1 || body[0] == 2) && body[1] == 0 && body[2] == 0 && body[3] == 0
	if framed {
		for len(body) >= 8 {
			n := int(body[4])<<24 | int(body[5])<<16 | int(body[6])<<8 | int(body[7])
			if n < 0 || 8+n > len(body) {
				break
			}
			raw = append(raw, strings.Split(strings.TrimRight(string(body[8:8+n]), "\n"), "\n")...)
			body = body[8+n:]
		}
	} else {
		raw = strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	}
	out := make([]LogLine, 0, len(raw))
	for _, line := range raw {
		stamp, text, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil || !at.After(since) {
			continue
		}
		out = append(out, LogLine{At: at, Text: strings.TrimRight(text, "\r")})
	}
	return out
}

// FilterDocker reads only the containers the settings allow: those whose
// name matches an include pattern (when there are any) and no exclude
// pattern. Every reader, the scan's checks and the agent's figures, logs
// and events, goes through it, so a left-out container is never seen.
func FilterDocker(d Docker, include, exclude []string) Docker {
	if d == nil || (len(include) == 0 && len(exclude) == 0) {
		return d
	}
	return filteredDocker{inner: d, include: include, exclude: exclude}
}

type filteredDocker struct {
	inner            Docker
	include, exclude []string
}

func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

func (f filteredDocker) allowed(name string) bool {
	name = strings.TrimPrefix(name, "/")
	if len(f.include) > 0 && !matchAny(f.include, name) {
		return false
	}
	return !matchAny(f.exclude, name)
}

func (f filteredDocker) Containers(ctx context.Context) ([]Container, error) {
	all, err := f.inner.Containers(ctx)
	var out []Container
	for _, c := range all {
		if f.allowed(c.Name) {
			out = append(out, c)
		}
	}
	return out, err
}

func (f filteredDocker) Dies(ctx context.Context, since, until time.Time) (map[string]int, error) {
	dies, err := f.inner.Dies(ctx, since, until)
	if err != nil || len(dies) == 0 {
		return dies, err
	}
	list, lerr := f.Containers(ctx)
	if lerr != nil {
		return nil, lerr
	}
	keep := map[string]bool{}
	for _, c := range list {
		keep[c.ID] = true
	}
	out := map[string]int{}
	for id, n := range dies {
		if keep[id] {
			out[id] = n
		}
	}
	return out, nil
}

func (f filteredDocker) Logs(ctx context.Context, id string, since time.Time) ([]LogLine, error) {
	return f.inner.Logs(ctx, id, since)
}
