package checks

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// Listener is a TCP port listening on a public address.
type Listener struct {
	Port int
	Addr string
}

// readListeners reads proc/net/tcp and proc/net/tcp6 and keeps the
// listening sockets on public addresses, one per port.
func readListeners(fsys fs.FS) ([]Listener, error) {
	byPort := map[int]Listener{}
	read := 0
	for _, name := range []string{"proc/net/tcp", "proc/net/tcp6"} {
		data, err := fs.ReadFile(fsys, name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		read++
		ls, err := parseProcNet(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		for _, l := range ls {
			if _, ok := byPort[l.Port]; !ok {
				byPort[l.Port] = l
			}
		}
	}
	if read == 0 {
		return nil, errors.New("cannot read /proc/net/tcp")
	}
	out := make([]Listener, 0, len(byPort))
	for _, l := range byPort {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out, nil
}

// parseProcNet keeps sockets in the LISTEN state (0A) on public addresses.
func parseProcNet(data []byte) ([]Listener, error) {
	var out []Listener
	sc := bufio.NewScanner(bytes.NewReader(data))
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[3] != "0A" {
			continue
		}
		hexIP, hexPort, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil {
			return nil, err
		}
		ip, err := procIP(hexIP)
		if err != nil {
			return nil, err
		}
		if publicIP(ip) {
			out = append(out, Listener{Port: int(port), Addr: ip.String()})
		}
	}
	return out, sc.Err()
}

// procIP decodes /proc/net addresses, stored as 32-bit words in host
// (little-endian) byte order.
func procIP(h string) (net.IP, error) {
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return nil, fmt.Errorf("bad address %q", h)
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.IP(b), nil
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// publicIP is true for "every address" (0.0.0.0 and ::) and for addresses
// on the public internet. Loopback, private, link-local and shared ranges
// (such as Tailscale's 100.64.0.0/10) are not public.
func publicIP(ip net.IP) bool {
	if ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil && cgnat.Contains(ip4) {
		return false
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast())
}

// publicHostIP reports whether Docker published a port on a public address.
// An empty HostIp means every address.
func publicHostIP(s string) bool {
	if s == "" {
		return true
	}
	ip := net.ParseIP(s)
	return ip != nil && publicIP(ip)
}

// publishedPublic lists the ports running containers publish on public
// addresses, one entry per port and container.
type published struct {
	Port      int
	Container system.Container
}

func publishedPublic(cs []system.Container) []published {
	var out []published
	for _, c := range cs {
		if c.Status != "running" && c.Status != "restarting" {
			continue
		}
		seen := map[int]bool{}
		for _, p := range c.Ports {
			if p.Proto != "tcp" || !publicHostIP(p.HostIP) || seen[p.HostPort] {
				continue
			}
			seen[p.HostPort] = true
			out = append(out, published{Port: p.HostPort, Container: c})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}
