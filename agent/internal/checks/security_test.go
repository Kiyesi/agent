package checks

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// procTCP builds /proc/net/tcp with LISTEN sockets on 0.0.0.0 for ports.
func procTCP(ports ...int) string {
	var b strings.Builder
	b.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	for i, p := range ports {
		b.WriteString("   " + itoa(i) + ": 00000000:" + hex4(p) + " 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0\n")
	}
	return b.String()
}

func itoa(i int) string { return string(rune('0' + i)) }

func hex4(p int) string {
	const digits = "0123456789ABCDEF"
	return string([]byte{digits[p>>12&15], digits[p>>8&15], digits[p>>4&15], digits[p&15]})
}

func redis(hostIP string) system.Container {
	return system.Container{ID: "r", Name: "checkout-redis-1", Image: "redis:7.0", Status: "running", User: "redis",
		ComposeService: "redis", Ports: []system.PublishedPort{{HostIP: hostIP, HostPort: 6379, Proto: "tcp"}}}
}

func TestOpenPorts(t *testing.T) {
	e := newTestEnv().file("proc/net/tcp", procTCP(22, 80, 443, 6379, 8080))
	r := run(t, openPortsCheck{}, e)
	// 6379 is a database: the exposed-databases check reports it.
	wantStatus(t, r, StatusFail, "open")
	if r.Findings[0].Vars["port"] != "8080" {
		t.Errorf("vars = %v", r.Findings[0].Vars)
	}
	e.cfg.Ports.Allowed = append(e.cfg.Ports.Allowed, 8080)
	ok := run(t, openPortsCheck{}, e)
	wantStatus(t, ok, StatusPass)
	if ok.Vars["ports"] != "22, 80, 443, 6379, 8080" {
		t.Errorf("ports = %q", ok.Vars["ports"])
	}
}

func TestExposedDatabaseThroughDockerIgnoresUFW(t *testing.T) {
	e := newTestEnv().file("proc/net/tcp", procTCP(22, 6379)).file("etc/ufw/ufw.conf", "ENABLED=yes\n").
		command("ufw status verbose", mustRead(t, "ufw-status-verbose.txt"))
	e.docker = fakeDocker{cs: []system.Container{redis("0.0.0.0")}}
	r := run(t, exposedDatabasesCheck{}, e)
	wantStatus(t, r, StatusFail, "open")
	f := r.Findings[0]
	if f.Vars["database"] != "Redis" || f.Vars["service"] != "redis" || f.Variant != "" {
		t.Errorf("finding = %+v", f)
	}
	// Published on 127.0.0.1 only: safe.
	safe := newTestEnv().file("proc/net/tcp", procTCP(22))
	safe.docker = fakeDocker{cs: []system.Container{redis("127.0.0.1")}}
	wantStatus(t, run(t, exposedDatabasesCheck{}, safe), StatusPass)
}

func TestExposedDatabaseOnTheHost(t *testing.T) {
	// PostgreSQL listens everywhere and no firewall is on.
	open := newTestEnv().file("proc/net/tcp", procTCP(22, 5432))
	r := run(t, exposedDatabasesCheck{}, open)
	wantStatus(t, r, StatusFail, "open")
	if r.Findings[0].Variant != "postgresql" {
		t.Errorf("variant = %q", r.Findings[0].Variant)
	}
	// ufw is on and does not allow 5432: blocked on this server.
	blocked := newTestEnv().file("proc/net/tcp", procTCP(22, 5432)).file("etc/ufw/ufw.conf", "ENABLED=yes\n").
		command("ufw status verbose", mustRead(t, "ufw-status-verbose.txt"))
	wantStatus(t, run(t, exposedDatabasesCheck{}, blocked), StatusPass)
	// ufw is on but its rules need root: unknown, so skipped, never passed.
	nr := newTestEnv().file("proc/net/tcp", procTCP(22, 5432)).file("etc/ufw/ufw.conf", "ENABLED=yes\n")
	nr.root = false
	if r := run(t, exposedDatabasesCheck{}, nr); r.SkipKey != "needs-root" {
		t.Errorf("want needs-root, got %+v", r)
	}
}

func TestDockerFirewall(t *testing.T) {
	app := system.Container{ID: "a", Name: "app", Status: "running", ComposeService: "app",
		Ports: []system.PublishedPort{{HostIP: "0.0.0.0", HostPort: 3000, Proto: "tcp"}, {HostIP: "0.0.0.0", HostPort: 443, Proto: "tcp"}}}
	e := newTestEnv().file("etc/ufw/ufw.conf", "ENABLED=yes\n").command("ufw status verbose", mustRead(t, "ufw-status-verbose.txt"))
	e.docker = fakeDocker{cs: []system.Container{app}}
	r := run(t, dockerFirewallCheck{}, e)
	wantStatus(t, r, StatusFail, "bypass")
	if r.Findings[0].Vars["port"] != "3000" {
		t.Errorf("vars = %v", r.Findings[0].Vars)
	}
	noUFW := newTestEnv()
	noUFW.docker = fakeDocker{cs: []system.Container{app}}
	wantStatus(t, run(t, dockerFirewallCheck{}, noUFW), StatusPass)
}

// ufw allowing only SSH, with Caddy publishing 80 and 443: those are a
// website's ports, so they are worth a look (info, no points) and never
// get "bind it to 127.0.0.1", which would take the site offline. Another
// port still costs points.
func TestDockerFirewallWebPortsAreInfo(t *testing.T) {
	sshOnly := "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n"
	caddy := system.Container{ID: "c", Name: "appstack-caddy-1", Status: "running", ComposeService: "caddy",
		Ports: []system.PublishedPort{{HostIP: "0.0.0.0", HostPort: 80, Proto: "tcp"}, {HostIP: "0.0.0.0", HostPort: 443, Proto: "tcp"}, {HostIP: "0.0.0.0", HostPort: 8080, Proto: "tcp"}}}
	e := newTestEnv().file("etc/ufw/ufw.conf", "ENABLED=yes\n").command("ufw status verbose", sshOnly)
	e.docker = fakeDocker{cs: []system.Container{caddy}}
	r := run(t, dockerFirewallCheck{}, e)
	wantStatus(t, r, StatusFail, "web", "web", "bypass")
	if r.Findings[0].Vars["port"] != "80" || r.Findings[1].Vars["port"] != "443" || r.Findings[2].Vars["port"] != "8080" || r.Findings[0].Vars["service"] != "caddy" {
		t.Errorf("findings = %+v", r.Findings)
	}
}

func TestSSH(t *testing.T) {
	ubuntu := func() *testEnv {
		return newTestEnv().saved(t, "etc/ssh/sshd_config", "sshd_config-ubuntu")
	}
	// Ubuntu's defaults with cloud-init turning passwords on.
	e := ubuntu().file("etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
	e.root = false
	wantStatus(t, run(t, sshCheck{}, e), StatusFail, "password")
	// The fix from the pack, applied.
	fixed := ubuntu().file("etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n").
		file("etc/ssh/sshd_config.d/00-kiyesi-no-password.conf", "PasswordAuthentication no\n")
	fixed.root = false
	wantStatus(t, run(t, sshCheck{}, fixed), StatusPass)
	// As root, sshd -T is the source of truth.
	root := ubuntu().command("sshd -T", "port 22\npermitrootlogin yes\npasswordauthentication no\nkbdinteractiveauthentication no\nusepam yes\n")
	wantStatus(t, run(t, sshCheck{}, root), StatusFail, "root")
	if r := run(t, sshCheck{}, newTestEnv()); !r.None {
		t.Errorf("no SSH server: %+v", r)
	}
}

func TestFirewall(t *testing.T) {
	wantStatus(t, run(t, firewallCheck{}, newTestEnv().file("etc/ufw/ufw.conf", "ENABLED=yes\n")), StatusPass)
	off := newTestEnv().file("etc/ufw/ufw.conf", "ENABLED=no\n").command("iptables -S INPUT", "-P INPUT ACCEPT\n")
	wantStatus(t, run(t, firewallCheck{}, off), StatusFail, "off")
	if r := run(t, firewallCheck{}, off); r.Findings[0].Vars["ssh_port"] != "22" {
		t.Errorf("no SSH settings: want port 22, got %+v", r.Findings[0].Vars)
	}
	// The printed fix opens the port sshd really listens on, so it never locks anyone out.
	moved := newTestEnv().file("etc/ufw/ufw.conf", "ENABLED=no\n").command("iptables -S INPUT", "-P INPUT ACCEPT\n").
		command("sshd -T", "port 2222\nport 22\npasswordauthentication no\n")
	if r := run(t, firewallCheck{}, moved); r.Status != StatusFail || r.Findings[0].Vars["ssh_port"] != "2222,22" {
		t.Errorf("sshd on 2222 and 22: %+v", r)
	}
	unrooted := newTestEnv().file("etc/ufw/ufw.conf", "ENABLED=no\n").command("iptables -S INPUT", "-P INPUT ACCEPT\n").
		file("etc/ssh/sshd_config", "Port 2200\nPasswordAuthentication no\n")
	if r := run(t, firewallCheck{}, unrooted); r.Status != StatusFail || r.Findings[0].Vars["ssh_port"] != "2200" {
		t.Errorf("sshd_config with Port 2200: %+v", r)
	}
	nft := newTestEnv().command("nft list ruleset", "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n")
	if r := run(t, firewallCheck{}, nft); r.Status != StatusPass || r.Vars["firewall"] != "nftables" {
		t.Errorf("nftables: %+v", r)
	}
	nr := newTestEnv()
	nr.root = false
	if r := run(t, firewallCheck{}, nr); r.SkipKey != "needs-root" {
		t.Errorf("want needs-root, got %+v", r)
	}
}

func TestLoginProtection(t *testing.T) {
	pw := func() *testEnv {
		return newTestEnv().saved(t, "etc/ssh/sshd_config", "sshd_config-ubuntu").
			file("etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
	}
	e := pw()
	e.root = false
	wantStatus(t, run(t, loginProtectionCheck{}, e), StatusFail, "missing")
	guarded := pw().command("systemctl is-active fail2ban", "active\n")
	guarded.root = false
	if r := run(t, loginProtectionCheck{}, guarded); r.Status != StatusPass || r.Vars["protection"] != "fail2ban is running" {
		t.Errorf("fail2ban running: %+v", r)
	}
}

func TestRiskyContainers(t *testing.T) {
	e := newTestEnv()
	e.docker = fakeDocker{cs: []system.Container{
		{Name: "agent", Status: "running", User: "1000", Mounts: []string{"/var/run/docker.sock", "/var/run/docker.sock"}},
		{Name: "vpn", Status: "running", User: "nobody", Privileged: true},
		{Name: "api", Status: "running", User: ""},
		{Name: "old", Status: "exited", Privileged: true},
	}}
	wantStatus(t, run(t, riskyContainersCheck{}, e), StatusFail, "docker-socket", "privileged", "root")
}

// Valkey's image starts as root and switches to its own user: the running
// process decides, not the configured user.
func TestRiskyContainersReadsTheRealUser(t *testing.T) {
	e := newTestEnv().
		file("proc/4242/status", "Name:\tvalkey-server\nUid:\t999\t999\t999\t999\nGid:\t999\t999\t999\t999\n").
		file("proc/4343/status", "Name:\tcaddy\nUid:\t0\t0\t0\t0\n")
	e.docker = fakeDocker{cs: []system.Container{
		{Name: "valkey", Status: "running", User: "", Pid: 4242},
		{Name: "caddy", Status: "running", User: "", Pid: 4343},
	}}
	r := run(t, riskyContainersCheck{}, e)
	wantStatus(t, r, StatusFail, "root")
	if r.Findings[0].Vars["name"] != "caddy" {
		t.Errorf("flagged %v, want only caddy", r.Findings[0].Vars)
	}
}

func TestSecretsNeverKeepTheValue(t *testing.T) {
	// A made-up key, built at runtime so secret scanners do not flag the test.
	secret := "sk_" + "live_" + "9f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e"
	e := newTestEnv()
	e.fs["srv/checkout/.env"] = &fstest.MapFile{Data: []byte("NODE_ENV=production\nPAYSTACK_SECRET_KEY=" + secret + "\n"), Mode: 0o644}
	e.fs["srv/checkout/.env.example"] = &fstest.MapFile{Data: []byte("PAYSTACK_SECRET_KEY=" + secret + "\n"), Mode: 0o644}
	e.fs["srv/checkout/docker-compose.yml"] = &fstest.MapFile{Data: []byte("services:\n  db:\n    environment:\n      POSTGRES_USER: app\n      POSTGRES_PASSWORD: hunter2hunter2\n  api:\n    environment:\n      - API_TOKEN=${API_TOKEN}\n"), Mode: 0o600}
	e.fs["root/.bash_history"] = &fstest.MapFile{Data: []byte("ls\nexport STRIPE=" + secret + "\n"), Mode: 0o600}
	e.fs["srv/private/.env"] = &fstest.MapFile{Data: []byte("DB_PASSWORD=" + secret + "\n"), Mode: 0o600}
	e.fs["srv/app/node_modules/x/.env"] = &fstest.MapFile{Data: []byte("TOKEN=abcdefabcdef\n"), Mode: 0o644}
	r := run(t, secretsCheck{}, e)
	wantStatus(t, r, StatusFail, "in-history", "world-readable", "in-compose")
	if v := r.Findings[2].Vars; v["path"] != "/srv/checkout/docker-compose.yml" || v["line"] != "5" {
		t.Errorf("compose finding = %v", v)
	}
	if v := r.Findings[0].Vars; v["line"] != "2" {
		t.Errorf("history finding = %v", v)
	}
	for _, f := range r.Findings {
		for _, v := range f.Vars {
			if strings.Contains(v, secret) || strings.Contains(v, "hunter2") {
				t.Fatalf("a secret value leaked into a finding: %+v", f)
			}
		}
	}
}

// A secret file set readable by all is a door open only when every folder
// above it lets other users through. Behind /root (700) it is a note.
func TestSecretFileBehindAClosedFolderIsANote(t *testing.T) {
	secret := "sk_" + "live_" + "9f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e"
	e := newTestEnv()
	e.fs["root"] = &fstest.MapFile{Mode: fs.ModeDir | 0o700}
	e.fs["root/.env"] = &fstest.MapFile{Data: []byte("STRIPE_KEY=" + secret + "\n"), Mode: 0o644}
	e.fs["opt/appstack"] = &fstest.MapFile{Mode: fs.ModeDir | 0o755}
	e.fs["opt/appstack/.env.api"] = &fstest.MapFile{Data: []byte("STRIPE_KEY=" + secret + "\n"), Mode: 0o644}
	r := run(t, secretsCheck{}, e)
	wantStatus(t, r, StatusFail, "world-readable", "readable-closed")
	if v := r.Findings[0].Vars; v["path"] != "/opt/appstack/.env.api" {
		t.Errorf("open finding = %v", v)
	}
	if v := r.Findings[1].Vars; v["path"] != "/root/.env" || v["folder"] != "/root" {
		t.Errorf("closed finding = %v", v)
	}
}

// The provider's firewall (DigitalOcean's Cloud Firewall, an AWS security
// group) cannot be seen from inside. Said in the settings, it is the
// firewall, and ports on public addresses are behind it, not open.
func TestProviderFirewallInTheSettings(t *testing.T) {
	e := newTestEnv().file("proc/net/tcp", procTCP(22, 80, 443, 5432, 8080))
	e.cfg.Ports.ProviderFirewall = true
	r := run(t, firewallCheck{}, e)
	wantStatus(t, r, StatusPass)
	if !strings.Contains(r.Vars["firewall"], "your provider's") {
		t.Errorf("firewall: %+v", r)
	}
	wantStatus(t, run(t, openPortsCheck{}, e), StatusFail, "provider")
	wantStatus(t, run(t, exposedDatabasesCheck{}, e), StatusFail, "provider")
}

// "No firewall" names the firewall this server's provider offers, which
// Kiyesi cannot see from inside.
func TestNoFirewallNamesTheProvidersOwn(t *testing.T) {
	do := newTestEnv().saved(t, "run/cloud-init/instance-data.json", "instance-data-do-lon1.json").
		file("etc/ufw/ufw.conf", "ENABLED=no\n").command("iptables -S INPUT", "-P INPUT ACCEPT\n")
	r := run(t, firewallCheck{}, do)
	if r.Status != StatusFail || r.Findings[0].Vars["provider_firewall"] != "a DigitalOcean Cloud Firewall" {
		t.Errorf("DigitalOcean: %+v", r)
	}
	unknown := newTestEnv().file("etc/ufw/ufw.conf", "ENABLED=no\n").command("iptables -S INPUT", "-P INPUT ACCEPT\n")
	if r := run(t, firewallCheck{}, unknown); r.Findings[0].Vars["provider_firewall"] != "your provider's firewall" {
		t.Errorf("unknown provider: %+v", r)
	}
}
