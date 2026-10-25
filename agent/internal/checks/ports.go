package checks

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// databases maps each database port to its name. These ports are reported
// by the exposed-databases check only, so one problem costs the grade once.
var databases = map[int]string{27017: "MongoDB", 6379: "Redis", 5432: "PostgreSQL", 3306: "MySQL"}

// databaseVariant names each database's own fix in the pack.
var databaseVariant = map[int]string{27017: "mongodb", 6379: "redis", 5432: "postgresql", 3306: "mysql"}

type openPortsCheck struct{}

func (openPortsCheck) ID() string { return "open-ports" }

func (openPortsCheck) Run(ctx context.Context, env *Env) Result {
	ls, err := env.Listeners()
	if err != nil {
		return Skip("not-linux", nil)
	}
	open := map[int]bool{}
	for _, l := range ls {
		open[l.Port] = true
	}
	// With Docker's userland proxy turned off, published ports do not show
	// in /proc/net/tcp, so add them from Docker. Without root this part is
	// unknown, which the docker checks report.
	if cs, err := env.Containers(ctx); err == nil {
		for _, p := range publishedPublic(cs) {
			open[p.Port] = true
		}
	}
	allowed := map[int]bool{}
	for _, p := range env.Cfg.Ports.Allowed {
		allowed[p] = true
	}
	ports := make([]int, 0, len(open))
	for p := range open {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	var found []Finding
	var shown []string
	for _, p := range ports {
		shown = append(shown, strconv.Itoa(p))
		if allowed[p] || databases[p] != "" {
			continue
		}
		found = append(found, Found("open", map[string]string{"port": strconv.Itoa(p)}))
	}
	if len(found) > 0 {
		return Fail(found...)
	}
	if len(shown) == 0 {
		shown = []string{"none"}
	}
	return Pass(map[string]string{"ports": strings.Join(shown, ", ")})
}

type exposedDatabasesCheck struct{}

func (exposedDatabasesCheck) ID() string { return "exposed-databases" }

func (exposedDatabasesCheck) Run(ctx context.Context, env *Env) Result {
	ls, err := env.Listeners()
	if err != nil {
		return Skip("not-linux", nil)
	}
	cs, dockerErr := env.Containers(ctx)
	if dockerErr != nil && !errors.Is(dockerErr, system.ErrNeedsRoot) {
		return Failed(dockerErr)
	}
	var found []Finding
	byDocker := map[int]bool{}

	// Docker publishes past ufw, so a public published port is open
	// whatever ufw says.
	for _, p := range publishedPublic(cs) {
		name := databases[p.Port]
		if name == "" {
			continue
		}
		byDocker[p.Port] = true
		vars := map[string]string{"database": name, "port": strconv.Itoa(p.Port), "service": p.Container.ComposeService}
		variant := ""
		if p.Container.ComposeService == "" {
			variant = "docker-run"
		}
		found = append(found, Finding{Key: "open", Variant: variant, Vars: vars})
	}

	fw := env.Firewall(ctx)
	unknown := false
	for _, l := range ls {
		name := databases[l.Port]
		if name == "" || byDocker[l.Port] {
			continue
		}
		// docker-proxy listens for published ports; if Docker could not be
		// read, this may be one, and the fix would be wrong, but the port is
		// open all the same.
		if fw.Blocks(l.Port) {
			continue
		}
		if fw.UFW && !fw.UFWRulesKnown {
			unknown = true
			continue
		}
		vars := map[string]string{"database": name, "port": strconv.Itoa(l.Port)}
		found = append(found, Finding{Key: "open", Variant: databaseVariant[l.Port], Vars: vars})
	}
	if len(found) > 0 {
		return Fail(found...)
	}
	if unknown || errors.Is(dockerErr, system.ErrNeedsRoot) {
		return NeedsRoot()
	}
	return Pass(nil)
}

type dockerFirewallCheck struct{}

func (dockerFirewallCheck) ID() string { return "docker-firewall" }

func (dockerFirewallCheck) Run(ctx context.Context, env *Env) Result {
	cs, err := env.Containers(ctx)
	if errors.Is(err, system.ErrNeedsRoot) {
		return NeedsRoot()
	}
	if err != nil {
		return Failed(err)
	}
	fw := env.Firewall(ctx)
	if !fw.UFW {
		// Without ufw there is no rule for Docker to bypass. A missing
		// firewall is the firewall check's finding.
		return Pass(nil)
	}
	var found []Finding
	for _, p := range publishedPublic(cs) {
		if databases[p.Port] != "" {
			continue // reported by exposed-databases
		}
		if !fw.UFWRulesKnown {
			return NeedsRoot()
		}
		if fw.Blocks(p.Port) {
			vars := map[string]string{"port": strconv.Itoa(p.Port), "service": p.Container.ComposeService}
			if vars["service"] == "" {
				vars["service"] = p.Container.Name
			}
			// 80 and 443 are a website's ports, public on purpose: worth a
			// look, never a lost point, and never "bind it to 127.0.0.1",
			// which would take the site offline.
			key := "bypass"
			if p.Port == 80 || p.Port == 443 {
				key = "web"
			}
			found = append(found, Found(key, vars))
		}
	}
	if len(found) > 0 {
		return Fail(found...)
	}
	return Pass(nil)
}
