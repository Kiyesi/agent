package checks

import (
	"context"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/packs"
)

// serverPlace is where this server is, from the provider's own details.
type serverPlace struct {
	provider string // "DigitalOcean", or empty when unknown
	place    string // "London, UK"
	country  string // ISO code
	known    bool
}

// homeVars are the values every data-location sentence uses.
func homeVars(env *Env, places *packs.Places) map[string]string {
	home := env.Cfg.HomeCountry
	v := map[string]string{"home": places.CountryName(home), "rule": ""}
	if c := places.Country(home); c != nil {
		v["home"] = c.Name
		v["rule"] = strings.TrimSpace(c.Rule)
	}
	return v
}

func with(base map[string]string, kv ...string) map[string]string {
	out := make(map[string]string, len(base)+len(kv)/2)
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

// Server reads where this server is, once per scan: first cloud-init's
// local copy of the provider's details, then the provider's metadata
// address, chosen by the maker the firmware reports. Nothing is sent.
func (e *Env) Server(ctx context.Context) serverPlace {
	e.serverOnce.Do(func() { e.server = readServer(ctx, e) })
	return e.server
}

func readServer(ctx context.Context, e *Env) serverPlace {
	places, err := packs.LoadPlaces()
	if err != nil {
		return serverPlace{}
	}
	var prov *packs.Provider
	if data, err := fs.ReadFile(e.Sys.FS, "run/cloud-init/instance-data.json"); err == nil {
		var doc struct {
			V1 struct {
				CloudName        string `json:"cloud_name"`
				Region           string `json:"region"`
				AvailabilityZone string `json:"availability_zone"`
			} `json:"v1"`
		}
		if json.Unmarshal(data, &doc) == nil {
			prov = places.ProviderByCloudInit(doc.V1.CloudName)
			if prov != nil {
				for _, code := range []string{doc.V1.Region, doc.V1.AvailabilityZone} {
					if r, _, ok := prov.Region(code); ok && code != "" {
						return serverPlace{provider: prov.Name, place: places.Place(r), country: r.Country, known: true}
					}
				}
			}
		}
	}
	if prov == nil {
		if vendor, err := fs.ReadFile(e.Sys.FS, "sys/class/dmi/id/sys_vendor"); err == nil {
			prov = places.ProviderByVendor(string(vendor))
		}
	}
	if prov == nil || e.Sys.Metadata == nil {
		return serverPlace{}
	}
	if code := metadataRegion(ctx, e, prov.ID); code != "" {
		if r, _, ok := prov.Region(code); ok {
			return serverPlace{provider: prov.Name, place: places.Place(r), country: r.Country, known: true}
		}
	}
	return serverPlace{provider: prov.Name}
}

// metadataRegion asks the one provider the server runs on for its region.
func metadataRegion(ctx context.Context, e *Env, provider string) string {
	m := e.Sys.Metadata
	get := func(path string, headers map[string]string) string {
		v, err := m.Get(ctx, http.MethodGet, path, headers)
		if err != nil {
			return ""
		}
		return v
	}
	switch provider {
	case "digitalocean":
		return get("/metadata/v1/region", nil)
	case "hetzner":
		return get("/hetzner/v1/metadata/availability-zone", nil)
	case "aws":
		token, err := m.Get(ctx, http.MethodPut, "/latest/api/token", map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "60"})
		if err != nil {
			return ""
		}
		return get("/latest/meta-data/placement/region", map[string]string{"X-aws-ec2-metadata-token": token})
	case "gcp":
		zone := get("/computeMetadata/v1/instance/zone", map[string]string{"Metadata-Flavor": "Google"})
		return zone[strings.LastIndex(zone, "/")+1:]
	case "azure":
		return get("/metadata/instance/compute/location?api-version=2021-02-01&format=text", map[string]string{"Metadata": "true"})
	case "vultr":
		var doc struct {
			Region struct {
				RegionCode string `json:"regioncode"`
			} `json:"region"`
		}
		if json.Unmarshal([]byte(get("/v1.json", nil)), &doc) == nil {
			return strings.ToLower(doc.Region.RegionCode)
		}
	}
	return ""
}

type serverLocationCheck struct{}

func (serverLocationCheck) ID() string { return "server-location" }

func (serverLocationCheck) Run(ctx context.Context, env *Env) Result {
	places, err := packs.LoadPlaces()
	if err != nil {
		return Failed(err)
	}
	s := env.Server(ctx)
	if !s.known {
		name := "this server"
		if s.provider != "" {
			name = "this server (" + s.provider + ")"
		}
		r := Skip("unknown", nil)
		r.Locations = []Location{{Kind: "Server", Name: name, Provider: s.provider}}
		return r
	}
	vars := with(homeVars(env, places), "place", s.place)
	row := Location{Kind: "Server", Name: s.provider + ", " + s.place, Provider: s.provider, Place: s.place, Country: s.country, Confidence: "confirmed"}
	if s.country != env.Cfg.HomeCountry {
		r := Fail(Found("outside", vars))
		r.Locations = []Location{row}
		return r
	}
	r := Pass(vars)
	r.Locations = []Location{row}
	return r
}

// dbConn is one database the server's settings connect to. It never holds
// a user name or password.
type dbConn struct {
	kind  string // PostgreSQL, MongoDB, Redis, MySQL
	host  string
	port  string
	local bool // on this server
	// private is on the server's private network (10.x, 192.168.x, .internal).
	private bool
	// provider is the provider's name when the host was recognised.
	provider string
	place    string
	country  string
	known    bool
}

func (d dbConn) name() string {
	if d.local {
		return strings.ToLower(d.kind) + " (this server)"
	}
	if d.port != "" {
		return d.host + ":" + d.port
	}
	return d.host
}

var dbKey = regexp.MustCompile(`^(DATABASE_URL|DB_URL|[A-Z0-9_]*_DATABASE_URL|MONGO[A-Z0-9_]*_(URI|URL)|MONGO_(URI|URL)|MONGODB_(URI|URL)|REDIS_(URL|HOST)|[A-Z0-9_]*_REDIS_URL|VALKEY_URL|POSTGRES(QL)?_(HOST|URL)|PGHOST|MYSQL_(HOST|URL)|MARIADB_HOST|DB_HOST|[A-Z0-9_]*_DB_HOST)$`)

var schemeKind = map[string]string{
	"postgres": "PostgreSQL", "postgresql": "PostgreSQL",
	"mongodb": "MongoDB", "mongodb+srv": "MongoDB",
	"redis": "Redis", "rediss": "Redis", "valkey": "Valkey", "valkeys": "Valkey",
	"mysql": "MySQL", "mariadb": "MySQL",
}

func kindFromKey(key string) string {
	switch {
	case strings.Contains(key, "MONGO"):
		return "MongoDB"
	case strings.Contains(key, "VALKEY"):
		return "Valkey"
	case strings.Contains(key, "REDIS"):
		return "Redis"
	case strings.Contains(key, "MYSQL"), strings.Contains(key, "MARIADB"):
		return "MySQL"
	default:
		return "PostgreSQL"
	}
}

// localHost is true for this server: loopback, private addresses, and
// single-word names such as a Compose service.
// containerImages maps each running container's names (its own and its
// Compose service's) to its image, lower case.
func containerImages(ctx context.Context, e *Env) map[string]string {
	out := map[string]string{}
	if e.Sys.Docker == nil {
		return out
	}
	cs, err := e.Sys.Docker.Containers(ctx)
	if err != nil {
		return out
	}
	for _, c := range cs {
		img := strings.ToLower(c.Image)
		out[strings.ToLower(c.Name)] = img
		if c.ComposeService != "" {
			out[strings.ToLower(c.ComposeService)] = img
		}
	}
	return out
}

// valkeyAt is whether the database at host runs Valkey: the container of
// that name does, or, for localhost, the only database container here does.
func valkeyAt(images map[string]string, host string) bool {
	if img, ok := images[strings.ToLower(host)]; ok {
		return strings.Contains(img, "valkey")
	}
	if host == "localhost" || host == "127.0.0.1" {
		valkey, redis := false, false
		for _, img := range images {
			valkey = valkey || strings.Contains(img, "valkey")
			redis = redis || strings.Contains(img, "redis")
		}
		return valkey && !redis
	}
	return false
}

// localHost is a database on this server: localhost, the host from a
// container, or a Compose service's name (no dot).
func localHost(h string) bool {
	if h == "localhost" || h == "host.docker.internal" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return !strings.Contains(h, ".")
}

// privateHost is an address on a private network: another machine, near.
func privateHost(h string) bool {
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	return strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".local")
}

// databaseAddress is a value that is a database's address, whatever the
// setting is called: a URL with a database's scheme and a host.
func databaseAddress(v string) bool {
	u, err := url.Parse(strings.TrimSpace(v))
	return err == nil && u.Host != "" && schemeKind[strings.ToLower(u.Scheme)] != ""
}

// Databases lists the databases named in connection settings, once per scan.
func (e *Env) Databases(ctx context.Context) []dbConn {
	e.databasesOnce.Do(func() {
		places, err := packs.LoadPlaces()
		if err != nil {
			return
		}
		server := e.Server(ctx)
		images := containerImages(ctx, e)
		seen := map[string]bool{}
		for _, s := range e.Settings().Values {
			// By its name, or, whatever it is called, by a value that is a
			// database's address (MY_DB_ADDR=postgres://…).
			if !dbKey.MatchString(s.Key) && !databaseAddress(s.Value) {
				continue
			}
			d := dbConn{kind: kindFromKey(s.Key)}
			if u, err := url.Parse(s.Value); err == nil && u.Host != "" {
				if k := schemeKind[strings.ToLower(u.Scheme)]; k != "" {
					d.kind = k
				}
				host := u.Host
				if i := strings.Index(host, ","); i > 0 { // a replica set lists several hosts
					host = host[:i]
				}
				d.host, d.port = splitHostPort(host)
			} else {
				d.host, d.port = splitHostPort(s.Value)
			}
			d.host = strings.ToLower(d.host)
			if d.host == "" || strings.ContainsAny(d.host, " /$") {
				continue
			}
			d.local = localHost(d.host)
			d.private = !d.local && privateHost(d.host)
			// Valkey answers redis:// addresses too: the container the
			// address points to says which it is.
			if d.kind == "Redis" && valkeyAt(images, d.host) {
				d.kind = "Valkey"
			}
			key := d.name()
			if seen[key] {
				continue
			}
			seen[key] = true
			switch {
			case d.local:
				d.place, d.country, d.known, d.provider = server.place, server.country, server.known, server.provider
			case d.private:
				// On the server's private network: in the same place as the
				// server with every provider Kiyesi knows, though a VPN can
				// reach further, so it is likely, not confirmed.
				d.place, d.country, d.known, d.provider = server.place, server.country, server.known, server.provider
			default:
				if prov, r, ok := places.HostRegion(d.host); ok {
					d.place, d.country, d.known = places.Place(r), r.Country, true
					d.provider = prov.Name
				}
			}
			e.databases = append(e.databases, d)
		}
		sort.SliceStable(e.databases, func(i, j int) bool { return e.databases[i].local && !e.databases[j].local })
	})
	return e.databases
}

func splitHostPort(s string) (string, string) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	return strings.Trim(s, "[]"), ""
}

type databaseConnectionsCheck struct{}

func (databaseConnectionsCheck) ID() string { return "database-connections" }

func (databaseConnectionsCheck) Run(ctx context.Context, env *Env) Result {
	places, err := packs.LoadPlaces()
	if err != nil {
		return Failed(err)
	}
	dbs := env.Databases(ctx)
	if len(dbs) == 0 {
		if env.Settings().Blocked && !env.Sys.Root {
			return NeedsRoot()
		}
		return PassNone()
	}
	base := homeVars(env, places)
	var rows []Location
	var found []Finding
	for _, d := range dbs {
		row := Location{Kind: "Database", Name: d.name(), Provider: d.provider, Place: d.place, Country: d.country, Payment: tagged(env.Cfg.PaymentData, d), Private: d.private}
		if !d.local {
			row.Host = d.host
		}
		if d.known {
			row.Confidence = "likely"
			if d.local {
				row.Confidence = env.Server(ctx).confidence()
			}
		}
		rows = append(rows, row)
		// A database on this server is where the server is: the server
		// check reports it, so it costs the grade once.
		if !d.local && !d.private && d.known && d.country != env.Cfg.HomeCountry {
			found = append(found, Found("outside", with(base, "host", d.name(), "place", d.place)))
		}
	}
	var r Result
	if len(found) > 0 {
		r = Fail(found...)
	} else {
		r = Pass(with(base, "count", strconv.Itoa(len(dbs))))
	}
	r.Locations = rows
	return r
}

func (s serverPlace) confidence() string {
	if s.known {
		return "confirmed"
	}
	return ""
}

type backupDestinationsCheck struct{}

func (backupDestinationsCheck) ID() string { return "backup-destinations" }

// backup is one place backups are sent.
type backup struct {
	target   string
	host     string
	provider string
	place    string
	country  string
}

var (
	resticRepo  = regexp.MustCompile(`(?i)RESTIC_REPOSITORY=["']?(\S+)|restic\s+(?:-r|--repo)\s+["']?(\S+)`)
	endpointURL = regexp.MustCompile(`(?i)--endpoint(?:-url)?[= ]["']?(https?://[^\s"']+)`)
	s3Region    = regexp.MustCompile(`(?i)aws\s+s3\s+(?:cp|sync|mv)\b.*\s--region[= ]([a-z]{2}-[a-z]+-\d)`)
	s3Bucket    = regexp.MustCompile(`s3://([a-z0-9.\-]+)`)
)

func backups(env *Env, places *packs.Places) []backup {
	var out []backup
	seen := map[string]bool{}
	add := func(target, host, region string, prov *packs.Provider) {
		b := backup{target: target, host: host}
		if host != "" {
			if p, r, ok := places.HostRegion(host); ok {
				b.place, b.country, b.provider = places.Place(r), r.Country, p.Name
			}
		}
		if b.place == "" && prov != nil && region != "" {
			if r, _, ok := prov.Region(region); ok {
				b.place, b.country, b.provider = places.Place(r), r.Country, prov.Name
			}
		}
		if !seen[b.target] {
			seen[b.target] = true
			out = append(out, b)
		}
	}
	aws := providerByID(places, "aws")
	s := env.Settings()
	for _, rc := range s.Rclone {
		host := rc.Endpoint
		if u, err := url.Parse(rc.Endpoint); err == nil && u.Host != "" {
			host = u.Host
		}
		var prov *packs.Provider
		if strings.EqualFold(rc.Provider, "AWS") || (rc.Type == "s3" && rc.Provider == "") {
			prov = aws
		}
		add("rclone remote "+rc.Name, host, rc.Region, prov)
	}
	lines := append(append([]Setting{}, s.Scripts...), s.Values...)
	for _, l := range lines {
		text := l.Value
		if l.Key != "" {
			text = l.Key + "=" + l.Value
		}
		if m := resticRepo.FindStringSubmatch(text); m != nil {
			repo := m[1] + m[2]
			repo = strings.Trim(repo, `"'`)
			host := ""
			if rest, ok := strings.CutPrefix(repo, "s3:"); ok {
				if u, err := url.Parse(rest); err == nil && u.Host != "" {
					host = u.Host
				} else {
					host, _, _ = strings.Cut(rest, "/")
				}
			}
			add("restic repository "+maskRepo(repo), host, "", nil)
		}
		if m := endpointURL.FindStringSubmatch(text); m != nil {
			if u, err := url.Parse(m[1]); err == nil {
				add(u.Host, u.Host, "", nil)
			}
		}
		if m := s3Bucket.FindStringSubmatch(text); m != nil && strings.Contains(text, "aws s3") {
			region := ""
			if r := s3Region.FindStringSubmatch(text); r != nil {
				region = r[1]
			}
			add("s3://"+m[1], "", region, aws)
		}
	}
	return out
}

// maskRepo drops anything that looks like a credential from a restic
// repository address.
func maskRepo(repo string) string {
	rest, isS3 := strings.CutPrefix(repo, "s3:")
	if u, err := url.Parse(rest); err == nil && u.User != nil {
		u.User = nil
		if isS3 {
			return "s3:" + u.String()
		}
		return u.String()
	}
	return repo
}

func providerByID(places *packs.Places, id string) *packs.Provider {
	for _, p := range places.Providers {
		if p.ID == id {
			return p
		}
	}
	return nil
}

func (backupDestinationsCheck) Run(_ context.Context, env *Env) Result {
	places, err := packs.LoadPlaces()
	if err != nil {
		return Failed(err)
	}
	bs := backups(env, places)
	if len(bs) == 0 {
		if env.Settings().Blocked && !env.Sys.Root {
			return NeedsRoot()
		}
		return PassNone()
	}
	base := homeVars(env, places)
	var rows []Location
	var found []Finding
	for _, b := range bs {
		row := Location{Kind: "Backup", Name: b.target, Host: b.host, Provider: b.provider, Place: b.place, Country: b.country}
		if b.place != "" {
			row.Confidence = "likely"
			if b.country != env.Cfg.HomeCountry {
				found = append(found, Found("outside", with(base, "target", b.target, "place", b.place)))
			}
		}
		rows = append(rows, row)
	}
	var r Result
	if len(found) > 0 {
		r = Fail(found...)
	} else {
		r = Pass(with(base, "count", strconv.Itoa(len(bs))))
	}
	r.Locations = rows
	return r
}

type outsideServicesCheck struct{}

func (outsideServicesCheck) ID() string { return "outside-services" }

// services maps setting names to the outside service they point at.
var services = []struct {
	key  *regexp.Regexp
	name string
}{
	{regexp.MustCompile(`SENTRY_DSN`), "Sentry"},
	{regexp.MustCompile(`(SMTP|MAIL|EMAIL)_(HOST|SERVER)$`), "Email (SMTP)"},
	{regexp.MustCompile(`TWILIO`), "Twilio"},
	{regexp.MustCompile(`TERMII`), "Termii"},
	{regexp.MustCompile(`AFRICASTALKING|AT_API_KEY`), "Africa's Talking"},
	{regexp.MustCompile(`SENDGRID`), "SendGrid"},
	{regexp.MustCompile(`MAILGUN`), "Mailgun"},
	{regexp.MustCompile(`POSTMARK`), "Postmark"},
	{regexp.MustCompile(`RESEND`), "Resend"},
	{regexp.MustCompile(`BREVO|SENDINBLUE`), "Brevo"},
	{regexp.MustCompile(`^DD_|DATADOG`), "Datadog"},
	{regexp.MustCompile(`NEW_RELIC`), "New Relic"},
	{regexp.MustCompile(`LOGTAIL|BETTERSTACK`), "Better Stack"},
	{regexp.MustCompile(`PAPERTRAIL`), "Papertrail"},
	{regexp.MustCompile(`LOKI_(URL|HOST)`), "Loki"},
}

func (outsideServicesCheck) Run(_ context.Context, env *Env) Result {
	seen := map[string]bool{}
	var rows []Location
	for _, s := range env.Settings().Values {
		for _, svc := range services {
			if !svc.key.MatchString(s.Key) {
				continue
			}
			name := svc.name
			if u, err := url.Parse(s.Value); err == nil && u.Host != "" {
				name += " (" + u.Hostname() + ")"
			} else if strings.HasSuffix(s.Key, "_HOST") && strings.Contains(s.Value, ".") && !strings.ContainsAny(s.Value, " /") {
				name += " (" + s.Value + ")"
			}
			if !seen[name] {
				seen[name] = true
				rows = append(rows, Location{Kind: "Service", Name: name, Review: true})
			}
			break
		}
	}
	if len(rows) == 0 {
		if env.Settings().Blocked && !env.Sys.Root {
			return NeedsRoot()
		}
		return PassNone()
	}
	r := Pass(map[string]string{"count": strconv.Itoa(len(rows))})
	r.Locations = rows
	return r
}

type paymentDataCheck struct{}

func (paymentDataCheck) ID() string { return "payment-data" }

func (paymentDataCheck) Run(ctx context.Context, env *Env) Result {
	places, err := packs.LoadPlaces()
	if err != nil {
		return Failed(err)
	}
	tags := env.Cfg.PaymentData
	if len(tags) == 0 {
		return PassNone()
	}
	base := homeVars(env, places)
	var found []Finding
	matched := 0
	for _, d := range env.Databases(ctx) {
		if !tagged(tags, d) {
			continue
		}
		matched++
		if d.known && d.country != env.Cfg.HomeCountry {
			conf := "likely"
			if d.local && env.Server(ctx).known {
				conf = "confirmed"
			}
			f := Found("outside", with(base, "host", d.name(), "place", d.place))
			f.Confidence = conf
			found = append(found, f)
		}
	}
	if len(found) > 0 {
		return Fail(found...)
	}
	return Pass(with(base, "count", strconv.Itoa(matched)))
}

func tagged(tags []string, d dbConn) bool {
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == d.host || t == d.host+":"+d.port || t == d.name() || (d.local && (t == strings.ToLower(d.kind) || (d.kind == "Valkey" && t == "redis"))) {
			return true
		}
	}
	return false
}
