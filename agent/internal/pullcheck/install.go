package pullcheck

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
)

// downloadAndRun are commands that fetch code and run it in one go.
var downloadAndRun = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:-\s*)?(?:sh|bash|zsh|dash|ksh|node|python[0-9.]*|perl|ruby|php)\b`),
	regexp.MustCompile(`(?i)\b(?:sh|bash|zsh)\b\s+(?:-c\s+)?["']?\$\(\s*(?:curl|wget)\b`),
	regexp.MustCompile(`(?i)\b(?:sh|bash|zsh)\s+<\(\s*(?:curl|wget)\b`),
	regexp.MustCompile(`(?i)\b(?:curl|wget)\b.*(?:&&|;|\|\|)\s*(?:sudo\s+)?(?:sh|bash|node|python[0-9.]*|chmod\s+\+x|\./)`),
	regexp.MustCompile(`(?i)\bnode\s+(?:-e|--eval|-p|--print)\b.*(?:fetch\s*\(|https?\.(?:get|request)\b|require\(\s*['"\\]+https?['"\\]+\s*\)|https?://)`),
	regexp.MustCompile(`(?i)\bpython[0-9.]*\s+-c\b.*(?:urllib|requests|https?://|socket)`),
	regexp.MustCompile(`(?i)(?:\biwr\b|invoke-webrequest|\birm\b|invoke-restmethod|downloadstring|downloadfile|net\.webclient|start-bitstransfer).*(?:\|\s*iex\b|invoke-expression|\biex\b|start-process)`),
	regexp.MustCompile(`(?i)\biex\b.*(?:downloadstring|\biwr\b|\birm\b|invoke-webrequest|invoke-restmethod)`),
	regexp.MustCompile(`(?i)\bpowershell(?:\.exe)?\b.*\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}`),
}

func downloadsAndRuns(s string) bool {
	for _, re := range downloadAndRun {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// The scripts npm and Composer run on their own while installing.
var (
	npmHooks      = []string{"preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish"}
	composerHooks = []string{"pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd", "pre-autoload-dump", "post-autoload-dump", "post-root-package-install", "post-create-project-cmd"}
	hookLine      = regexp.MustCompile(`"((?:pre|post)?install|prepare|preprepare|postprepare|prepublish|(?:pre|post)-(?:install|update|autoload)-(?:cmd|dump)|post-root-package-install|post-create-project-cmd)"\s*:\s*(.*)$`)
)

// buildFile is a file that runs when a package is built or installed,
// and what in it downloads and what runs.
type buildFile struct {
	download, run *regexp.Regexp
	// alone downloads and runs in one line, with nothing else needed.
	alone *regexp.Regexp
}

var buildFiles = map[string]buildFile{
	"setup.py": {
		download: regexp.MustCompile(`\burllib\b|\brequests\.(?:get|post)\b|\burlopen\b|https?://|\bcurl\b|\bwget\b|\bhttp\.client\b|\bsocket\.`),
		run:      regexp.MustCompile(`(?:^|[^.\w])exec\s*\(|(?:^|[^.\w])eval\s*\(|\bsubprocess\b|\bos\.(?:system|popen|exec\w*)\s*\(|\bPopen\b`),
	},
	"build.rs": {
		download: regexp.MustCompile(`\breqwest\b|\bureq\b|\bTcpStream\b|https?://|\bcurl\b|\bwget\b`),
		run:      regexp.MustCompile(`\bCommand::new\b|\bstd::process\b`),
		alone:    regexp.MustCompile(`Command::new\(\s*"(?:curl|wget)"`),
	},
	"extconf.rb": rubyBuild,
	"Gemfile":    rubyBuild,
}

var rubyBuild = buildFile{
	download: regexp.MustCompile(`\bopen-uri\b|\bURI\.open\b|\bNet::HTTP\b|\bcurl\b|\bwget\b|\bopen\(\s*["']https?://`),
	run:      regexp.MustCompile(`(?:^|[^.\w])(?:system|exec|eval|spawn)\s*[\( ]|` + "`[^`]+`" + `|%x[\(\[{]|\bIO\.popen\b|\bKernel\.(?:system|spawn|exec)\b`),
}

// install finds install scripts that download and run code, and new npm
// dependencies that run their own install script.
func (c *checker) install(f File, p string, t *text) {
	base := path.Base(f.Path)
	switch {
	case base == "package.json":
		c.languages["npm"] = true
		c.installHooks(f, p, t, npmHooks)
	case base == "composer.json":
		c.languages["Packagist"] = true
		c.installHooks(f, p, t, composerHooks)
	case base == "package-lock.json" || base == "npm-shrinkwrap.json":
		if f.After != nil {
			c.npmInstallScripts(f, p, t)
		}
	case base == "pnpm-lock.yaml":
		if f.After != nil {
			c.pnpmInstallScripts(f, p, t)
		}
	case strings.HasSuffix(base, ".gemspec"):
		c.buildFile(p, t, rubyBuild)
	default:
		if b, ok := buildFiles[base]; ok {
			c.buildFile(p, t, b)
		}
	}
}

// hookScripts reads a manifest's install scripts: npm's are strings,
// Composer's a string or a list.
func hookScripts(s string, hooks []string) (map[string][]string, bool) {
	if jsonTooDeep(s, 256) {
		return nil, false
	}
	var m struct {
		Scripts map[string]json.RawMessage `json:"scripts"`
	}
	if json.Unmarshal([]byte(s), &m) != nil {
		return nil, false
	}
	out := map[string][]string{}
	for _, h := range hooks {
		raw, ok := m.Scripts[h]
		if !ok {
			continue
		}
		var one string
		var many []string
		if json.Unmarshal(raw, &one) == nil {
			out[h] = []string{one}
		} else if json.Unmarshal(raw, &many) == nil {
			out[h] = many
		}
	}
	return out, true
}

// installHooks reads the whole manifest when it is given, else the
// lines the patch adds.
func (c *checker) installHooks(f File, p string, t *text, hooks []string) {
	if f.After == nil {
		for _, a := range t.added {
			if m := hookLine.FindStringSubmatch(a.s); m != nil && downloadsAndRuns(m[2]) {
				c.scriptFinding(p, t, m[1], a.n, a.s)
			}
		}
		return
	}
	after, ok := hookScripts(*f.After, hooks)
	if !ok {
		return
	}
	before := map[string][]string{}
	if f.Before != nil {
		before, _ = hookScripts(*f.Before, hooks)
	}
	for _, h := range hooks {
		was := map[string]bool{}
		for _, cmd := range before[h] {
			was[cmd] = true
		}
		for _, cmd := range after[h] {
			// A script is read as a line is: its first MaxLine bytes.
			if was[cmd] || !downloadsAndRuns(cutAt(cmd, MaxLine)) {
				continue
			}
			n := t.lineWith(`"`+h+`"`, 1)
			if probe := cutAt(cmd, 40); n > 0 {
				if m := t.lineWith(jsonQuote(probe), n); m > 0 && m-n < 50 {
					n = m
				}
			}
			c.scriptFinding(p, t, h, n, cmd)
		}
	}
}

// jsonQuote is a string as JSON writes it, without its quotes.
func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return strings.Trim(string(b), `"`)
}

func (c *checker) scriptFinding(p string, t *text, hook string, n int, cmd string) {
	title, how, fix := c.words("install-script", map[string]string{"script": hook, "file": p})
	c.add(Finding{
		Rule: RuleInstall, Title: title, File: p, Start: n, End: n, Snippet: t.snippet(n, n),
		How: how, Fix: fix, Fingerprint: fingerprint(RuleInstall, p, normalise(hook+": "+cmd)),
	})
}

// npmInstallScripts finds packages new to package-lock.json that run
// their own install script.
func (c *checker) npmInstallScripts(f File, p string, t *text) {
	if jsonTooDeep(*f.After, 256) {
		return
	}
	after := npmLock(*f.After)
	before := map[string]npmEntry{}
	if f.Before != nil && !jsonTooDeep(*f.Before, 256) {
		before = npmLock(*f.Before)
	}
	keys := make([]string, 0, len(after))
	for k := range after {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e := after[k]
		if !e.HasInstallScript {
			continue
		}
		if old, ok := before[k]; ok && old.HasInstallScript && old.Version == e.Version {
			continue
		}
		c.dependencyScript(p, t, e.Name, e.Version)
	}
}

// pnpmInstallScripts does the same for pnpm-lock.yaml's requiresBuild.
func (c *checker) pnpmInstallScripts(f File, p string, t *text) {
	builds := func(s string) map[string]bool {
		out := map[string]bool{}
		var cur string
		in := false
		for _, l := range strings.Split(s, "\n") {
			l = strings.TrimRight(l, "\r")
			if l == "" {
				continue
			}
			if !strings.HasPrefix(l, " ") {
				in = strings.HasPrefix(l, "packages:")
				continue
			}
			if !in {
				continue
			}
			if !strings.HasPrefix(l, "   ") {
				cur = ""
				if m := pnpmKey.FindStringSubmatch(l); m != nil {
					cur = m[1] + "\x00" + m[2]
				}
				continue
			}
			if cur != "" && strings.TrimSpace(l) == "requiresBuild: true" {
				out[cur] = true
			}
		}
		return out
	}
	after := builds(*f.After)
	before := map[string]bool{}
	if f.Before != nil {
		before = builds(*f.Before)
	}
	keys := make([]string, 0, len(after))
	for k := range after {
		if !before[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		name, version, _ := strings.Cut(k, "\x00")
		c.dependencyScript(p, t, name, version)
	}
}

func (c *checker) dependencyScript(p string, t *text, name, version string) {
	if c.data.IsKnownGood(name) {
		return
	}
	dep, _ := c.data.DependencyFile(p)
	start, end := t.locatePackage(p, name, version)
	vars := map[string]string{"name": name, "version": version, "file": p, "manifest": dep.Manifest, "command": dep.Command}
	title, how, fix := c.words("install-dependency", vars)
	c.add(Finding{
		Rule: RuleInstall, Title: title, File: p, Start: start, End: end, Snippet: t.snippet(start, end),
		How: how, Fix: fix, Fingerprint: fingerprint(RuleInstall, p, "npm/"+name+"@"+version),
		Package: &Package{Ecosystem: "npm", Name: name, Version: version},
	})
}

// buildFile finds added lines in a build file that download code, with
// added lines near them that run something.
func (c *checker) buildFile(p string, t *text, b buildFile) {
	const near = 15
	for i := 0; i < len(t.added); i++ {
		a := t.added[i]
		if i%1024 == 0 && c.ctx.Err() != nil {
			return
		}
		if b.alone != nil && b.alone.MatchString(a.s) {
			c.buildFinding(p, t, a, a)
			continue
		}
		if !b.download.MatchString(a.s) {
			continue
		}
		for j := max(0, i-near); j < len(t.added) && j <= i+near; j++ {
			r := t.added[j]
			if r.n-a.n > near || a.n-r.n > near {
				continue
			}
			if b.run.MatchString(r.s) {
				c.buildFinding(p, t, a, r)
				// The lines up to what runs are the same problem.
				i = max(i, j)
				break
			}
		}
	}
}

func (c *checker) buildFinding(p string, t *text, a, b line) {
	start, end := min(a.n, b.n), max(a.n, b.n)
	title, how, fix := c.words("install-build", map[string]string{"file": p})
	lines := []string{a.s}
	if b.n != a.n {
		lines = append(lines, b.s)
	}
	c.add(Finding{
		Rule: RuleInstall, Title: title, File: p, Start: start, End: end, Snippet: t.snippet(start, end),
		How: how, Fix: fix, Fingerprint: fingerprint(RuleInstall, p, normalise(lines...)),
	})
}
