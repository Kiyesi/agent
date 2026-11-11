package pullcheck

import (
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

var (
	commitRef = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)
	// The pull request's own code, as a workflow names it.
	headCode = regexp.MustCompile(`github\.event\.pull_request\.head\.(?:sha|ref|repo)|github\.head_ref|github\.event\.workflow_run\.head_(?:sha|branch|repository)|refs/pull/|github\.event\.pull_request\.merge_commit_sha|github\.event\.number`)
	gitFetch = regexp.MustCompile(`\bgit\s+(?:checkout|fetch|switch|pull|worktree\s+add)\b`)
	prFetch  = regexp.MustCompile(`\bgh\s+pr\s+checkout\b`)
	// Secrets, as a step's script names them.
	secretExpr = regexp.MustCompile(`\$\{\{\s*secrets\.[A-Za-z0-9_-]+\s*\}\}`)
	allSecrets = regexp.MustCompile(`(?i)toJSON\(\s*secrets\s*\)`)
	printCmd   = regexp.MustCompile(`(?i)^(?:echo|printf|cat|printenv|write-host|write-output|print|puts|console\.log)\b`)
	envDump    = regexp.MustCompile(`(?i)^(?:env|printenv|export\s+-p|set|declare\s+-p|compgen\s+-v|(?:get-childitem|gci|dir|ls)\s+env:)\s*(?:\|\s*(?:sort|base64|tee|cat|less|grep)\b.*)?$`)
	xtrace     = regexp.MustCompile(`^set\s+-[a-wyz]*x|^set\s+-o\s+xtrace\b|^(?:bash|sh)\s+-[a-wyz]*x\b`)
	// Commands a secret may be piped to without being shown.
	showingPipe = regexp.MustCompile(`^(?:base64|xxd|od|rev|hexdump|tee|sed|tr|awk|cat)\b`)
	segments    = regexp.MustCompile(`&&|\|\||;`)
)

// workflow finds risky steps the change adds to a GitHub Actions workflow:
// the same rules run on the file before, and only what is new is kept.
func (c *checker) workflow(f File, p string, t *text) {
	after, ok := c.workflowFindings(p, *f.After, t)
	if !ok {
		c.note(fmt.Sprintf("%s is not valid YAML, so its workflow rules were not checked.", p))
		return
	}
	old := map[string]bool{}
	if f.Before != nil {
		bt := &text{hasAfter: true}
		bt.after = bt.split(*f.Before)
		before, _ := c.workflowFindings(p, *f.Before, bt)
		for _, b := range before {
			old[b.Fingerprint] = true
		}
	}
	for _, a := range after {
		if !old[a.Fingerprint] {
			c.add(a)
		}
	}
}

// node follows an alias to what it names.
func node(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < 10; i++ {
		n = n.Alias
	}
	return n
}

// get is a mapping's value for a key, or nil.
func get(n *yaml.Node, key string) *yaml.Node {
	n = node(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if node(n.Content[i]).Value == key {
			return node(n.Content[i+1])
		}
	}
	return nil
}

// items are a sequence's items, or a mapping's values.
func items(n *yaml.Node) []*yaml.Node {
	n = node(n)
	if n == nil {
		return nil
	}
	var out []*yaml.Node
	switch n.Kind {
	case yaml.SequenceNode:
		for _, x := range n.Content {
			out = append(out, node(x))
		}
	case yaml.MappingNode:
		for i := 1; i < len(n.Content); i += 2 {
			out = append(out, node(n.Content[i]))
		}
	}
	return out
}

// triggers are the events a workflow runs on.
func triggers(n *yaml.Node) []string {
	n = node(n)
	if n == nil {
		return nil
	}
	var out []string
	switch n.Kind {
	case yaml.ScalarNode:
		out = append(out, n.Value)
	case yaml.SequenceNode:
		for _, x := range n.Content {
			out = append(out, node(x).Value)
		}
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			out = append(out, node(n.Content[i]).Value)
		}
	}
	return out
}

// secretNames are the env names whose values are secrets.
func secretNames(names map[string]bool, env *yaml.Node) map[string]bool {
	out := map[string]bool{}
	for k := range names {
		out[k] = true
	}
	env = node(env)
	if env == nil || env.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(env.Content); i += 2 {
		if strings.Contains(node(env.Content[i+1]).Value, "secrets.") {
			out[node(env.Content[i]).Value] = true
		}
	}
	return out
}

// workflowFindings are a workflow's risky parts. ok is false when the
// file is not YAML.
func (c *checker) workflowFindings(p, s string, t *text) ([]Finding, bool) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(s), &doc); err != nil {
		return nil, false
	}
	if len(doc.Content) == 0 {
		return nil, true
	}
	root := node(doc.Content[0])
	var out []Finding
	add := func(kind string, n int, vars map[string]string, lines ...string) {
		vars["file"] = p
		title, how, fix := c.words(kind, vars)
		out = append(out, Finding{
			Rule: RuleWorkflow, Title: title, File: p, Start: n, End: n, Snippet: t.snippet(n, n),
			How: how, Fix: fix, Fingerprint: fingerprint(RuleWorkflow, p, normalise(lines...)),
		})
	}
	untrusted := ""
	for _, tr := range triggers(get(root, "on")) {
		if tr == "pull_request_target" || tr == "workflow_run" {
			untrusted = tr
			break
		}
	}
	for _, m := range allSecretsLines(t) {
		add("workflow-secret", m.n, map[string]string{}, m.s)
	}
	workflowSecrets := secretNames(nil, get(root, "env"))
	for _, job := range items(get(root, "jobs")) {
		c.unpinned(get(job, "uses"), add)
		jobSecrets := secretNames(workflowSecrets, get(job, "env"))
		for _, step := range items(get(job, "steps")) {
			uses := get(step, "uses")
			c.unpinned(uses, add)
			if untrusted != "" && uses != nil && strings.HasPrefix(strings.ToLower(uses.Value), "actions/checkout") {
				if ref := get(get(step, "with"), "ref"); ref != nil && headCode.MatchString(ref.Value) {
					add("workflow-untrusted", ref.Line, map[string]string{"trigger": untrusted}, "on: "+untrusted, "ref: "+ref.Value)
				}
			}
			run := get(step, "run")
			if run == nil || run.Kind != yaml.ScalarNode {
				continue
			}
			names := secretNames(jobSecrets, get(step, "env"))
			c.script(run, names, untrusted, t, add)
		}
	}
	return out, true
}

type addFunc func(kind string, n int, vars map[string]string, lines ...string)

// unpinned flags an action used by a tag or branch. Local actions, images
// pinned by digest and GitHub's own actions are fine.
func (c *checker) unpinned(uses *yaml.Node, add addFunc) {
	if uses == nil || uses.Kind != yaml.ScalarNode {
		return
	}
	v := strings.TrimSpace(uses.Value)
	if v == "" || strings.HasPrefix(v, "./") {
		return
	}
	repo, ref, _ := strings.Cut(v, "@")
	if strings.HasPrefix(v, "docker://") {
		if strings.Contains(v, "@sha256:") {
			return
		}
		img := strings.TrimPrefix(v, "docker://")
		repo, ref = v, ""
		if i := strings.LastIndex(img, ":"); i > strings.LastIndex(img, "/") {
			repo, ref = "docker://"+img[:i], img[i+1:]
		}
	} else {
		if commitRef.MatchString(ref) {
			return
		}
		owner, _, _ := strings.Cut(repo, "/")
		for _, o := range c.data.GitHubOwners {
			if strings.EqualFold(owner, o) {
				return
			}
		}
	}
	if ref == "" {
		ref = "latest"
	}
	add("workflow-unpinned", uses.Line, map[string]string{"action": v, "repo": repo, "ref": ref}, "uses: "+v)
}

// script reads a step's run lines: a checkout of the pull request's code
// in an untrusted workflow, and lines that print secrets.
func (c *checker) script(run *yaml.Node, names map[string]bool, untrusted string, t *text, add addFunc) {
	var nameRef *regexp.Regexp
	if len(names) > 0 {
		var alts []string
		for n := range names {
			alts = append(alts, regexp.QuoteMeta(n))
		}
		nameRef = regexp.MustCompile(`\$\{?(?:` + strings.Join(alts, "|") + `)\b|\$env:(?:` + strings.Join(alts, "|") + `)\b`)
	}
	hasSecrets := len(names) > 0 || strings.Contains(run.Value, "secrets.")
	from := run.Line
	for _, l := range strings.Split(run.Value, "\n") {
		l = strings.TrimSpace(cutAt(l, MaxLine))
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		n := t.lineWith(cutAt(l, 200), from)
		if n == 0 {
			n = run.Line
		} else {
			from = n
		}
		if untrusted != "" && ((gitFetch.MatchString(l) && headCode.MatchString(l)) || prFetch.MatchString(l)) {
			add("workflow-untrusted", n, map[string]string{"trigger": untrusted}, "on: "+untrusted, l)
			continue
		}
		switch {
		case printsSecret(l, nameRef):
		case hasSecrets && len(names) > 0 && envDump.MatchString(l):
		case hasSecrets && xtrace.MatchString(l):
		default:
			continue
		}
		add("workflow-secret", n, map[string]string{}, l)
	}
}

// printsSecret says a line shows a secret in the log: printed as it is,
// or through a pipe that only changes how it looks. Piped into another
// command, or written to a file, it is not shown.
func printsSecret(l string, nameRef *regexp.Regexp) bool {
	if strings.Contains(l, "::add-mask::") {
		return false
	}
	for _, seg := range segments.Split(l, -1) {
		seg = strings.TrimSpace(seg)
		if !printCmd.MatchString(seg) {
			continue
		}
		cmd, pipe, piped := strings.Cut(seg, "|")
		if !secretExpr.MatchString(cmd) && (nameRef == nil || !nameRef.MatchString(cmd)) {
			continue
		}
		if piped {
			if showingPipe.MatchString(strings.TrimSpace(pipe)) {
				return true
			}
			continue
		}
		if i := strings.Index(cmd, ">"); i >= 0 && !strings.HasPrefix(cmd[i:], ">&") {
			if strings.Contains(cmd[i:], "GITHUB_STEP_SUMMARY") {
				return true
			}
			continue
		}
		return true
	}
	return false
}

// allSecretsLines are the lines that hand every secret to a step at once.
func allSecretsLines(t *text) []line {
	var out []line
	for i, l := range t.after {
		if allSecrets.MatchString(l) {
			out = append(out, line{i + 1, l})
		}
	}
	return out
}
