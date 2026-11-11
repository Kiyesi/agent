package githook

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/pullcheck"
)

// Budget is the longest a push is checked for; the rules stop by
// themselves at the same time, and what was not read is said.
const Budget = pullcheck.Deadline

// maxStdin caps what git sends the hook: one line per ref pushed.
const maxStdin = 1 << 20

// maxDiff caps the change read from git, so a push of huge files is
// stopped reading in seconds, not minutes.
const maxDiff = 64 << 20

// Update is one line git sends a pre-push hook: a ref it is about to push.
type Update struct {
	LocalRef  string `json:"localRef"`
	LocalSHA  string `json:"localSha"`
	RemoteRef string `json:"remoteRef"`
	RemoteSHA string `json:"remoteSha"`
}

var hexSHA = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// ParseUpdates reads git's lines: <local ref> <local sha> <remote ref> <remote sha>.
func ParseUpdates(r io.Reader) ([]Update, error) {
	if r == nil {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(r, maxStdin+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxStdin {
		return nil, errors.New("git sent over 1 MB of refs")
	}
	var out []Update
	for _, l := range strings.Split(string(data), "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		if len(f) != 4 || !hexSHA.MatchString(f[1]) || !hexSHA.MatchString(f[3]) {
			return nil, fmt.Errorf("not a line git sends a pre-push hook: %q", l)
		}
		out = append(out, Update{LocalRef: f[0], LocalSHA: f[1], RemoteRef: f[2], RemoteSHA: f[3]})
	}
	return out, nil
}

// RefCheck is what was compared for one ref.
type RefCheck struct {
	Ref string `json:"ref"`
	// Base is the commit the push was compared with, or "" for none.
	Base  string `json:"base"`
	Files int    `json:"files"`
}

// Report is what a push's check found, across all its refs.
type Report struct {
	Remote   string              `json:"remote"`
	Refs     []RefCheck          `json:"refs"`
	Findings []pullcheck.Finding `json:"findings"`
	Skipped  []pullcheck.Skipped `json:"skipped"`
	Notes    []string            `json:"notes"`
	// Stop is true when a finding stops the push.
	Stop bool `json:"stop"`
}

func (r *Report) note(s string) {
	for _, n := range r.Notes {
		if n == s {
			return
		}
	}
	r.Notes = append(r.Notes, s)
}

func (r *Report) skip(s pullcheck.Skipped, seen map[string]bool) {
	k := s.Path + "\x00" + s.Why
	if !seen[k] {
		seen[k] = true
		r.Skipped = append(r.Skipped, s)
	}
}

// Stops says whether a finding stops a push: a malicious package, hidden
// code and lockfile tampering do; install scripts and workflow advice warn.
func Stops(f pullcheck.Finding) bool { return f.Conclusion == "failure" }

// CheckPush checks each ref a push sends with all five rules, the list at
// listPath, and nothing else: no account, no team settings. Deleted refs
// are not checked. A finding in several refs is listed once.
func CheckPush(ctx context.Context, dir, remote string, updates []Update, listPath string) Report {
	ctx, cancel := context.WithTimeout(ctx, Budget)
	defer cancel()
	rep := Report{Remote: remote}
	seen := map[string]bool{}
	skipped := map[string]bool{}
	for _, u := range updates {
		if isZero(u.LocalSHA) {
			continue
		}
		if ctx.Err() != nil {
			rep.note(fmt.Sprintf("%s was not checked: the check ran out of time.", short(u.LocalRef)))
			continue
		}
		base, note, err := baseOf(ctx, dir, remote, u)
		if err != nil {
			rep.note(fmt.Sprintf("%s was not checked: %v.", short(u.LocalRef), err))
			continue
		}
		if note != "" {
			rep.note(note)
		}
		rc := RefCheck{Ref: u.LocalRef, Base: base}
		if base == u.LocalSHA {
			rep.Refs = append(rep.Refs, rc)
			continue
		}
		files, skips, notes := changedFiles(ctx, dir, base, u.LocalSHA)
		for _, n := range notes {
			rep.note(n)
		}
		rc.Files = len(files) + len(skips)
		rep.Refs = append(rep.Refs, rc)
		for _, s := range skips {
			rep.skip(s, skipped)
		}
		// Dependency and workflow files first, by themselves: a push of
		// many big files that uses up the time never hides a malicious
		// package.
		var deps, rest []pullcheck.File
		for _, f := range files {
			if pullcheck.ReadWhole(f.Path) {
				deps = append(deps, f)
			} else {
				rest = append(rest, f)
			}
		}
		for _, part := range [][]pullcheck.File{deps, rest} {
			if len(part) == 0 {
				continue
			}
			out := pullcheck.Check(ctx, pullcheck.Input{List: listPath, Rules: pullcheck.Rules, Files: part})
			for _, s := range out.Skipped {
				rep.skip(s, skipped)
			}
			for _, n := range out.Notes {
				rep.note(n)
			}
			for _, f := range out.Findings {
				k := f.File + "\x00" + f.Fingerprint
				if seen[k] {
					continue
				}
				seen[k] = true
				rep.Findings = append(rep.Findings, f)
				if Stops(f) {
					rep.Stop = true
				}
			}
		}
	}
	if rep.Refs == nil {
		rep.Refs = []RefCheck{}
	}
	if rep.Findings == nil {
		rep.Findings = []pullcheck.Finding{}
	}
	if rep.Skipped == nil {
		rep.Skipped = []pullcheck.Skipped{}
	}
	if rep.Notes == nil {
		rep.Notes = []string{}
	}
	return rep
}

func short(ref string) string {
	for _, p := range []string{"refs/heads/", "refs/tags/"} {
		if strings.HasPrefix(ref, p) {
			return strings.TrimPrefix(ref, p)
		}
	}
	return ref
}

// baseOf is the commit a ref's push is compared with: the remote's commit
// when this clone has it (a push or a force push); for a new branch, where
// it leaves the remote's main branch; else the empty tree.
func baseOf(ctx context.Context, dir, remote string, u Update) (string, string, error) {
	if _, err := git(ctx, dir, "cat-file", "-e", u.LocalSHA+"^{commit}"); err != nil {
		return "", "", fmt.Errorf("this clone does not have %s", u.LocalSHA[:12])
	}
	if !isZero(u.RemoteSHA) {
		if _, err := git(ctx, dir, "cat-file", "-e", u.RemoteSHA+"^{commit}"); err == nil {
			return u.RemoteSHA, "", nil
		}
	}
	var heads []string
	if remote != "" && !strings.ContainsAny(remote, ":/\\ ") {
		heads = append(heads, "refs/remotes/"+remote+"/HEAD", "refs/remotes/"+remote+"/main", "refs/remotes/"+remote+"/master")
	}
	heads = append(heads, "refs/remotes/origin/HEAD", "refs/remotes/origin/main", "refs/remotes/origin/master")
	for _, h := range heads {
		if _, err := git(ctx, dir, "rev-parse", "--verify", "-q", h+"^{commit}"); err != nil {
			continue
		}
		mb, err := git(ctx, dir, "merge-base", h, u.LocalSHA)
		if err != nil || !hexSHA.MatchString(mb) {
			continue
		}
		note := ""
		if !isZero(u.RemoteSHA) {
			note = fmt.Sprintf("%s on the remote is at a commit this clone has not fetched, so the push was compared with %s.", short(u.RemoteRef), shortRemote(h))
		}
		return mb, note, nil
	}
	empty, err := git(ctx, dir, "hash-object", "-t", "tree", "--stdin")
	if err != nil {
		return "", "", err
	}
	return empty, fmt.Sprintf("%s shares no history with the remote's main branch, so all its files were checked, up to %d files and %d MB.", short(u.LocalRef), pullcheck.MaxFiles, pullcheck.MaxTotal>>20), nil
}

func shortRemote(ref string) string {
	return strings.TrimSuffix(strings.TrimPrefix(ref, "refs/remotes/"), "/HEAD")
}

// entry is one changed file, as git diff --raw says it.
type entry struct {
	oldMode, newMode string
	oldSHA, newSHA   string
	status           string
	path, previous   string
}

// diffArgs are the options both reads of a change share, so they list the
// same files.
func diffArgs(base, head string) []string {
	return []string{"--no-ext-diff", "--no-textconv", "--no-color", "-M", "--diff-filter=ACDMR", base, head}
}

// changedFiles reads a change as the service reads a pull request: every
// file's patch, and dependency and workflow files whole, before and after.
// It stops at 300 files and 5 MB, and says what it left out.
func changedFiles(ctx context.Context, dir, base, head string) ([]pullcheck.File, []pullcheck.Skipped, []string) {
	var skipped []pullcheck.Skipped
	var notes []string
	raw, err := git(ctx, dir, append([]string{"diff", "--raw", "-z", "--no-abbrev"}, diffArgs(base, head)...)...)
	if err != nil {
		return nil, nil, []string{"Kiyesi could not list the push's files: " + err.Error()}
	}
	entries := parseRaw(raw)
	if more := len(entries) - pullcheck.MaxFiles; more > 0 {
		entries = entries[:pullcheck.MaxFiles]
		skipped = append(skipped, pullcheck.Skipped{Path: plural(more, "more file") + " not listed", Why: "over the file limit"})
	}
	patches, full, err := readPatches(ctx, dir, base, head, len(entries))
	if err != nil {
		notes = append(notes, "Kiyesi could not read the push's changes: "+err.Error())
	}
	var want []string
	for _, e := range entries {
		if pullcheck.ReadWhole(e.path) {
			if e.status != "added" && e.oldSHA != "" {
				want = append(want, e.oldSHA)
			}
			if e.status != "removed" && e.newSHA != "" {
				want = append(want, e.newSHA)
			}
		}
	}
	blobs, err := readBlobs(ctx, dir, want)
	if err != nil {
		notes = append(notes, "Kiyesi could not read whole files, so dependency and workflow files were read from their changes only: "+err.Error())
	}
	var files []pullcheck.File
	used := 0
	stop := false
	for _, e := range entries {
		if stop {
			skipped = append(skipped, pullcheck.Skipped{Path: e.path, Why: "over the size limit"})
			continue
		}
		whole := pullcheck.ReadWhole(e.path)
		var was, is *string
		if whole {
			var big bool
			if e.status != "added" {
				was, big = blobs.get(e.oldSHA)
			}
			if e.status != "removed" {
				var b2 bool
				is, b2 = blobs.get(e.newSHA)
				big = big || b2
			}
			if big {
				skipped = append(skipped, pullcheck.Skipped{Path: e.path, Why: "over 1 MB"})
			}
		}
		p, ok := patches[header(e)]
		if !ok && full {
			skipped = append(skipped, pullcheck.Skipped{Path: e.path, Why: "over the size limit"})
			stop = true
			continue
		}
		size := len(p.text)
		if was != nil {
			size += len(*was)
		}
		if is != nil {
			size += len(*is)
		}
		if used+size > pullcheck.MaxTotal {
			stop = true
			skipped = append(skipped, pullcheck.Skipped{Path: e.path, Why: "over the size limit"})
			continue
		}
		used += size
		if p.over {
			skipped = append(skipped, pullcheck.Skipped{Path: e.path, Why: "over 1 MB"})
			continue
		}
		files = append(files, pullcheck.File{
			Path: e.path, Previous: e.previous, Status: e.status, Patch: p.text,
			Before: was, After: is, Binary: p.binary && !whole,
		})
	}
	return files, skipped, notes
}

func plural(n int, s string) string {
	if n == 1 {
		return "1 " + s
	}
	return strconv.Itoa(n) + " " + s + "s"
}

// parseRaw reads git diff --raw -z: ":old new oldsha newsha status\0path\0[path\0]".
func parseRaw(raw string) []entry {
	parts := strings.Split(raw, "\x00")
	var out []entry
	for i := 0; i < len(parts); i++ {
		meta := strings.TrimPrefix(parts[i], "\n")
		if !strings.HasPrefix(meta, ":") {
			continue
		}
		f := strings.Fields(meta[1:])
		if len(f) < 5 || i+1 >= len(parts) {
			break
		}
		e := entry{oldMode: f[0], newMode: f[1], oldSHA: f[2], newSHA: f[3]}
		if isZero(e.oldSHA) {
			e.oldSHA = ""
		}
		if isZero(e.newSHA) {
			e.newSHA = ""
		}
		code := f[4][:1]
		i++
		e.path = parts[i]
		switch code {
		case "R", "C":
			if i+1 >= len(parts) {
				return out
			}
			i++
			e.previous, e.path = e.path, parts[i]
			e.status = "renamed"
			if code == "C" {
				e.status, e.previous = "added", ""
			}
		case "A":
			e.status = "added"
		case "D":
			e.status = "removed"
		default:
			e.status = "modified"
		}
		// A submodule is a commit, not a file.
		if e.oldMode == "160000" || e.newMode == "160000" {
			continue
		}
		out = append(out, e)
	}
	return out
}

// header is the first line git diff prints for an entry.
func header(e entry) string {
	old := e.path
	if e.previous != "" {
		old = e.previous
	}
	return "diff --git " + quoteC("a/"+old) + " " + quoteC("b/"+e.path)
}

// quoteC quotes a path as git does with core.quotePath off.
func quoteC(s string) string {
	need := false
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f || c == '"' || c == '\\' {
			need = true
			break
		}
	}
	if !need {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\a':
			b.WriteString(`\a`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\v':
			b.WriteString(`\v`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			if c < 0x20 || c == 0x7f {
				fmt.Fprintf(&b, `\%03o`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// patch is one file's hunks.
type patch struct {
	text   string
	binary bool
	over   bool
}

// readPatches reads the change's patches, by each file's header line. full
// is true when the reading stopped at its cap: the files not read are over
// the size limit.
func readPatches(ctx context.Context, dir, base, head string, max int) (map[string]patch, bool, error) {
	out := map[string]patch{}
	// --text: a file the repository marks -diff or binary in
	// .gitattributes is still read; real binary files are told by their
	// NUL bytes, as the service's rules do.
	cmd := gitCmd(ctx, dir, append([]string{"diff", "-p", "-U3", "--text", "--src-prefix=a/", "--dst-prefix=b/"}, diffArgs(base, head)...)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return out, false, err
	}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		return out, false, err
	}
	r := bufio.NewReaderSize(stdout, 1<<16)
	var cur string
	var buf strings.Builder
	var p patch
	inHunks := false
	read := 0
	full := false
	flush := func() {
		if cur != "" {
			if !p.over {
				p.text = buf.String()
			}
			out[cur] = p
		}
		buf.Reset()
		p = patch{}
		inHunks = false
	}
	for {
		l, err := r.ReadString('\n')
		read += len(l)
		if read > maxDiff || len(out) > max {
			full = true
			cur = ""
			break
		}
		if l != "" {
			switch {
			case strings.HasPrefix(l, "diff --git "):
				flush()
				cur = strings.TrimRight(l, "\n")
			case !inHunks && strings.HasPrefix(l, "@@"):
				inHunks = true
				if strings.IndexByte(l, 0) >= 0 {
					p.binary = true
				} else {
					buf.WriteString(l)
				}
			case inHunks && p.binary:
			case inHunks && strings.IndexByte(l, 0) >= 0:
				p.binary = true
				buf.Reset()
			case inHunks:
				if !p.over {
					if buf.Len()+len(l) > pullcheck.MaxFile {
						p.over = true
						buf.Reset()
					} else {
						buf.WriteString(l)
					}
				}
			case strings.HasPrefix(l, "Binary files ") || strings.HasPrefix(l, "GIT binary patch"):
				p.binary = true
			}
		}
		if err != nil {
			break
		}
	}
	if !full {
		flush()
	}
	if full {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return out, true, nil
	}
	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return out, true, nil
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return out, false, errors.New(strings.TrimSpace(errb.String()))
		}
		return out, false, err
	}
	return out, false, nil
}

// blobSet is whole files by their blob id; a nil text with big set is
// over 1 MB.
type blobSet map[string]*blob

type blob struct {
	text *string
	big  bool
}

func (b blobSet) get(sha string) (*string, bool) {
	if sha == "" {
		return nil, false
	}
	v := b[sha]
	if v == nil {
		return nil, false
	}
	return v.text, v.big
}

// readBlobs reads files whole with one git cat-file --batch.
func readBlobs(ctx context.Context, dir string, shas []string) (blobSet, error) {
	out := blobSet{}
	if len(shas) == 0 {
		return out, nil
	}
	cmd := gitCmd(ctx, dir, "cat-file", "--batch")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return out, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return out, err
	}
	if err := cmd.Start(); err != nil {
		return out, err
	}
	go func() {
		w := bufio.NewWriter(stdin)
		for _, s := range shas {
			_, _ = w.WriteString(s + "\n")
		}
		_ = w.Flush()
		_ = stdin.Close()
	}()
	r := bufio.NewReaderSize(stdout, 1<<16)
	var rerr error
	for range shas {
		h, err := r.ReadString('\n')
		if err != nil {
			rerr = err
			break
		}
		f := strings.Fields(h)
		if len(f) != 3 {
			// "<sha> missing": not in this clone.
			continue
		}
		n, err := strconv.Atoi(f[2])
		if err != nil || n < 0 {
			rerr = errors.New("git cat-file said " + strings.TrimSpace(h))
			break
		}
		if f[1] != "blob" || n > pullcheck.MaxFile {
			if _, err := io.CopyN(io.Discard, r, int64(n)+1); err != nil {
				rerr = err
				break
			}
			if f[1] == "blob" {
				out[f[0]] = &blob{big: true}
			}
			continue
		}
		data := make([]byte, n+1)
		if _, err := io.ReadFull(r, data); err != nil {
			rerr = err
			break
		}
		s := string(data[:n])
		out[f[0]] = &blob{text: &s}
	}
	if rerr != nil {
		_ = cmd.Process.Kill()
	}
	_ = cmd.Wait()
	return out, rerr
}
