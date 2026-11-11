package githook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Marker is the line that says a pre-push hook is Kiyesi's.
const Marker = "# Kiyesi pre-push hook."

// PreviousName is where an earlier pre-push hook is kept, beside Kiyesi's,
// which runs it after its own check. git never runs it by this name.
const PreviousName = "pre-push.kiyesi-previous"

// TeamLine is the line to add to a pre-push hook the team keeps in the
// repository: it checks the push when kiyesi is installed, stops it only
// for a stopping finding, and does nothing on a teammate's machine without
// kiyesi. It works under sh -e, as Husky runs hooks.
const TeamLine = `if command -v kiyesi >/dev/null 2>&1; then kiyesi hook run "$@" || [ $? -ne 1 ] || exit 1; fi`

// Repo is where a repository's hooks are.
type Repo struct {
	// Top is the working tree's top folder.
	Top string `json:"top"`
	// Hooks is the folder git runs hooks from.
	Hooks string `json:"hooks"`
	// HooksPath is core.hooksPath as set, or "".
	HooksPath string `json:"hooksPath,omitempty"`
	// Team is true when the hooks folder is inside the working tree (as
	// Husky sets it): the team's files, which Kiyesi does not edit.
	Team bool `json:"team"`
	// Shared is true when core.hooksPath names a folder outside the
	// repository, such as a global hooks folder other repositories use too.
	Shared bool `json:"shared"`
	// TeamHook is the file to add TeamLine to, when Team.
	TeamHook string `json:"teamHook,omitempty"`
}

// Locate finds the repository dir is in, and its hooks folder. It works in
// worktrees and submodules, as git itself says where their hooks are.
func Locate(ctx context.Context, dir string) (Repo, error) {
	var r Repo
	top, err := git(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return r, fmt.Errorf("%s is not in a git repository with a working tree (%v)", dir, err)
	}
	r.Top = realPath(filepath.FromSlash(top))
	hp, _ := git(ctx, dir, "config", "--get", "core.hooksPath")
	r.HooksPath = hp
	if hp != "" {
		p := hp
		if p == "~" || strings.HasPrefix(p, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				p = filepath.Join(home, strings.TrimPrefix(p[1:], "/"))
			}
		}
		p = filepath.FromSlash(p)
		if !filepath.IsAbs(p) {
			// git runs hooks from the working tree's top.
			p = filepath.Join(r.Top, p)
		}
		r.Hooks = realPath(p)
	} else {
		h, err := git(ctx, dir, "rev-parse", "--git-path", "hooks")
		if err != nil {
			return r, err
		}
		h = filepath.FromSlash(h)
		if !filepath.IsAbs(h) {
			h = filepath.Join(dir, h)
		}
		r.Hooks = realPath(h)
	}
	if hp != "" {
		if inside(r.Top, r.Hooks) {
			r.Team = true
			r.TeamHook = filepath.Join(r.Hooks, "pre-push")
			// Husky 9 runs .husky/_/pre-push, which runs .husky/pre-push.
			if filepath.Base(r.Hooks) == "_" && filepath.Base(filepath.Dir(r.Hooks)) == ".husky" {
				r.TeamHook = filepath.Join(filepath.Dir(r.Hooks), "pre-push")
			}
		} else {
			r.Shared = true
		}
	}
	return r, nil
}

// realPath is p with symbolic links resolved where it exists, so paths
// compare as git sees them (macOS's /var is /private/var).
func realPath(p string) string {
	abs, err := filepath.Abs(p)
	if err == nil {
		p = abs
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	// A folder not made yet: resolve its parent.
	if r, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		return filepath.Join(r, filepath.Base(p))
	}
	return p
}

func inside(top, p string) bool {
	rel, err := filepath.Rel(top, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// Script is the pre-push hook, a POSIX sh script with LF line ends that
// Git for Windows' sh runs too. It runs kiyesi from where it was when the
// hook was installed, else from PATH, with git's arguments and what git
// sends on stdin; then the earlier hook, if there was one, with the same
// arguments and the same stdin. A push stops only when kiyesi says so
// (exit 1): Kiyesi's own trouble never stops a push.
func Script(kiyesiPath string) string {
	lines := []string{
		"#!/bin/sh",
		Marker + " kiyesi hook install wrote it; kiyesi hook uninstall removes it.",
		"# It checks what a push adds with the rules of Kiyesi's pull-request check.",
		"# To push without the check: git push --no-verify",
		"kiyesi=" + shQuote(shPath(kiyesiPath)),
		`if [ ! -x "$kiyesi" ]; then`,
		`	kiyesi=$(command -v kiyesi 2>/dev/null) || kiyesi=`,
		`fi`,
		`previous="$(dirname "$0")/` + PreviousName + `"`,
		`input=`,
		`if [ -f "$previous" ]; then`,
		`	input=$(mktemp 2>/dev/null || mktemp -t kiyesi) || exit 1`,
		`	trap 'rm -f "$input"' EXIT`,
		`	trap 'exit 1' HUP INT TERM`,
		`	cat >"$input"`,
		`fi`,
		`if [ -n "$kiyesi" ]; then`,
		`	if [ -n "$input" ]; then`,
		`		"$kiyesi" hook run "$@" <"$input"`,
		`	else`,
		`		"$kiyesi" hook run "$@"`,
		`	fi`,
		`	[ $? -ne 1 ] || exit 1`,
		`else`,
		`	echo "kiyesi was not found, so Kiyesi did not check this push. To remove its hook: kiyesi hook uninstall" >&2`,
		`fi`,
		`if [ -n "$input" ] && [ -x "$previous" ]; then`,
		`	"$previous" "$@" <"$input"`,
		`	exit $?`,
		`fi`,
		`exit 0`,
	}
	return strings.Join(lines, "\n") + "\n"
}

var winDrive = regexp.MustCompile(`^[A-Za-z]:\\`)

// shPath is a path as Git for Windows' sh reads it: C:\x\kiyesi.exe as
// C:/x/kiyesi.exe. Elsewhere a backslash is part of a name, and kept.
func shPath(p string) string {
	if filepath.Separator == '\\' || winDrive.MatchString(p) {
		return strings.ReplaceAll(p, `\`, "/")
	}
	return p
}

// shQuote puts s in single quotes for sh.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// recordedKiyesi reads the kiyesi path back from a hook Script wrote.
func recordedKiyesi(script []byte) string {
	for _, l := range strings.Split(string(script), "\n") {
		if !strings.HasPrefix(l, "kiyesi='") {
			continue
		}
		v := strings.TrimPrefix(l, "kiyesi=")
		v = strings.TrimSuffix(strings.TrimPrefix(v, "'"), "'")
		return filepath.FromSlash(strings.ReplaceAll(v, `'\''`, "'"))
	}
	return ""
}

// IsKiyesis says whether a hook file's text is Kiyesi's hook.
func IsKiyesis(script []byte) bool {
	return bytes.Contains(script, []byte("\n"+Marker))
}

// Result is what install or uninstall did.
type Result struct {
	Repo Repo `json:"repo"`
	// Action is installed, updated, unchanged, team (nothing edited: add
	// Line to Repo.TeamHook), removed or absent.
	Action string `json:"action"`
	Hook   string `json:"hook"`
	// Previous is the earlier hook Kiyesi's runs after its own check, or
	// the one put back by uninstall.
	Previous string `json:"previous,omitempty"`
	Line     string `json:"line,omitempty"`
	// LinePresent is true when the team's hook already runs kiyesi.
	LinePresent bool `json:"linePresent,omitempty"`
}

// Install writes Kiyesi's pre-push hook in the repository dir is in, to run
// the kiyesi at kiyesiPath. An earlier hook is moved beside it and run
// after it. Installing again only refreshes Kiyesi's hook. A hooks folder
// in the working tree is the team's: nothing is edited, and the result
// carries the line to add.
func Install(ctx context.Context, dir, kiyesiPath string) (Result, error) {
	r, err := Locate(ctx, dir)
	if err != nil {
		return Result{}, err
	}
	res := Result{Repo: r, Hook: filepath.Join(r.Hooks, "pre-push")}
	if r.Team {
		res.Action, res.Line, res.Hook = "team", TeamLine, r.TeamHook
		res.LinePresent = teamHasLine(r.TeamHook)
		return res, nil
	}
	if strings.ContainsAny(kiyesiPath, "\r\n") {
		return res, fmt.Errorf("kiyesi's path has a line break in it: %q", kiyesiPath)
	}
	if err := os.MkdirAll(r.Hooks, 0o750); err != nil {
		return res, fmt.Errorf("making the hooks folder: %w", err)
	}
	want := []byte(Script(kiyesiPath))
	prev := filepath.Join(r.Hooks, PreviousName)
	if _, err := os.Lstat(prev); err == nil {
		res.Previous = prev
	}
	cur, err := os.ReadFile(res.Hook) // #nosec G304 -- the repository's own pre-push hook, only read
	switch {
	case errors.Is(err, os.ErrNotExist):
		if _, lerr := os.Lstat(res.Hook); lerr == nil {
			// A link to a file that is gone: keep it as the earlier hook.
			if err := keepPrevious(res.Hook, prev, res.Previous); err != nil {
				return res, err
			}
			res.Previous = prev
		}
		res.Action = "installed"
	case err != nil:
		return res, fmt.Errorf("reading %s: %w", res.Hook, err)
	case IsKiyesis(cur):
		if bytes.Equal(cur, want) {
			res.Action = "unchanged"
			return res, nil
		}
		res.Action = "updated"
	default:
		if err := keepPrevious(res.Hook, prev, res.Previous); err != nil {
			return res, err
		}
		res.Previous = prev
		res.Action = "installed"
	}
	if err := writeExecutable(res.Hook, want); err != nil {
		return res, err
	}
	return res, nil
}

// keepPrevious moves an earlier hook aside, unchanged (its bytes and its
// mode), unless one is kept there already.
func keepPrevious(hook, prev, existing string) error {
	if existing != "" {
		return fmt.Errorf("%s is not Kiyesi's, and %s already holds an earlier hook: move or delete one of them, then run kiyesi hook install again", hook, prev)
	}
	if err := os.Rename(hook, prev); err != nil {
		return fmt.Errorf("moving the earlier hook aside: %w", err)
	}
	return nil
}

// writeExecutable replaces path with data, readable and runnable, in one
// step: a push at the same moment sees the old hook or the new, never half.
func writeExecutable(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pre-push.kiyesi-*")
	if err != nil {
		return fmt.Errorf("writing the hook: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name) // #nosec G104 -- gone already after the rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing the hook: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing the hook: %w", err)
	}
	// #nosec G302 -- a git hook must be runnable; it holds no secret
	if err := os.Chmod(name, 0o755); err != nil {
		return fmt.Errorf("making the hook runnable: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("writing the hook: %w", err)
	}
	return nil
}

func teamHasLine(file string) bool {
	b, err := os.ReadFile(file) // #nosec G304 -- the team's hook, only read
	return err == nil && bytes.Contains(b, []byte("kiyesi hook run"))
}

// Uninstall removes Kiyesi's hook and puts the earlier one back exactly as
// it was. It removes nothing that is not Kiyesi's.
func Uninstall(ctx context.Context, dir string) (Result, error) {
	r, err := Locate(ctx, dir)
	if err != nil {
		return Result{}, err
	}
	res := Result{Repo: r, Hook: filepath.Join(r.Hooks, "pre-push")}
	if r.Team {
		res.Action, res.Line, res.Hook = "team", TeamLine, r.TeamHook
		res.LinePresent = teamHasLine(r.TeamHook)
		return res, nil
	}
	cur, err := os.ReadFile(res.Hook) // #nosec G304 -- the repository's own pre-push hook, only read
	if err != nil || !IsKiyesis(cur) {
		res.Action = "absent"
		return res, nil
	}
	if err := os.Remove(res.Hook); err != nil {
		return res, fmt.Errorf("removing Kiyesi's hook: %w", err)
	}
	res.Action = "removed"
	prev := filepath.Join(r.Hooks, PreviousName)
	if _, err := os.Lstat(prev); err == nil {
		if err := os.Rename(prev, res.Hook); err != nil {
			return res, fmt.Errorf("putting the earlier hook back: %w", err)
		}
		res.Previous = res.Hook
	}
	return res, nil
}

// HookStatus is whether Kiyesi's hook is in a repository.
type HookStatus struct {
	Repo      Repo   `json:"repo"`
	Installed bool   `json:"installed"`
	Hook      string `json:"hook"`
	// Previous is the earlier hook run after Kiyesi's, or "".
	Previous string `json:"previous,omitempty"`
	// Kiyesi is the kiyesi the hook runs, as recorded when it was installed.
	Kiyesi      string `json:"kiyesi,omitempty"`
	KiyesiFound bool   `json:"kiyesiFound"`
	// Line is the line for a team's hook; LinePresent says it is there.
	Line        string `json:"line,omitempty"`
	LinePresent bool   `json:"linePresent,omitempty"`
}

// Status says whether Kiyesi's hook is installed in the repository dir is in.
func Status(ctx context.Context, dir string) (HookStatus, error) {
	r, err := Locate(ctx, dir)
	if err != nil {
		return HookStatus{}, err
	}
	s := HookStatus{Repo: r, Hook: filepath.Join(r.Hooks, "pre-push")}
	if r.Team {
		s.Hook, s.Line = r.TeamHook, TeamLine
		s.LinePresent = teamHasLine(r.TeamHook)
		s.Installed = s.LinePresent
		return s, nil
	}
	cur, err := os.ReadFile(s.Hook) // #nosec G304 -- the repository's own pre-push hook, only read
	if err != nil || !IsKiyesis(cur) {
		return s, nil
	}
	s.Installed = true
	s.Kiyesi = recordedKiyesi(cur)
	if st, err := os.Stat(s.Kiyesi); err == nil && !st.IsDir() { // #nosec G703 -- only asks whether the kiyesi the hook names is there
		s.KiyesiFound = true
	}
	prev := filepath.Join(r.Hooks, PreviousName)
	if _, err := os.Lstat(prev); err == nil {
		s.Previous = prev
	}
	return s, nil
}
