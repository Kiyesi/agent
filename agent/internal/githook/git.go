// Package githook is kiyesi's git pre-push hook: it installs and removes
// the hook in a repository, keeps a copy of the malicious-package list, and
// checks what a push adds with the pull-request rules (package pullcheck),
// on the developer's own machine.
//
// It runs git only as exec.Command("git", ...) with fixed arguments and no
// shell, and never runs anything from the repository: diffs are read with
// --no-ext-diff and --no-textconv, and core.fsmonitor is turned off.
package githook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// isZero says whether sha is git's name for no commit (a ref created or
// deleted), in either hash format.
func isZero(sha string) bool {
	return sha != "" && strings.Trim(sha, "0") == ""
}

// safe are the options every git command here runs with: nothing the
// repository's settings name is run, and diffs are printed the way they
// are read here, whatever the person's diff settings.
var safe = []string{
	"-c", "core.fsmonitor=false", "-c", "core.quotePath=false",
	"-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false", "-c", "diff.relative=false",
}

// gitCmd is one git command in dir, with the safe options first.
func gitCmd(ctx context.Context, dir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", append(append([]string{}, safe...), args...)...) // #nosec G204 -- git, a fixed program; the arguments are fixed words, commit names and paths, with no shell
	cmd.Dir = dir
	return cmd
}

// git runs one git command and returns its output, trimmed of the last
// line end.
func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := gitCmd(ctx, dir, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		var ee *exec.Error
		if errors.As(err, &ee) {
			return "", fmt.Errorf("git is not installed, or not on PATH: %w", err)
		}
		return "", fmt.Errorf("git %s: %s", args[0], msg)
	}
	return strings.TrimRight(out.String(), "\r\n"), nil
}
