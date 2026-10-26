package fix

import (
	"fmt"
	"strings"
)

// UndoCommands are the commands that put one earlier change back, newest
// first, for a person to review and run: Kiyesi runs none of them. A file
// the change added is removed; one it rewrote is written back as it was,
// with its mode; a mode it changed is set back; key lines it took out are
// added back to their files; then the record's own steps, such as
// reloading SSH. notes say what to check first.
func UndoCommands(r *Record) (cmds, notes []string) {
	for i := len(r.Files) - 1; i >= 0; i-- {
		f := r.Files[i]
		switch {
		case f.ModeOnly:
			cmds = append(cmds, fmt.Sprintf("sudo chmod %04o %s", f.Mode.Perm(), shellWord(f.Path)))
			notes = append(notes, "Check "+f.Path+" is still the file you expect (ls -l "+shellWord(f.Path)+") before you set its mode back.")
		case !f.Existed:
			cmds = append(cmds, "sudo rm -f "+shellWord(f.Path))
		default:
			end := "KIYESI_EOF"
			for strings.Contains(string(f.Content), end) {
				end += "_"
			}
			cmds = append(cmds,
				fmt.Sprintf("sudo tee %s >/dev/null <<'%s'\n%s%s", shellWord(f.Path), end, withNewline(string(f.Content)), end),
				fmt.Sprintf("sudo chmod %04o %s", f.Mode.Perm(), shellWord(f.Path)))
		}
	}
	for _, k := range r.Keys {
		for _, line := range k.Lines {
			cmds = append(cmds, "echo "+shellWord(line)+" | sudo tee -a "+shellWord(k.Path)+" >/dev/null")
		}
	}
	for _, c := range r.Then {
		var words []string
		for _, w := range c {
			words = append(words, shellWord(w))
		}
		if len(words) > 0 {
			cmds = append(cmds, "sudo "+strings.Join(words, " "))
		}
	}
	return cmds, notes
}

func withNewline(s string) string {
	if s == "" || strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

// shellWord quotes a word for a shell only when it needs it.
func shellWord(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-@:+=,") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
