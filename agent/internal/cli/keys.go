package cli

import (
	"fmt"
	"io/fs"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/config"
	"github.com/kiyesi/kiyesi/agent/internal/keys"
	"github.com/kiyesi/kiyesi/agent/internal/render"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// keysFS and keysAsRoot are the server as kiyesi keys sees it. Tests
// replace them.
var (
	keysFS     = func() system.RootFS { return system.NewRootFS("/") }
	keysAsRoot = func() bool { return os.Geteuid() == 0 }
)

func newKeys(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "List who can sign in to this server with an SSH key, and how to take one out",
		Long: "Lists every SSH key that opens this server, by account: its fingerprint,\n" +
			"type and comment, and when its file last changed. The keys themselves are never\n" +
			"shown or sent. On a connected server the same list feeds the dashboard's\n" +
			"Access map, which shows each key across all your servers.",
		Example: "  sudo kiyesi keys\n  sudo kiyesi keys remove SHA256:JQ6b…   # where it is, and the commands to take it out",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if !keysAsRoot() {
				return &exitError{code: ExitNoAccess, msg: "Run it with sudo: sudo kiyesi keys\nOther accounts' keys can be read only by root."}
			}
			ks := keys.Read(keysFS())
			if asJSON {
				return jsonOut(io.Out, ks)
			}
			if len(ks) == 0 {
				fmt.Fprintln(io.Out, "No SSH keys open this server.")
				return nil
			}
			w := tabwriter.NewWriter(io.Out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ACCOUNT\tKEY\tTYPE\tCOMMENT\tFILE CHANGED")
			for _, k := range ks {
				comment := k.Comment
				if k.Restricted {
					comment = strings.TrimSpace(comment + " (limited)")
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", k.User, k.Fingerprint, strings.TrimPrefix(k.Type, "ssh-"), comment, k.ChangedAt.Local().Format("2 Jan 2006"))
			}
			if err := w.Flush(); err != nil {
				return err
			}
			out := render.NewWriter(io.Out, io.Environ)
			fmt.Fprintln(out)
			fmt.Fprintln(out, render.Grey("How to take one out, everywhere on this server: sudo kiyesi keys remove <KEY>"))
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the keys as JSON")
	cmd.AddCommand(newKeysRemove(io))
	return cmd
}

func newKeysRemove(io IO) *cobra.Command {
	var yes, asJSON bool
	var configPath string
	cmd := &cobra.Command{
		Use:   "remove <fingerprint>",
		Short: "Show where one SSH key is on this server, and the commands to take it out",
		Long: "Finds the key with this fingerprint in every authorized_keys file on this\n" +
			"server and prints, for each file, the command that takes its line out, for\n" +
			"you to review and run. Kiyesi changes nothing. It warns when the key is the\n" +
			"last one you sign in with.",
		Example: "  sudo kiyesi keys remove SHA256:JQ6bTs0Wp5uD9IhzbSPDx3VfmHmzSj0Ep0e2p8KQhXk",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fp := strings.TrimSpace(args[0])
			if !keys.ValidFingerprint(fp) {
				return usageErr("%q is not a key's fingerprint. They look like SHA256:JQ6bTs0Wp5uD9IhzbSPDx3VfmHmzSj0Ep0e2p8KQhXk; see them with sudo kiyesi keys", fp)
			}
			if !keysAsRoot() {
				return &exitError{code: ExitNoAccess, msg: "Run it with sudo, so every account's keys can be read: sudo kiyesi keys remove " + fp}
			}
			fsys := keysFS()
			plan := keys.Plan(fsys, fp)
			if len(plan) == 0 {
				return &exitError{code: ExitUsage, msg: "No account on this server has the key " + fp + ". See the keys with: sudo kiyesi keys"}
			}
			label := fp
			if k, ok := keys.ParseLine(plan[0].Lines[0]); ok && k.Comment != "" {
				label = fp + " (" + k.Comment + ")"
			}
			type step struct {
				Account string `json:"account"`
				File    string `json:"file"`
				Command string `json:"command"`
			}
			var steps []step
			for _, r := range plan {
				for _, line := range r.Lines {
					steps = append(steps, step{Account: r.Account.Name, File: r.Path, Command: removeLineCommand(line, r.Path)})
				}
			}
			me := sudoUser(io.Environ)
			who, last := lastKeyOf(fsys, plan, me)
			if asJSON {
				return render.JSON(io.Out, map[string]any{"changed": false, "key": fp, "last_key_of": map[bool]string{true: who}[last], "steps": steps})
			}
			out := render.NewWriter(io.Out, io.Environ)
			fmt.Fprintln(out)
			fmt.Fprintln(out, render.Bold("Kiyesi changes nothing on this server.")+" "+neverRuns)
			fmt.Fprintf(out, "\nThe key %s opens:\n", label)
			for _, st := range steps {
				fmt.Fprintf(out, "  %s (%s)\n", st.Account, st.File)
			}
			if last {
				fmt.Fprintf(out, "\n%s It is the only key %s signs in with here: add your new key first (ssh-copy-id from your computer), or you could lock yourself out.\n", render.Amber("Careful."), who)
			}
			fmt.Fprintln(out, "\nTo take it out, review and run:")
			for _, st := range steps {
				fmt.Fprintf(out, "  %s\n", st.Command)
			}
			fmt.Fprintln(out)
			fmt.Fprintln(out, render.Grey("Whoever holds the key can no longer sign in as these accounts. Sessions open now stay open."))
			return nil
		},
	}
	// Kept so scripts written before 0.40.0 still run; they change nothing now.
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "ignored: Kiyesi never changes anything")
	_ = cmd.Flags().MarkHidden("yes")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print where the key is, and the commands, as JSON")
	cmd.Flags().StringVar(&configPath, "config", config.DefaultPath, "the settings file")
	return cmd
}

// removeLineCommand is the command that takes one key's line out of an
// authorized_keys file, matched by the key itself: the long base64 part,
// which holds no | and is the same in no other key.
func removeLineCommand(line, path string) string {
	body := ""
	for _, f := range strings.Fields(line) {
		if strings.HasPrefix(f, "AAAA") {
			body = f
			break
		}
	}
	if body == "" {
		return "sudo nano " + path + "   (delete the line with this key)"
	}
	return "sudo sed -i '\\|" + body + "|d' " + path
}

// sudoUser is who ran sudo, or root.
func sudoUser(environ []string) string {
	for _, e := range environ {
		if v, ok := strings.CutPrefix(e, "SUDO_USER="); ok && v != "" {
			return v
		}
	}
	return "root"
}

// lastKeyOf says whether the removal would leave the person running it
// with no key to sign in with.
func lastKeyOf(fsys fs.FS, plan []keys.Removal, me string) (string, bool) {
	have, losing := 0, 0
	for _, k := range keys.Read(fsys) {
		if k.User == me {
			have++
		}
	}
	for _, r := range plan {
		if r.Account.Name == me {
			losing += len(r.Lines)
		}
	}
	return me, losing > 0 && have <= losing
}
