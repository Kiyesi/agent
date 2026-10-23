package cli

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/config"
	"github.com/kiyesi/kiyesi/agent/internal/fix"
	"github.com/kiyesi/kiyesi/agent/internal/keys"
	"github.com/kiyesi/kiyesi/agent/internal/render"
	"github.com/kiyesi/kiyesi/agent/internal/send"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// keysFS, keysWriter and keysAsRoot are the server as kiyesi keys sees it.
// Tests replace them.
var (
	keysFS                 = func() system.RootFS { return system.NewRootFS("/") }
	keysWriter keys.Writer = keys.RealWriter{}
	keysAsRoot             = func() bool { return os.Geteuid() == 0 }
	keysStore              = func() *fix.Store { return &fix.Store{Dir: fix.DefaultDir} }
)

func init() {
	// Undo of a key removal puts the lines back with the user's own rights.
	fix.RestoreKeys = func(ctx context.Context, k fix.KeyLines) error {
		return keysWriter.Edit(ctx, keys.Account{Name: k.User, UID: k.UID, GID: k.GID, Home: k.Home}, k.Path, nil, k.Lines)
	}
}

func newKeys(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "List who can sign in to this server with an SSH key, and remove a key",
		Long: "Lists every SSH key that opens this server, by account: its fingerprint,\n" +
			"type and comment, and when its file last changed. The keys themselves are never\n" +
			"shown or sent. On a connected server the same list feeds the dashboard's\n" +
			"Access map, which shows each key across all your servers.",
		Example: "  sudo kiyesi keys\n  sudo kiyesi keys remove SHA256:JQ6b…   # from every account on this server, after a yes",
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
			fmt.Fprintln(out, render.Grey("Remove one everywhere on this server: sudo kiyesi keys remove <KEY>"))
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the keys as JSON")
	cmd.AddCommand(newKeysRemove(io), newKeysEditOwn(io))
	return cmd
}

func newKeysRemove(io IO) *cobra.Command {
	var yes, asJSON bool
	var configPath string
	cmd := &cobra.Command{
		Use:   "remove <fingerprint>",
		Short: "Take one SSH key out of every account on this server, after a yes",
		Long: "Takes the key with this fingerprint out of every authorized_keys file on this\n" +
			"server, after saying where it is and asking. Each file is changed with its own\n" +
			"account's rights, and the lines are kept, so sudo kiyesi fix undo <id> puts\n" +
			"them back. The key you are signed in with is never the last one taken away.",
		Example: "  sudo kiyesi keys remove SHA256:JQ6bTs0Wp5uD9IhzbSPDx3VfmHmzSj0Ep0e2p8KQhXk",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fp := strings.TrimSpace(args[0])
			if !keys.ValidFingerprint(fp) {
				return usageErr("%q is not a key's fingerprint. They look like SHA256:JQ6bTs0Wp5uD9IhzbSPDx3VfmHmzSj0Ep0e2p8KQhXk; see them with sudo kiyesi keys", fp)
			}
			if !keysAsRoot() {
				return &exitError{code: ExitNoAccess, msg: "Run it with sudo: sudo kiyesi keys remove " + fp}
			}
			if asJSON && !yes {
				return usageErr("--json needs --yes, as nobody is there to answer")
			}
			if changesOff(configPath) {
				return &exitError{code: ExitNoAccess, msg: "Kiyesi does not change this server (fix: off in " + configPath + ").\n" +
					"Take the key out by hand: its lines are in the files sudo kiyesi keys lists."}
			}
			out := render.NewWriter(io.Out, io.Environ)
			fsys := keysFS()
			plan := keys.Plan(fsys, fp)
			if len(plan) == 0 {
				return &exitError{code: ExitUsage, msg: "No account on this server has the key " + fp + ". See the keys with: sudo kiyesi keys"}
			}
			me := sudoUser(io.Environ)
			if who, last := lastKeyOf(fsys, plan, me); last {
				return &exitError{code: ExitUsage, msg: fmt.Sprintf(
					"This is the only key %s signs in with here, so taking it away could lock you out.\n"+
						"Add the new key first (ssh-copy-id from your computer), then run this again.", who)}
			}
			var where []string
			for _, r := range plan {
				where = append(where, fmt.Sprintf("%s (%s)", r.Account.Name, r.Path))
			}
			label := fp
			if k, ok := keys.ParseLine(plan[0].Lines[0]); ok && k.Comment != "" {
				label = fp + " (" + k.Comment + ")"
			}
			if !asJSON {
				fmt.Fprintf(out, "\n  Takes the key %s out of:\n", label)
				for _, w := range where {
					fmt.Fprintf(out, "    %s\n", w)
				}
				fmt.Fprintln(out, render.Grey("  Whoever holds it can no longer sign in as these accounts. Sessions open now stay open."))
				fmt.Fprintln(out)
			}
			if !yes {
				if a := strings.ToLower(strings.TrimSpace(ask(io, "Remove it? [y/N] "))); a != "y" && a != "yes" {
					fmt.Fprintln(out, "Nothing changed.")
					return nil
				}
			}
			done := "Removed login key " + label + " from " + accountsOf(plan)
			store := keysStore()
			rec, err := store.Begin("keys", truncate(done, 280), me, true)
			if err != nil {
				return &exitError{code: ExitFindings, msg: "Nothing changed: the undo record could not be made: " + err.Error()}
			}
			ctx := cmd.Context()
			var failed []string
			for _, r := range plan {
				if err := keysWriter.Edit(ctx, r.Account, r.Path, r.Lines, nil); err != nil {
					failed = append(failed, err.Error())
					continue
				}
				rec.Keys = append(rec.Keys, fix.KeyLines{User: r.Account.Name, UID: r.Account.UID, GID: r.Account.GID, Home: r.Account.Home, Path: r.Path, Lines: r.Lines})
				if err := store.Save(rec); err != nil {
					failed = append(failed, "the undo record: "+err.Error())
				}
			}
			if len(rec.Keys) == 0 {
				return &exitError{code: ExitFindings, msg: "Not removed: " + strings.Join(failed, "; ")}
			}
			if asJSON {
				return render.JSON(io.Out, map[string]any{"removed": fp, "undo_id": rec.ID, "accounts": accountsOf(plan), "problems": failed})
			}
			fmt.Fprintf(out, "  %s %s%s\n", render.Green("✓"), rec.Done, render.Grey("  (undo: sudo kiyesi fix undo "+rec.ID+")"))
			for _, f := range failed {
				fmt.Fprintf(out, "  %s %s\n", render.Red("✗"), f)
			}
			// A connected server tells the dashboard now, not in 15 minutes.
			if _, _, err := loadConnection(); err == nil {
				now := time.Now()
				b := send.Items(now,
					send.Item{Kind: "fixed", At: now.UTC().Format(time.RFC3339), Fixed: &send.Fixed{ID: rec.ID, Fix: rec.Fix, Done: rec.Done, User: me}},
					send.Access(now, keys.Read(fsys)),
				)
				ob := send.Outbox{Dir: outboxDir(), MaxBytes: outboxBytes}
				if ob.Put(b, now) == nil {
					fmt.Fprintln(out, render.Grey("  The Access map shows it within a minute."))
				}
			}
			if len(failed) > 0 {
				return &exitError{code: ExitFindings}
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "remove without asking")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print what was removed as JSON (needs --yes)")
	cmd.Flags().StringVar(&configPath, "config", config.DefaultPath, "the settings file")
	return cmd
}

// newKeysEditOwn is the hidden helper kiyesi keys remove and its undo start
// as a user, to change that user's own file with that user's rights.
func newKeysEditOwn(io IO) *cobra.Command {
	return &cobra.Command{
		Use:    "edit-own",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			in := io.In
			if in == nil {
				in = os.Stdin
			}
			if err := keys.EditOwnFrom(in); err != nil {
				return &exitError{code: ExitUsage, msg: err.Error()}
			}
			return nil
		},
	}
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

func accountsOf(plan []keys.Removal) string {
	var names []string
	for _, r := range plan {
		names = append(names, r.Account.Name)
	}
	return strings.Join(names, ", ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
