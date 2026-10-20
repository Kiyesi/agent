package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
)

// ask prints a question and reads one line of answer.
func ask(io IO, question string) string {
	fmt.Fprint(io.Err, question)
	if io.In == nil {
		return ""
	}
	// One byte at a time, so the next question's answer is left unread.
	var line []byte
	buf := make([]byte, 1)
	for len(line) < 1024 {
		n, err := io.In.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				break
			}
			line = append(line, buf[0])
		}
		if err != nil {
			break
		}
	}
	return strings.TrimSpace(string(line))
}

// visibleServer finds a server the person can see by its name.
func visibleServer(ctx context.Context, c *api.Client, name string) (api.Server, error) {
	list, err := c.Servers(ctx)
	if err != nil {
		return api.Server{}, apiErr(err)
	}
	s, ok := find(list, name)
	if !ok {
		return api.Server{}, usageErr("There is no server called %q that you can see. Run kiyesi servers for the list.", name)
	}
	return s, nil
}

func codeOrAsk(io IO, code string) string {
	if code == "" {
		code = ask(io, "Code from your authenticator app: ")
	}
	return strings.ReplaceAll(code, " ", "")
}

func newServersDisconnect(io IO) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disconnect <name>",
		Short: "Stop a server sending results; its history stays until it expires",
		Long: "The server's token stops working at once and it no longer counts as silent.\n" +
			"Its scans, metrics, logs and history stay until they expire. To connect it\n" +
			"again, make a new token with kiyesi servers reconnect.",
		Example: "  kiyesi servers disconnect old-web-1",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			s, err := visibleServer(cmd.Context(), c, args[0])
			if err != nil {
				return err
			}
			if s.State == "disconnected" {
				fmt.Fprintf(io.Out, "%s is already disconnected. To connect it again: kiyesi servers reconnect %s\n", s.Name, s.Name)
				return nil
			}
			if err := c.DisconnectServer(cmd.Context(), s.ID); err != nil {
				return apiErr(err)
			}
			fmt.Fprintf(io.Out, "Disconnected %s. Its token no longer works; its history stays until it expires.\n", s.Name)
			return nil
		},
	}
	cmd.SetContext(context.Background())
	return cmd
}

func newServersDelete(io IO) *cobra.Command {
	var confirm, code string
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a server and, after 7 days, everything it sent",
		Long: "Hides the server everywhere and stops its token at once, and emails every\n" +
			"owner and admin. After 7 days its scans, alerts, history, metrics and logs\n" +
			"are erased for good; until then, kiyesi servers restore brings it back.\n" +
			"It asks you to type the name again and a code from your authenticator app.",
		Example: "  kiyesi servers delete old-web-1",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			s, err := visibleServer(cmd.Context(), c, args[0])
			if err != nil {
				return err
			}
			if confirm == "" {
				fmt.Fprintf(io.Err, "This deletes %s. After 7 days everything it sent is erased for good.\n", s.Name)
				confirm = ask(io, "Type the server's name to confirm: ")
			}
			if confirm != s.Name {
				return usageErr("The name typed was not %s, so nothing was deleted.", s.Name)
			}
			purgeAt, err := c.DeleteServer(cmd.Context(), s.ID, confirm, codeOrAsk(io, code))
			if err != nil {
				return apiErr(err)
			}
			fmt.Fprintf(io.Out, "Deleted %s. It is erased for good on %s; until then: kiyesi servers restore %s\n",
				s.Name, purgeAt.Local().Format("Mon 2 Jan 15:04"), s.Name)
			return nil
		},
	}
	cmd.Flags().StringVar(&confirm, "confirm", "", "the server's name again, instead of typing it when asked")
	cmd.Flags().StringVar(&code, "code", "", "the code from your authenticator app, instead of typing it when asked")
	cmd.SetContext(context.Background())
	return cmd
}

func newServersRestore(io IO) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "restore <name>",
		Short:   "Bring back a server deleted in the last 7 days, with its history",
		Example: "  kiyesi servers restore old-web-1",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			list, err := c.DeletedServers(cmd.Context())
			if err != nil {
				return apiErr(err)
			}
			for _, s := range list {
				if strings.EqualFold(s.Name, args[0]) {
					if err := c.RestoreServer(cmd.Context(), s.ID); err != nil {
						return apiErr(err)
					}
					fmt.Fprintf(io.Out, "Restored %s, disconnected. To start sending again: kiyesi servers reconnect %s\n", s.Name, s.Name)
					return nil
				}
			}
			return usageErr("No deleted server is called %q. Servers are erased for good 7 days after they are deleted.", args[0])
		},
	}
	cmd.SetContext(context.Background())
	return cmd
}

func newServersReconnect(io IO) *cobra.Command {
	var code string
	cmd := &cobra.Command{
		Use:   "reconnect <name>",
		Short: "Make a new token for a server, to connect it again",
		Long: "Makes a new token and prints the command to run on the server. Any older\n" +
			"token stops working. It asks for a code from your authenticator app.",
		Example: "  kiyesi servers reconnect old-web-1",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			s, err := visibleServer(cmd.Context(), c, args[0])
			if err != nil {
				return err
			}
			command, err := c.NewServerToken(cmd.Context(), s.ID, codeOrAsk(io, code))
			if err != nil {
				return apiErr(err)
			}
			fmt.Fprintf(io.Out, "Run this on %s (the token is shown once):\n\n  %s\n", s.Name, command)
			return nil
		},
	}
	cmd.Flags().StringVar(&code, "code", "", "the code from your authenticator app, instead of typing it when asked")
	cmd.SetContext(context.Background())
	return cmd
}
