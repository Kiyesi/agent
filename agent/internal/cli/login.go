package cli

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/send"
)

// openBrowser opens the approval page. Tests replace it.
var openBrowser = func(url string) {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	if path, err := exec.LookPath(name); err == nil {
		_ = exec.Command(path, url).Start() // #nosec G204 -- the system's own opener; url is one argument, no shell
	}
}

// sleep waits between polls. Tests replace it.
var sleep = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func newLogin(io IO) *cobra.Command {
	var apiURL string
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in from this computer, to see your servers here",
		Long: "Shows a code and opens the dashboard, where you approve the sign-in. The\n" +
			"token is kept in the system keychain (the macOS Keychain, or the Secret\n" +
			"Service on Linux), or in a file only you can read where there is none.",
		Example: "  kiyesi login\n  kiyesi servers",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := send.CheckAPI(apiURL); err != nil {
				return usageErr("%v", err)
			}
			c := api.New(apiURL, "")
			ctx := cmd.Context()
			d, err := c.StartLogin(ctx)
			if err != nil {
				return &exitError{code: ExitNoAccess, msg: fmt.Sprintf("%v\nCheck the address and your connection, then try again.", err)}
			}
			fmt.Fprintf(io.Out, "Open %s and check this code: %s\n", d.VerificationURI, d.UserCode)
			if !noBrowser && d.VerificationURIComplete != "" {
				openBrowser(d.VerificationURIComplete)
			}
			fmt.Fprintln(io.Out, "Waiting for you to approve it in the browser...")
			token, err := poll(ctx, c, d)
			if err != nil {
				return err
			}
			where, err := saveLogin(apiURL, token)
			if err != nil {
				return err
			}
			c.Token = token
			if me, err := c.Me(ctx); err == nil {
				fmt.Fprintf(io.Out, "Signed in as %s (%s), %s in %s.\n", me.User.Name, me.User.Email, me.Role, me.Team.Name)
			} else {
				fmt.Fprintln(io.Out, "Signed in.")
			}
			fmt.Fprintf(io.Out, "Saved the token to %s. Sign out with kiyesi logout.\n", where)
			return nil
		},
	}
	cmd.Flags().StringVar(&apiURL, "api", DefaultAPI, "the service address; change it only for a service you run yourself")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "print the address instead of opening the browser")
	cmd.SetContext(context.Background())
	return cmd
}

// poll asks every few seconds whether the sign-in was approved, until the
// code runs out.
func poll(ctx context.Context, c *api.Client, d api.DeviceCode) (string, error) {
	interval := time.Duration(max(d.Interval, 5)) * time.Second
	deadline := time.Now().Add(time.Duration(max(d.ExpiresIn, 60)) * time.Second)
	for time.Now().Before(deadline) {
		if err := sleep(ctx, interval); err != nil {
			return "", err
		}
		token, err := c.PollLogin(ctx, d.DeviceCode)
		switch {
		case err == nil:
			return token, nil
		case errors.Is(err, api.ErrPending):
		case errors.Is(err, api.ErrSlowDown):
			interval += 5 * time.Second
		case errors.Is(err, api.ErrDenied), errors.Is(err, api.ErrExpired):
			return "", &exitError{code: ExitNoAccess, msg: capital(err.Error()) + "."}
		default:
			return "", &exitError{code: ExitNoAccess, msg: err.Error()}
		}
	}
	return "", &exitError{code: ExitNoAccess, msg: "The code expired before it was approved. Run kiyesi login again."}
}

func newLogout(io IO) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Sign out on this computer",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if l, err := loadLogin(); err == nil {
				// End the session on the service too; carry on if it cannot be reached.
				_ = api.New(l.API, l.Token).Logout(context.Background())
			}
			if err := forgetLogin(); err != nil {
				return err
			}
			fmt.Fprintln(io.Out, "Signed out.")
			return nil
		},
	}
}

func capital(s string) string {
	if s == "" {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}
