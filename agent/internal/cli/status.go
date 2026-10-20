package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
)

var statusStates = []string{"investigating", "identified", "fixing", "monitoring", "resolved"}

var componentWords = map[string]string{"up": "working normally", "failing": "working normally", "down": "HAVING PROBLEMS", "waiting": "not checked yet"}

func newStatus(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Your public status pages, and what each one shows now",
		Long: "Each project can have a public status page at status.kiyesi.dev, showing the\n" +
			"uptime checks you chose under names your customers know. Post updates with\n" +
			"kiyesi status post.",
		Example: "  kiyesi status\n  kiyesi status post \"We found the cause and are fixing it.\" --state fixing",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := signedIn()
			if err != nil {
				return err
			}
			pages, err := c.StatusPages(cmd.Context())
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitUsage, msg: "Your role cannot see status pages."}
			}
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return jsonOut(io.Out, pages)
			}
			if len(pages) == 0 {
				fmt.Fprintln(io.Out, "No status page yet. Make one on the Uptime screen.")
				return nil
			}
			for _, p := range pages {
				public := "public"
				if !p.On {
					public = "not public yet"
				}
				fmt.Fprintf(io.Out, "%s (%s), %s\n  %d email subscribers, %d views this week\n", p.Title, public, p.URL, p.Subscribers, p.Views)
				for _, s := range p.Components {
					state := "not checked yet"
					if s.Status != nil {
						state = componentWords[*s.Status]
					}
					fmt.Fprintf(io.Out, "  %s: %s\n", s.Name, state)
				}
				fmt.Fprintln(io.Out)
			}
			return nil
		},
	}
	cmd.AddCommand(newStatusPost(io))
	cmd.SetContext(context.Background())
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	return cmd
}

func newStatusPost(io IO) *cobra.Command {
	var page, title, state string
	cmd := &cobra.Command{
		Use:   "post <text>",
		Short: "Publish an update on a status page, and email its subscribers",
		Long: "Adds the next step to the problem that is open on the page, or, with --title,\n" +
			"starts a new one. --state resolved closes it. It goes on the public page and to\n" +
			"everyone who asked for email updates: write plain words, no server names.",
		Example: "  kiyesi status post \"Some customers cannot place orders.\" --title \"Some orders are failing\"\n" +
			"  kiyesi status post \"All orders go through again.\" --state resolved",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !contains(statusStates, state) {
				return usageErr("--state must be one of %s", strings.Join(statusStates, ", "))
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			pages, err := c.StatusPages(cmd.Context())
			if errors.Is(err, api.ErrNotFound) {
				return &exitError{code: ExitNoAccess, msg: "Your role cannot see status pages."}
			}
			if err != nil {
				return apiErr(err)
			}
			if len(pages) == 0 {
				return usageErr("No status page yet. Make one on the Uptime screen.")
			}
			var target *api.StatusPage
			for i := range pages {
				if page == "" && len(pages) == 1 || pages[i].Slug == page || strings.EqualFold(pages[i].Title, page) {
					target = &pages[i]
				}
			}
			if target == nil {
				if page == "" && len(pages) > 1 {
					return usageErr("you have %d status pages: name one with --page", len(pages))
				}
				return usageErr("there is no status page called %q that you can see", page)
			}
			body := map[string]string{"state": state, "text": args[0]}
			if title != "" {
				body["title"] = title
			} else {
				posts, err := c.StatusPosts(cmd.Context(), target.ID)
				if err != nil {
					return apiErr(err)
				}
				for _, p := range posts {
					if p.ResolvedAt == nil {
						body["postId"] = p.ID
						title = p.Title
						break
					}
				}
				if body["postId"] == "" {
					return usageErr("nothing is open on %s: give the problem a --title", target.Title)
				}
			}
			if err := c.PostStatus(cmd.Context(), target.ID, body); err != nil {
				return apiErr(err)
			}
			// The service emails subscribers only while the page is public.
			if target.On {
				fmt.Fprintf(io.Out, "Posted on %s: %s (%s). Subscribers are emailed.\n", target.URL, title, state)
			} else {
				fmt.Fprintf(io.Out, "Saved on %s: %s (%s). The page is not public, so nobody was emailed.\n", target.Title, title, state)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&page, "page", "", "the page's address or title, when you have more than one")
	cmd.Flags().StringVar(&title, "title", "", "start a new problem with this title, such as \"Some orders are failing\"")
	cmd.Flags().StringVar(&state, "state", "investigating", "investigating, identified, fixing, monitoring or resolved")
	return cmd
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
