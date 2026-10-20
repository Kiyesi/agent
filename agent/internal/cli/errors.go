package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/api"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

func newErrors(io IO) *cobra.Command {
	var frontend, since string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "errors",
		Short: "Browser errors from your frontends, grouped, with file and line",
		Long: "Lists what went wrong in your users' browsers, busiest first: the error,\n" +
			"where in the code (the real file and line once source maps are uploaded),\n" +
			"how often, for how many people, and when it was first seen.",
		Example: "  kiyesi errors\n  kiyesi errors --frontend storefront-web --since 7d",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rng := map[string]string{"24h": "24h", "1d": "24h", "today": "24h", "yesterday": "24h", "7d": "7d", "week": "7d", "30d": "30d"}[strings.ToLower(since)]
			if rng == "" {
				return usageErr("--since must be 24h, 7d or 30d, not %q", since)
			}
			c, err := signedIn()
			if err != nil {
				return err
			}
			id := ""
			var list []api.Frontend
			if frontend != "" {
				list, err = c.Frontends(cmd.Context())
				if err != nil {
					return apiErr(err)
				}
				for _, f := range list {
					if strings.EqualFold(f.Name, frontend) {
						id = f.ID
					}
				}
				if id == "" {
					return usageErr("There is no frontend called %q that you can see.", frontend)
				}
			}
			out, err := c.Errors(cmd.Context(), id, rng)
			if err != nil {
				return apiErr(err)
			}
			if asJSON {
				return render.JSON(io.Out, out)
			}
			// The service counts a rolling 24 hours, whatever --since is.
			fmt.Fprintf(io.Out, "Last 24 hours: %s in %s.\n\n", plural(out.Today.Errors, "error", "errors"), plural(out.Today.Groups, "group", "groups"))
			if len(out.Groups) == 0 {
				fmt.Fprintln(io.Out, "No browser errors in that time.")
				// The snippet is worth suggesting only when no frontend reports
				// yet, and only to someone who can add one.
				if frontend == "" {
					list, err = c.Frontends(cmd.Context())
				}
				if err == nil && len(list) == 0 && mayDo(cmd.Context(), c, "settings", "manage") {
					fmt.Fprintln(io.Out, "No frontend sends errors yet. Add the snippet to one: Settings, Frontends.")
				}
				return nil
			}
			tw := tabwriter.NewWriter(io.Out, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "EVENTS\tUSERS\tERROR\tWHERE IN THE CODE\tFIRST SEEN")
			for _, g := range out.Groups {
				users := "-"
				if g.Users != nil {
					users = fmt.Sprint(*g.Users)
				}
				msg := g.Type + ": " + g.Message
				if len(msg) > 70 {
					msg = msg[:69] + "…"
				}
				where := g.Where
				if where == "" {
					where = "-"
				} else if !g.Mapped {
					where += " (no source map)"
				}
				first := g.FirstSeen.At.Local().Format("Mon 2 Jan 15:04")
				if g.FirstSeen.Version != "" {
					first += ", version " + g.FirstSeen.Version
				}
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", g.Events, users, msg, where, first)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&frontend, "frontend", "", "only this frontend")
	cmd.Flags().StringVar(&since, "since", "24h", "how far back: 24h, 7d or 30d")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts")
	cmd.SetContext(context.Background())
	return cmd
}

// builtMap is a map file and the name it is uploaded under.
type builtMap struct{ file, name string }

var mappingURL = regexp.MustCompile(`(?m)^//[#@] sourceMappingURL=(\S+)\s*$`)

// buildMaps finds a build's source maps. Each is uploaded under the name of
// the script that points to it (its sourceMappingURL) plus ".map", because
// some bundlers, such as Turbopack, name a map differently from its script,
// and the browser reports the script. A map no script points to keeps its
// own name.
func buildMaps(root string) ([]builtMap, error) {
	var scripts, maps []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "node_modules" {
			return filepath.SkipDir
		}
		switch {
		case d.IsDir():
		case strings.HasSuffix(d.Name(), ".map"):
			maps = append(maps, p)
		case strings.HasSuffix(d.Name(), ".js"), strings.HasSuffix(d.Name(), ".mjs"), strings.HasSuffix(d.Name(), ".cjs"):
			scripts = append(scripts, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	rel := func(p string) string {
		r, _ := filepath.Rel(root, p)
		return filepath.ToSlash(r)
	}
	used := map[string]bool{}
	var out []builtMap
	for _, js := range scripts {
		f, err := os.Open(js) // #nosec G304 -- files in the build folder named
		if err != nil {
			continue
		}
		info, _ := f.Stat()
		tail := make([]byte, min(info.Size(), 1024))
		_, _ = f.ReadAt(tail, info.Size()-int64(len(tail)))
		_ = f.Close()
		m := mappingURL.FindSubmatch(tail)
		if m == nil || strings.Contains(string(m[1]), ":") {
			continue
		}
		mapFile := filepath.Join(filepath.Dir(js), filepath.FromSlash(string(m[1])))
		if _, err := os.Stat(mapFile); err != nil {
			continue
		}
		used[mapFile] = true
		out = append(out, builtMap{file: mapFile, name: rel(js) + ".map"})
	}
	for _, m := range maps {
		if !used[m] {
			out = append(out, builtMap{file: m, name: rel(m)})
		}
	}
	return out, nil
}

// maxMap is the largest map uploaded, unzipped; the service refuses bigger.
const maxMap = 20 << 20

// sourcemapClient picks how source maps are uploaded: a deploy token from
// KIYESI_DEPLOY_TOKEN (for CI), or the person signed in with kiyesi login.
// Never this server's own token: the service refuses it for source maps.
func sourcemapClient(apiURL string, environ []string) (*api.Client, error) {
	if t := strings.TrimSpace(envMap(environ)["KIYESI_DEPLOY_TOKEN"]); t != "" {
		if !strings.HasPrefix(t, "kdp_") {
			return nil, usageErr("KIYESI_DEPLOY_TOKEN is not a deploy token. Make one in the dashboard: Settings, Deploy tokens.")
		}
		return api.New(apiURL, t), nil
	}
	c, err := signedIn()
	if err != nil {
		return nil, &exitError{code: ExitNoAccess, msg: "Set KIYESI_DEPLOY_TOKEN (Settings, Deploy tokens), or sign in with kiyesi login. A server's own token cannot upload source maps."}
	}
	return c, nil
}

func newSourcemaps(io IO) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sourcemaps",
		Short: "Upload a build's source maps, so browser errors show the real file and line",
	}
	var frontend, ver, apiURL string
	var remove bool
	upload := &cobra.Command{
		Use:   "upload <build folder>",
		Short: "Upload every .map file in a build folder, for one version",
		Long: "Run it in your build step, after building, with the same version as the\n" +
			"snippet's data-version. In CI, set KIYESI_DEPLOY_TOKEN. Add --delete to remove\n" +
			"the maps from the folder afterwards, so they are not published with the site.",
		Example: "  kiyesi sourcemaps upload --version 2.14.0 ./dist\n" +
			"  KIYESI_DEPLOY_TOKEN=kdp_... kiyesi sourcemaps upload --frontend storefront-web --version $GIT_SHA --delete ./dist",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if ver == "" {
				return usageErr("Give the version the snippet reports: kiyesi sourcemaps upload --version 2.14.0 ./dist")
			}
			root := args[0]
			maps, err := buildMaps(root)
			if err != nil {
				return usageErr("Cannot read %s: %v", root, err)
			}
			if len(maps) == 0 {
				return usageErr("No .map files in %s. Turn on source maps in your build, such as build.sourcemap: true in Vite.", root)
			}
			c, err := sourcemapClient(apiURL, io.Environ)
			if err != nil {
				return err
			}
			start := time.Now()
			skipped := 0
			var sent []string
			var bytesSent int64
			for _, m := range maps {
				data, err := os.ReadFile(m.file) // #nosec G304 -- files the person pointed us at
				if err != nil {
					return err
				}
				rel := m.name
				if len(data) > maxMap {
					fmt.Fprintf(io.Err, "skipped %s: larger than 20 MB\n", rel)
					skipped++
					continue
				}
				var gz bytes.Buffer
				zw := gzip.NewWriter(&gz)
				_, _ = zw.Write(data)
				_ = zw.Close()
				if err := c.UploadSourcemap(cmd.Context(), frontend, ver, rel, gz.Bytes()); err != nil {
					var p *api.Problem
					if errors.As(err, &p) && p.Status < 500 {
						return usageErr("%s: %s", rel, p.Message)
					}
					return apiErr(err)
				}
				sent = append(sent, m.file)
				bytesSent += int64(gz.Len())
			}
			if len(sent) == 0 {
				return usageErr("No source maps were uploaded: every map in %s is larger than 20 MB. None were removed.", root)
			}
			// Only the maps the service has: a skipped one stays, so it is not lost.
			if remove {
				for _, f := range sent {
					if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
						return err
					}
				}
			}
			fmt.Fprintf(io.Out, "Uploaded %s for version %s (%s) in %s.", plural(len(sent), "source map", "source maps"), ver, byteSize(bytesSent), time.Since(start).Round(time.Second))
			if remove {
				fmt.Fprint(io.Out, " Removed them from the folder.")
			}
			if skipped > 0 {
				fmt.Fprintf(io.Out, " Skipped %d larger than 20 MB", skipped)
				if remove {
					fmt.Fprint(io.Out, ", still in the folder: delete them before you publish")
				}
				fmt.Fprint(io.Out, ".")
			}
			fmt.Fprintln(io.Out)
			return nil
		},
	}
	upload.Flags().StringVar(&frontend, "frontend", "", "the frontend, as named in Settings (not needed when the team has only one)")
	upload.Flags().StringVar(&ver, "version", "", "the version the snippet reports, as in data-version")
	upload.Flags().BoolVar(&remove, "delete", false, "delete each map from the folder once uploaded, so it is not published")
	upload.Flags().StringVar(&apiURL, "api", envOr("KIYESI_API", DefaultAPI), "the service address, with a deploy token")
	upload.SetContext(context.Background())
	cmd.AddCommand(upload)
	return cmd
}
