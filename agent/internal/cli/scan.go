package cli

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/checks"
	"github.com/kiyesi/kiyesi/agent/internal/config"
	"github.com/kiyesi/kiyesi/agent/internal/packs"
	"github.com/kiyesi/kiyesi/agent/internal/render"
	"github.com/kiyesi/kiyesi/agent/internal/report"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// scanAsRoot says whether the scan runs as root. Tests replace it.
var scanAsRoot = func() bool { return os.Geteuid() == 0 }

// newSystem builds the real system. Tests replace it.
var newSystem = func(root bool, stateDir string) *system.System {
	fsys := system.NewRootFS("/")
	host, _ := os.Hostname()
	return &system.System{
		FS:       fsys,
		Exec:     system.ExecRunner{},
		Docker:   system.NewDocker(system.DockerSocket),
		Metadata: system.NewMetadata(),
		Statfs:   system.Statfs,
		State:    system.FileState{Path: filepath.Join(stateDir, "state.yaml")},
		Now:      time.Now,
		Root:     root,
		OS:       system.ReadOS(fsys),
		Hostname: host,
	}
}

func newScan(io IO) *cobra.Command {
	var (
		asJSON     bool
		failOn     string
		configPath string
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan this server and print the report. Nothing leaves the server",
		Long: "Runs the health and security checks on this server and prints a grade,\n" +
			"each problem in one sentence, and the fix for each critical one. The full\n" +
			"report, with every fix, is saved to /var/lib/kiyesi (or ~/.local/state/kiyesi\n" +
			"without root). Without root, checks that need it are skipped and say so.",
		Example: "  sudo kiyesi scan\n  sudo kiyesi scan --fail-on critical   # exit 1 if anything is critical, for a deploy pipeline",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if failOn != "" && failOn != "critical" && failOn != "warning" {
				return usageErr("--fail-on must be critical or warning, not %q. Example: kiyesi scan --fail-on critical", failOn)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			r, saveErr, err := runScan(ctx, configPath, 0, render.ByScan)
			if err != nil {
				return err
			}
			if asJSON {
				if err := render.JSON(io.Out, r); err != nil {
					return err
				}
			} else if err := render.Terminal(render.NewWriter(io.Out, io.Environ), r, saveErr, viaSudo(io.Environ)); err != nil {
				return err
			}
			return failure(r, failOn)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON, for scripts and pipelines")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit with code 1 when a finding is at this level or worse: critical or warning")
	cmd.Flags().StringVar(&configPath, "config", config.DefaultPath, "the settings file")
	cmd.SetContext(context.Background())
	return cmd
}

// runScan runs every check, saves the full report, and returns the report.
// The error is for problems the user must fix; saveErr only means the
// report file could not be written. by is who asked, for the report's
// last line.
func runScan(ctx context.Context, configPath string, reuseSlowFor time.Duration, by render.By) (r scan.Report, saveErr, err error) {
	r, _, saveErr, err = scanWithEnv(ctx, configPath, reuseSlowFor, by)
	return r, saveErr, err
}

// scanWithEnv is runScan that also returns what the checks read, for kiyesi fix.
func scanWithEnv(ctx context.Context, configPath string, reuseSlowFor time.Duration, by render.By) (r scan.Report, env *checks.Env, saveErr, err error) {
	cfg, err := config.Load(configPath)
	// The server's own setting wins; else the team's choice, as the
	// service last said it; else none.
	if err == nil && cfg.HomeCountry == "" {
		cfg.HomeCountry = teamHome()
	}
	if err != nil {
		return r, nil, nil, usageErr("%v\nFix the file, or move it away to use the defaults.", err)
	}
	pack, err := packs.English()
	if err != nil {
		return r, nil, nil, &exitError{code: ExitUsage, msg: "The built-in wording is damaged: " + err.Error() + ". Reinstall Kiyesi."}
	}
	root := scanAsRoot()
	dir := report.Dir(root)
	sys := newSystem(root, dir)
	sys.Docker = system.FilterDocker(sys.Docker, cfg.Containers.Include, cfg.Containers.Exclude)
	env = checks.NewEnv(sys, cfg)
	env.ReuseSlowFor = reuseSlowFor
	r = scan.Run(ctx, env, checks.Default(), pack)
	// Kiyesi only suggests: no report offers kiyesi fix, only the commands a
	// person reviews and runs.
	for i := range r.Checks {
		for j := range r.Checks[i].Findings {
			r.Checks[i].Findings[j].AutoFix = ""
		}
	}
	path, saveErr := report.Save(dir, sys.Now(), render.File(r, by))
	if saveErr == nil {
		r.ReportFile = path
	}
	return r, env, saveErr, nil
}

// viaSudo is true when root runs the scan on behalf of another user.
func viaSudo(environ []string) bool {
	if os.Geteuid() != 0 {
		return false
	}
	for _, e := range environ {
		if v, ok := strings.CutPrefix(e, "SUDO_USER="); ok && v != "" && v != "root" {
			return true
		}
	}
	return false
}

// failure returns exit code 1 when the user asked to fail on findings of
// this level and there are some. The report has already been printed.
func failure(r scan.Report, failOn string) error {
	switch {
	case failOn == "critical" && r.Counts.Critical > 0,
		failOn == "warning" && r.Counts.Critical+r.Counts.Warnings > 0:
		return &exitError{code: ExitFindings}
	}
	return nil
}
