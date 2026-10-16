package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/kiyesi/kiyesi/agent/internal/collect"
	"github.com/kiyesi/kiyesi/agent/internal/config"
	"github.com/kiyesi/kiyesi/agent/internal/dbwatch"
	"github.com/kiyesi/kiyesi/agent/internal/jobs"
	"github.com/kiyesi/kiyesi/agent/internal/scan"
	"github.com/kiyesi/kiyesi/agent/internal/send"
	"github.com/kiyesi/kiyesi/agent/internal/software"
	"github.com/kiyesi/kiyesi/agent/internal/system"
)

// The agent's rhythm.
const (
	scanEvery      = 15 * time.Minute
	heartbeatEvery = time.Minute
	outboxBytes    = 20 << 20
	// Slow checks (Trivy) run at most this often in the background.
	slowChecksEvery = 6 * time.Hour
)

func newAgent(io IO) *cobra.Command {
	var configPath string
	var minute time.Duration
	var noScan, container bool
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run as the background service: scan and send results (started by kiyesi connect)",
		Long: "Runs a scan now and every 15 minutes, says the server is alive every minute,\n" +
			"and sends both to the service. Results that cannot be sent wait on disk and\n" +
			"are sent later. It is normally started by the system service.",
		Example: "  sudo systemctl status kiyesi\n" +
			"  KIYESI_API=https://api.kiyesi.dev KIYESI_TOKEN=ksv_... kiyesi agent --container",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if minute < 2*time.Second || minute > time.Minute {
				return usageErr("--minute must be from 2s to 1m")
			}
			if container {
				return runContainer(cmd, io, configPath, minute)
			}
			conf, token, err := loadConnection()
			if err != nil {
				return &exitError{code: ExitUsage, msg: err.Error()}
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			// Measurements each minute, from the same read-only view of the
			// server as the scan.
			col := &collect.Collector{Sys: newSystem(os.Geteuid() == 0, stateDir())}
			docker := col.Sys.Docker
			applied := false
			// The folder kiyesi run drops its records in. Only as root, as the service runs.
			spool := ""
			if os.Geteuid() == 0 {
				if s, err := jobs.PrepareSpool(stateDir()); err == nil {
					spool = s
				} else {
					fmt.Fprintf(io.Err, "timed jobs cannot be recorded: %v\n", err)
				}
			}
			var lastJobScan, lastDBRead, softwareSent time.Time
			softwarePrint := ""
			dbs := &dbwatch.Reader{DiskBytes: diskBytes(col.Sys)}
			a := agentLoop{
				collect: func(ctx context.Context) (*collect.Metrics, []collect.Event, *collect.Logs, []send.Item) {
					// The settings are read each minute, so a change to the
					// logs section applies without a restart.
					applyLogSettings(col, docker, configPath, &applied, io.Err)
					m, ev := col.Collect(ctx)
					// Timed jobs: the runs kiyesi run recorded, and every 15
					// minutes the schedules, from crontabs and systemd timers.
					var schedules []jobs.Schedule
					if now := time.Now(); now.Sub(lastJobScan) >= scanEvery {
						lastJobScan = now
						schedules = jobs.Find(ctx, os.DirFS("/"), system.ExecRunner{}, now)
						if schedules == nil {
							schedules = []jobs.Schedule{}
						}
					}
					var runs []jobs.Run
					if spool != "" {
						runs = jobs.Take(spool)
					}
					items := send.Jobs(time.Now(), runs, schedules)
					// What is installed: when it changed, and at least once a day.
					if schedules != nil {
						now := time.Now()
						list := software.Read(ctx, col.Sys)
						if p := list.Print(); p != softwarePrint || now.Sub(softwareSent) >= 24*time.Hour {
							softwarePrint, softwareSent = p, now
							items = append(items, send.Software(now, list))
						}
					}
					// The databases in the settings, every 5 minutes.
					if now := time.Now(); now.Sub(lastDBRead) >= dbReadEvery {
						lastDBRead = now
						items = append(items, send.Databases(now, readDatabases(ctx, configPath, dbs, now))...)
					}
					return &m, ev, col.TakeLogs(), items
				},
				client: withHome(send.NewClient(conf.API, token), io.Err),
				outbox: send.Outbox{Dir: outboxDir(), MaxBytes: outboxBytes},
				scan: func(ctx context.Context) (scan.Report, error) {
					r, _, err := runScan(ctx, configPath, slowChecksEvery)
					return r, err
				},
				scanEvery: map[bool]time.Duration{true: 0, false: scanEvery}[noScan], beatEvery: minute,
				now: time.Now, log: io.Err,
			}
			fmt.Fprintf(io.Err, "kiyesi agent sending to %s\n", conf.API)
			a.run(ctx)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", config.DefaultPath, "the settings file")
	// Only for the end-to-end test, which cannot wait two whole minutes for
	// the first log lines.
	cmd.Flags().DurationVar(&minute, "minute", heartbeatEvery, "how often to measure and send")
	_ = cmd.Flags().MarkHidden("minute")
	// Only for the failure drills' own agent (deploy/drills), which reads a
	// few containers and must not scan the server it shares.
	cmd.Flags().BoolVar(&noScan, "no-scan", false, "send figures and logs only, never a scan")
	_ = cmd.Flags().MarkHidden("no-scan")
	cmd.Flags().BoolVar(&container, "container", false,
		"run beside a managed service (Render, Heroku, Fly.io, …): no scan and no host figures; the databases in the settings and the runs of kiyesi run. Reads KIYESI_API and KIYESI_TOKEN")
	return cmd
}

// runContainer is the agent beside a managed service, where the platform
// runs the machine: there is nothing to scan and the machine's figures are
// the platform's, not the app's. It sends a heartbeat each minute, the
// databases in the settings every 5 minutes, and each run of a job wrapped
// with kiyesi run. The address and token come from the environment.
func runContainer(cmd *cobra.Command, io IO, configPath string, minute time.Duration) error {
	api := strings.TrimSpace(os.Getenv("KIYESI_API"))
	if api == "" {
		api = "https://api.kiyesi.dev"
	}
	token := strings.TrimSpace(os.Getenv("KIYESI_TOKEN"))
	if token == "" {
		return usageErr("set KIYESI_TOKEN to the token from Settings, Managed services, Run the agent beside it")
	}
	if err := send.CheckAPI(api); err != nil {
		return &exitError{code: ExitUsage, msg: err.Error()}
	}
	if !cmd.Flags().Changed("config") {
		if p := os.Getenv("KIYESI_CONFIG"); p != "" {
			configPath = p
		}
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := send.NewClient(api, token)
	host, _ := os.Hostname()
	// Saying it runs makes the service watch for silence, as it does for a server.
	if _, err := client.Connect(ctx, host, "container"); errors.Is(err, send.ErrNotAllowed) {
		return &exitError{code: ExitUsage, msg: "the service refused this token: make a new one in Settings"}
	} else if err != nil {
		fmt.Fprintf(io.Err, "cannot reach the service yet (%v); results wait until it answers\n", err)
	}
	spool := ""
	if s, err := jobs.PrepareSpool(stateDir()); err == nil {
		spool = s
	} else {
		fmt.Fprintf(io.Err, "timed jobs cannot be recorded: %v\n", err)
	}
	dbs := &dbwatch.Reader{}
	var lastDBRead time.Time
	a := agentLoop{
		collect: func(ctx context.Context) (*collect.Metrics, []collect.Event, *collect.Logs, []send.Item) {
			var runs []jobs.Run
			if spool != "" {
				runs = jobs.Take(spool)
			}
			items := send.Jobs(time.Now(), runs, nil)
			if now := time.Now(); now.Sub(lastDBRead) >= dbReadEvery {
				lastDBRead = now
				items = append(items, send.Databases(now, readDatabases(ctx, configPath, dbs, now))...)
			}
			return nil, nil, nil, items
		},
		client:    client,
		outbox:    send.Outbox{Dir: outboxDir(), MaxBytes: outboxBytes},
		scan:      func(context.Context) (scan.Report, error) { return scan.Report{}, nil },
		scanEvery: 0,
		beatEvery: minute,
		now:       time.Now,
		log:       io.Err,
	}
	fmt.Fprintf(io.Err, "kiyesi agent (container) sending to %s\n", api)
	a.run(ctx)
	return nil
}

// applyLogSettings sets what the collector sends from the settings file.
// A file with a mistake keeps the last good settings (at first, the
// defaults) and says so.
func applyLogSettings(col *collect.Collector, docker system.Docker, path string, applied *bool, errOut io.Writer) {
	c, err := config.Load(path)
	if err != nil {
		if *applied {
			fmt.Fprintf(errOut, "logs settings not changed: %v\n", err)
			return
		}
		fmt.Fprintf(errOut, "using the default logs settings: %v\n", err)
		c = config.Default()
	}
	*applied = true
	col.Sys.Docker = system.FilterDocker(docker, c.Containers.Include, c.Containers.Exclude)
	col.Logs = c.Logs.Enabled
	col.Rules = collect.LogRules{Exclude: c.Logs.Exclude, Drop: c.Logs.Drop}
	col.Journal = collect.JournalRules{On: c.Logs.Journal, Auth: c.Logs.Auth, Firewall: c.Logs.Firewall, Include: c.Logs.Include}
	// The sign-in watch, unless logins: off. Kept across settings changes,
	// so the pairs already seen are not forgotten.
	switch {
	case c.Logins == "off":
		col.Signins = nil
	case col.Signins == nil:
		col.Signins = &collect.SigninWatch{Path: filepath.Join(stateDir(), "signins.json")}
	}
}

func loadConnection() (agentConf, string, error) {
	var conf agentConf
	data, err := os.ReadFile(agentConfPath())
	if err != nil {
		return conf, "", errors.New("this server is not connected. Run: sudo kiyesi connect --token <token>")
	}
	if err := yaml.Unmarshal(data, &conf); err != nil || conf.API == "" {
		return conf, "", fmt.Errorf("%s is damaged. Run kiyesi connect again", agentConfPath())
	}
	if err := send.CheckAPI(conf.API); err != nil {
		return conf, "", err
	}
	token, err := os.ReadFile(tokenPath())
	if err != nil {
		return conf, "", fmt.Errorf("cannot read the token in %s: run kiyesi connect again", tokenPath())
	}
	return conf, strings.TrimSpace(string(token)), nil
}

// agentLoop is the service's work, with its clock and parts replaceable
// for tests.
type agentLoop struct {
	client *send.Client
	outbox send.Outbox
	scan   func(context.Context) (scan.Report, error)
	// collect takes the minute's metrics, events and log lines; nil sends
	// heartbeats only.
	collect   func(context.Context) (*collect.Metrics, []collect.Event, *collect.Logs, []send.Item)
	scanEvery time.Duration
	beatEvery time.Duration
	now       func() time.Time
	log       io.Writer
}

func (a agentLoop) run(ctx context.Context) {
	nextScan := a.now()
	nextBeat := a.now()
	nextSend := a.now()
	failures := 0
	tick := time.NewTicker(min(a.beatEvery, time.Second))
	defer tick.Stop()
	for {
		now := a.now()
		// A scanEvery of 0 never scans: an agent that only sends figures and logs.
		if a.scanEvery > 0 && !now.Before(nextScan) {
			nextScan = now.Add(a.scanEvery)
			if r, err := a.scan(ctx); err != nil {
				fmt.Fprintf(a.log, "scan failed: %v\n", err)
			} else if err := a.outbox.Put(send.Scan(r, now), now); err != nil {
				fmt.Fprintf(a.log, "cannot keep the scan for sending: %v\n", err)
			}
			nextSend = now
		}
		if !now.Before(nextBeat) {
			nextBeat = now.Add(a.beatEvery)
			batch := send.Heartbeat(now)
			if a.collect != nil {
				m, events, logs, extra := a.collect(ctx)
				batch = send.Minute(now, m, events, logs, extra...)
			}
			if err := a.outbox.Put(batch, now); err != nil {
				fmt.Fprintf(a.log, "cannot keep the heartbeat for sending: %v\n", err)
			}
		}
		if !now.Before(nextSend) && a.outbox.Len() > 0 {
			_, err := a.outbox.FlushReporting(ctx, a.client, func(name string) {
				fmt.Fprintf(a.log, "the service refused batch %s as malformed or too large, so it was dropped: update the agent\n", name)
			})
			switch {
			case err == nil:
				failures = 0
				nextSend = now
			case errors.Is(err, send.ErrNotAllowed):
				fmt.Fprintln(a.log, "the service refused this server's token: results wait on disk. Run kiyesi connect with a new token.")
				nextSend = now.Add(15 * time.Minute)
			default:
				wait := send.Backoff(failures, 5*time.Second, 5*time.Minute)
				failures++
				fmt.Fprintf(a.log, "cannot send results (%v); trying again in %s\n", err, wait.Round(time.Second))
				nextSend = now.Add(wait)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// How often the databases in the settings are read.
const dbReadEvery = 5 * time.Minute

// diskBytes measures the disk a path is on: used plus what is still free.
func diskBytes(sys *system.System) func(string) (int64, bool) {
	return func(path string) (int64, bool) {
		if sys == nil || sys.Statfs == nil {
			return 0, false
		}
		u, err := sys.Statfs(path)
		if err != nil || u.TotalBytes == 0 {
			return 0, false
		}
		size := u.TotalBytes - u.FreeBytes + u.AvailBytes
		if size > math.MaxInt64 {
			return 0, false
		}
		return int64(size), true
	}
}

// readDatabases reads every database in the settings; nil when there are none.
func readDatabases(ctx context.Context, configPath string, r *dbwatch.Reader, now time.Time) []dbwatch.Figures {
	c, err := config.Load(configPath)
	if err != nil || len(c.Databases) == 0 {
		return nil
	}
	var out []dbwatch.Figures
	for _, d := range c.Databases {
		if !dbwatch.NamePattern.MatchString(d.Name) {
			continue
		}
		out = append(out, r.Read(ctx, dbwatch.Config{Name: d.Name, URL: d.URL, Limit: d.Limit, Backups: d.Backups}, now))
		if len(out) == 20 {
			break
		}
	}
	return out
}

// withHome keeps the team's home country from the service's replies, so the
// next scan compares with it.
func withHome(c *send.Client, errOut io.Writer) *send.Client {
	c.OnHome = func(code string) {
		if err := saveTeamHome(code); err != nil {
			fmt.Fprintf(errOut, "cannot keep the team's home country: %v\n", err)
		}
	}
	return c
}
