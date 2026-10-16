// Package config reads /etc/kiyesi/config.yaml: the limits from the PRD that
// a user can change. Every field has a default, so the file is optional.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DefaultPath is where the agent looks for its settings.
const DefaultPath = "/etc/kiyesi/config.yaml"

// Config holds every setting the scan reads.
type Config struct {
	// HomeCountry is the ISO code of the country data should stay in. Empty
	// means the team's choice in the dashboard, or none: Kiyesi then shows
	// where things are without calling any of them outside.
	HomeCountry string `yaml:"home_country"`
	// PaymentData lists the databases that hold payment data, by host,
	// host:port, or the name a connection setting gives them.
	PaymentData []string   `yaml:"payment_data"`
	Ports       Ports      `yaml:"ports"`
	Backups     Backups    `yaml:"backups"`
	Secrets     Secrets    `yaml:"secrets"`
	Limits      Limits     `yaml:"limits"`
	Logs        Logs       `yaml:"logs"`
	Containers  Containers `yaml:"containers"`
	// Fix is "off" to forbid sudo kiyesi fix on this server, for a team
	// whose rules allow no tool to change a server. On by default.
	Fix string `yaml:"fix"`
	// Logins is "off" to stop the sign-in watch: a note for each SSH
	// sign-in from a user and address not seen before. On by default.
	Logins string `yaml:"logins"`
	// Databases are read by the agent with a read-only user (PRD feature 24).
	// Their addresses and passwords stay in this file and are never sent.
	Databases []Database `yaml:"databases"`
}

// Database is one database the agent reads: sizes, counts and the slow log,
// never a row.
type Database struct {
	// Name is how Kiyesi shows it, such as orders.
	Name string `yaml:"name"`
	// URL is how to reach it with the read-only user:
	// postgres://, mysql://, mongodb:// or mongodb+srv://, redis:// or rediss://.
	URL string `yaml:"url"`
	// Limit is a hosted plan's storage, such as 512MB or 25GB. Without it, a
	// database on this server is measured against the disk it lives on.
	Limit string `yaml:"limit"`
	// Backups is the folder its backups are written to, for the newest one's age.
	Backups string `yaml:"backups"`
}

// Containers says which containers Kiyesi reads at all: their figures,
// output, requests, restarts and checks. Names may use *. Empty lists
// mean every container.
type Containers struct {
	// Include reads only these containers.
	Include []string `yaml:"include"`
	// Exclude leaves these containers out entirely.
	Exclude []string `yaml:"exclude"`
}

// Logs says which log lines a connected server sends. Passwords and
// tokens are masked on the server either way.
type Logs struct {
	// Enabled sends log lines at all.
	Enabled bool `yaml:"enabled"`
	// Journal reads the system log: your own services in full, and
	// warnings and errors from the rest.
	Journal bool `yaml:"journal"`
	// Auth also sends SSH, sudo and sign-in records. Off by default.
	Auth bool `yaml:"auth"`
	// Firewall also sends the firewall's blocked-connection lines. Off by default.
	Firewall bool `yaml:"firewall"`
	// Include sends every line of these systemd services too.
	Include []string `yaml:"include"`
	// Exclude skips containers, services or files by name; * matches anything.
	Exclude []string `yaml:"exclude"`
	// Drop skips any line that contains one of these texts.
	Drop []string `yaml:"drop"`
}

// Ports lists the ports that may be open on a public address.
type Ports struct {
	Allowed []int `yaml:"allowed"`
}

// Backups names the folders backups are written to.
type Backups struct {
	Paths       []string `yaml:"paths"`
	MaxAgeHours int      `yaml:"max_age_hours"`
}

// Secrets names the folders searched for env files, Compose files and shell history.
type Secrets struct {
	Paths []string `yaml:"paths"`
}

// Limits are the thresholds each health check warns at.
type Limits struct {
	LoadPerCore         float64 `yaml:"load_per_core"`
	MemoryPercent       float64 `yaml:"memory_percent"`
	SwapBelowMemoryGB   float64 `yaml:"swap_below_memory_gb"`
	DiskWarningPercent  float64 `yaml:"disk_warning_percent"`
	DiskCriticalPercent float64 `yaml:"disk_critical_percent"`
	CertificateDays     int     `yaml:"certificate_days"`
	UpdateDays          int     `yaml:"update_days"`
	RestartsPerHour     int     `yaml:"restarts_per_hour"`
}

// Default returns the PRD's default limits.
func Default() Config {
	return Config{
		Ports:   Ports{Allowed: []int{22, 80, 443}},
		Backups: Backups{MaxAgeHours: 24},
		Secrets: Secrets{Paths: []string{"/srv", "/opt", "/home", "/root", "/var/www"}},
		Logs:    Logs{Enabled: true, Journal: true},
		Limits: Limits{
			LoadPerCore:         0.85,
			MemoryPercent:       90,
			SwapBelowMemoryGB:   2,
			DiskWarningPercent:  80,
			DiskCriticalPercent: 90,
			CertificateDays:     14,
			UpdateDays:          7,
			RestartsPerHour:     3,
		},
	}
}

// Load reads the settings at path. A missing file gives the defaults; a
// file that cannot be read or parsed is an error the user must fix.
func Load(path string) (Config, error) {
	c := Default()
	// #nosec G304 -- the path is the settings file the user names with --config.
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("cannot read %s: %w", path, err)
	}
	if err := Parse(data, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Parse reads settings over the defaults already in c, and rejects
// unknown keys and impossible values.
func Parse(data []byte, c *Config) error {
	dec := yaml.NewDecoder(bytesReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, errEOF) {
		return fmt.Errorf("not valid settings: %w", err)
	}
	return c.validate()
}

func (c *Config) validate() error {
	if c.HomeCountry != "" && len(c.HomeCountry) != 2 {
		return errors.New("home_country must be a two-letter country code, such as DE, NG or US, or left out")
	}
	c.HomeCountry = strings.ToUpper(c.HomeCountry)
	l := c.Limits
	switch {
	case l.LoadPerCore <= 0:
		return errors.New("limits.load_per_core must be above 0")
	case l.MemoryPercent <= 0 || l.MemoryPercent > 100:
		return errors.New("limits.memory_percent must be between 1 and 100")
	case l.DiskWarningPercent <= 0 || l.DiskCriticalPercent > 100 || l.DiskWarningPercent > l.DiskCriticalPercent:
		return errors.New("limits.disk_warning_percent must be above 0 and not above limits.disk_critical_percent, which must not be above 100")
	case l.CertificateDays < 1, l.UpdateDays < 1, l.RestartsPerHour < 1, c.Backups.MaxAgeHours < 1:
		return errors.New("limits.certificate_days, limits.update_days, limits.restarts_per_hour and backups.max_age_hours must be 1 or more")
	}
	for _, list := range [][]string{c.Logs.Include, c.Logs.Exclude, c.Logs.Drop} {
		if len(list) > 100 {
			return errors.New("logs.include, logs.exclude and logs.drop take at most 100 entries each")
		}
		for _, v := range list {
			if strings.TrimSpace(v) == "" || len(v) > 200 {
				return errors.New("logs.include, logs.exclude and logs.drop entries must be 1 to 200 characters")
			}
		}
	}
	switch strings.ToLower(c.Logins) {
	case "", "on", "true", "yes":
		c.Logins = "on"
	case "off", "false", "no":
		c.Logins = "off"
	default:
		return fmt.Errorf("logins must be on or off, not %q", c.Logins)
	}
	switch strings.ToLower(c.Fix) {
	case "", "on", "true", "yes":
		c.Fix = "on"
	case "off", "false", "no":
		c.Fix = "off"
	default:
		return fmt.Errorf("fix must be on or off, not %q", c.Fix)
	}
	for _, p := range c.Ports.Allowed {
		if p < 1 || p > 65535 {
			return fmt.Errorf("ports.allowed: %d is not a port number", p)
		}
	}
	return nil
}
