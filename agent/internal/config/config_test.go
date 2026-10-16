package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMissingFileGivesDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "none.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Limits.DiskCriticalPercent != 90 || len(c.Ports.Allowed) != 3 {
		t.Errorf("unexpected defaults: %+v", c)
	}
}

func TestEmptyFileGivesDefaults(t *testing.T) {
	c := Default()
	if err := Parse(nil, &c); err != nil {
		t.Fatal(err)
	}
	if c.Limits.MemoryPercent != 90 {
		t.Errorf("memory_percent = %v", c.Limits.MemoryPercent)
	}
}

func TestOverridesKeepOtherDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := "ports:\n  allowed: [22, 443, 8443]\nbackups:\n  paths: [/var/backups/db]\nlimits:\n  disk_warning_percent: 70\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Ports.Allowed) != 3 || c.Ports.Allowed[2] != 8443 {
		t.Errorf("ports.allowed = %v", c.Ports.Allowed)
	}
	if c.Limits.DiskWarningPercent != 70 || c.Limits.DiskCriticalPercent != 90 {
		t.Errorf("disk limits = %v / %v", c.Limits.DiskWarningPercent, c.Limits.DiskCriticalPercent)
	}
	if c.Backups.Paths[0] != "/var/backups/db" || c.Backups.MaxAgeHours != 24 {
		t.Errorf("backups = %+v", c.Backups)
	}
}

func TestRejectsUnknownKeysAndBadValues(t *testing.T) {
	for name, data := range map[string]string{
		"unknown key":      "limits:\n  dsik_warning_percent: 70\n",
		"warning above":    "limits:\n  disk_warning_percent: 95\n",
		"not a port":       "ports:\n  allowed: [70000]\n",
		"not yaml":         "limits: [",
		"memory over 100":  "limits:\n  memory_percent: 120\n",
		"zero update days": "limits:\n  update_days: 0\n",
		"bad home country": "home_country: Nigeria\n",
	} {
		c := Default()
		if err := Parse([]byte(data), &c); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestHomeCountryAndPaymentData(t *testing.T) {
	// No country is assumed: the team chooses, from any country.
	c := Default()
	if c.HomeCountry != "" {
		t.Errorf("default home country = %q", c.HomeCountry)
	}
	if err := Parse([]byte("home_country: gh\npayment_data: [checkout-db-prod, \"pay.example.com:5432\"]\n"), &c); err != nil {
		t.Fatal(err)
	}
	if c.HomeCountry != "GH" || len(c.PaymentData) != 2 {
		t.Errorf("config = %+v", c)
	}
}

// fix: off forbids sudo kiyesi fix on a server; it is on by default, and
// the ways people write yes and no all work.
func TestFixOnOrOff(t *testing.T) {
	c := Default()
	if err := Parse([]byte(""), &c); err != nil || c.Fix != "on" {
		t.Fatalf("default: %q %v", c.Fix, err)
	}
	for in, want := range map[string]string{"fix: off\n": "off", "fix: false\n": "off", "fix: no\n": "off", "fix: on\n": "on", "fix: true\n": "on", "fix: OFF\n": "off"} {
		c := Default()
		if err := Parse([]byte(in), &c); err != nil || c.Fix != want {
			t.Errorf("%q: %q %v", in, c.Fix, err)
		}
	}
	c = Default()
	if err := Parse([]byte("fix: sometimes\n"), &c); err == nil {
		t.Error("fix: sometimes was accepted")
	}
}
