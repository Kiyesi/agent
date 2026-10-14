package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContainersSettingIsRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("containers:\n  include: [\"shop-*\"]\n  exclude: [\"kiyesi-drill-*\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Containers.Include) != 1 || c.Containers.Include[0] != "shop-*" || c.Containers.Exclude[0] != "kiyesi-drill-*" {
		t.Errorf("containers = %+v", c.Containers)
	}
}
