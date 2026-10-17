package checks

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

func smallThresholds(t *testing.T) {
	big, waste := bigLogBytes, dockerWasteBytes
	bigLogBytes, dockerWasteBytes = 10, 1000
	t.Cleanup(func() { bigLogBytes, dockerWasteBytes = big, waste })
}

func TestLeftoversFindsWhatDevelopmentLeftBehind(t *testing.T) {
	smallThresholds(t)
	e := newTestEnv().
		file("srv/shop/.env", "DB_HOST=db\nAPP_DEBUG=true\nAPP_KEY=base64:abc\n").
		file("srv/shop/.env.local.example", "APP_DEBUG=true\n").
		file("srv/api/.env.development", "NODE_ENV=development\n").
		file("srv/api/.env", "NODE_ENV=production\nDEBUG=express:*\n").
		file("var/www/blog/wp-config.php", "<?php\ndefine( 'WP_DEBUG', true );\n").
		file("var/www/shop/.git/HEAD", "ref: refs/heads/main\n").
		file("var/www/shop/index.php", "<?php\n").
		file("var/www/shop/node_modules/x/.git/HEAD", "ref\n").
		file("var/log/nginx/access.log", strings.Repeat("x", 20)).
		file("var/log/syslog", "small\n").
		file("var/lib/docker/containers/c1/c1-json.log", strings.Repeat("y", 30)).
		file("var/lib/docker/containers/c2/c2-json.log", strings.Repeat("y", 30))
	e.docker = fakeDocker{
		cs: []system.Container{
			{ID: "c1", Name: "pma", Image: "phpmyadmin:5.2", Status: "running", Ports: []system.PublishedPort{{HostIP: "0.0.0.0", HostPort: 8080}}},
			{ID: "c2", Name: "mail", Image: "docker.io/axllent/mailpit@sha256:abc", Status: "running", LogMaxSize: "20m", Ports: []system.PublishedPort{{HostIP: "127.0.0.1", HostPort: 8025}}},
			{ID: "c3", Name: "api", Image: "ghcr.io/acme/api:1.4", Status: "running", Env: []string{"PORT=3000", "NODE_ENV=development"}},
			{ID: "c4", Name: "old-adminer", Image: "adminer", Status: "exited"},
		},
		usage: system.DiskUsage{UnusedImages: 900, UnusedImageCount: 3, BuildCache: 300},
	}
	r := run(t, leftoversCheck{}, e)
	wantStatus(t, r, StatusFail,
		"big-container-log", "big-log", "debug", "debug", "debug-container", "dev-tool", "dev-tool-public", "docker-waste", "git-folder")
	by := map[string][]map[string]string{}
	for _, f := range r.Findings {
		by[f.Key] = append(by[f.Key], f.Vars)
	}
	if v := by["big-container-log"][0]; v["name"] != "pma" {
		t.Errorf("container log = %v; mail has a size limit", v)
	}
	if v := by["big-log"][0]; v["path"] != "/var/log/nginx/access.log" || v["size"] == "" {
		t.Errorf("big log = %v", v)
	}
	if v := by["debug"]; v[0]["path"] != "/srv/shop/.env" || v[0]["setting"] != "APP_DEBUG=true" || v[1]["setting"] != "WP_DEBUG=true" {
		t.Errorf("debug = %v; the example and development files are expected to have it", v)
	}
	if v := by["debug-container"][0]; v["name"] != "api" || v["setting"] != "NODE_ENV=development" {
		t.Errorf("debug container = %v", v)
	}
	if by["dev-tool"][0]["tool"] != "Mailpit" || by["dev-tool-public"][0]["tool"] != "phpMyAdmin" {
		t.Errorf("dev tools = %v %v", by["dev-tool"], by["dev-tool-public"])
	}
	if v := by["git-folder"]; len(v) != 1 || v[0]["path"] != "/var/www/shop/.git" {
		t.Errorf("git folders = %v", v)
	}
	// No value but the debug setting's own ever reaches the report.
	for _, f := range r.Findings {
		for _, v := range f.Vars {
			if strings.Contains(v, "base64") || strings.Contains(v, "3000") {
				t.Errorf("a value leaked: %v", f.Vars)
			}
		}
	}
}

func TestLeftoversPassesOnACleanServer(t *testing.T) {
	smallThresholds(t)
	e := newTestEnv().file("srv/shop/.env", "APP_DEBUG=false\nNODE_ENV=production\n").file("var/log/syslog", "ok\n")
	e.docker = fakeDocker{usage: system.DiskUsage{UnusedImages: 400}}
	wantStatus(t, run(t, leftoversCheck{}, e), StatusPass)
}

func TestLeftoversNeedsRootForWhatOnlyRootReads(t *testing.T) {
	e := newTestEnv()
	e.root = false
	e.docker = fakeDocker{err: system.ErrNeedsRoot}
	wantStatus(t, run(t, leftoversCheck{}, e), StatusSkip)
	e.fs["srv/x/.env"] = &fstest.MapFile{Data: []byte("FLASK_DEBUG=1\n")}
	wantStatus(t, run(t, leftoversCheck{}, e), StatusFail, "debug")
}

// Every language's own debug or development switch, and its production value.
func TestDebugSettingsInEveryLanguage(t *testing.T) {
	for line, want := range map[string]string{
		"APP_DEBUG=true":                         "APP_DEBUG=true",  // PHP: Laravel, Symfony
		"SYMFONY_ENV=dev":                        "SYMFONY_ENV=dev", // PHP: older Symfony
		"NODE_ENV=development":                   "NODE_ENV=development",
		"FLASK_DEBUG=1":                          "FLASK_DEBUG=1", // Python
		"DJANGO_DEBUG=True":                      "DJANGO_DEBUG=true",
		"RAILS_ENV=development":                  "RAILS_ENV=development",           // Ruby
		"GIN_MODE=debug":                         "GIN_MODE=debug",                  // Go
		"export SPRING_PROFILES_ACTIVE=prod,dev": "SPRING_PROFILES_ACTIVE=prod,dev", // Java
		"QUARKUS_PROFILE=dev":                    "QUARKUS_PROFILE=dev",
		"MICRONAUT_ENVIRONMENTS=local":           "MICRONAUT_ENVIRONMENTS=local",
		"MIX_ENV=dev":                            "MIX_ENV=dev",                        // Elixir
		"ASPNETCORE_ENVIRONMENT=Development":     "ASPNETCORE_ENVIRONMENT=development", // .NET
		"DOTNET_ENVIRONMENT=Development":         "DOTNET_ENVIRONMENT=development",
		"GIN_MODE=release":                       "",
		"SPRING_PROFILES_ACTIVE=prod,devops":     "",
		"MIX_ENV=prod":                           "",
		"DEBUG=express:*":                        "",
	} {
		got, _ := debugSetting(line)
		if got != want {
			t.Errorf("%s: %q, want %q", line, got, want)
		}
	}
}

func TestDevToolNames(t *testing.T) {
	for image, want := range map[string]string{
		"dpage/pgadmin4:8.12":            "pgAdmin",
		"mongo-express":                  "mongo-express",
		"rediscommander/redis-commander": "Redis Commander",
		"registry.example.com/adminer:4": "Adminer",
		"postgres:17":                    "",
		"ghcr.io/acme/mailer-api:2":      "",
	} {
		got, _ := devToolOf(image)
		if got != want {
			t.Errorf("%s: %q, want %q", image, got, want)
		}
	}
}
