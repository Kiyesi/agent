package dbwatch

import (
	"context"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMySQLGrantsBeyondShowView(t *testing.T) {
	global, onDB := mysqlGrants([]string{
		"GRANT USAGE ON *.* TO `kiyesi_ro`@`%`",
		"GRANT SHOW VIEW ON `shop`.* TO `kiyesi_ro`@`%`",
	})
	if len(global) != 0 || len(onDB) != 0 {
		t.Errorf("the smallest set is not too much: %v %v", global, onDB)
	}
	// MariaDB writes the password hash on the USAGE line: it is not a right.
	global, onDB = mysqlGrants([]string{
		"GRANT PROCESS ON *.* TO `kiyesi_ro`@`%` IDENTIFIED BY PASSWORD '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'",
		"GRANT SELECT, SHOW VIEW ON `shop`.* TO `kiyesi_ro`@`%`",
		"GRANT `reporting` TO `kiyesi_ro`@`%`",
	})
	if !reflect.DeepEqual(global["*.*"], []string{"PROCESS"}) || !reflect.DeepEqual(onDB["`shop`.*"], []string{"SELECT"}) {
		t.Errorf("global %v, on the database %v", global, onDB)
	}
	// SHOW VIEW on every database is more than one database needs.
	global, _ = mysqlGrants([]string{"GRANT SHOW VIEW ON *.* TO `kiyesi_ro`@`localhost`"})
	if !reflect.DeepEqual(global["*.*"], []string{"SHOW VIEW"}) {
		t.Errorf("SHOW VIEW on *.*: %v", global)
	}
}

func TestOnlyKiyesisOwnUserLosesRights(t *testing.T) {
	for name, own := range map[string]bool{"kiyesi_ro": true, "Kiyesi": true, "postgres": false, "shopapp": false, "root": false} {
		if ownUser(name) != own {
			t.Errorf("ownUser(%q) = %v", name, !own)
		}
	}
	got := ownUserInstead("shopapp", []Excess{{What: "It has SELECT."}}, "in mysql", []string{"CREATE USER …"})
	if len(got) != 1 || !got[0].NewUser || !reflect.DeepEqual(got[0].Details, []string{"It has SELECT."}) {
		t.Errorf("own user instead = %+v", got)
	}
}

// The main password, or none, is never Kiyesi's own user: it is told to
// make one, without connecting.
func TestRedisDefaultUser(t *testing.T) {
	for raw, pw := range map[string]string{"redis://127.0.0.1:1": "main", "redis://127.0.0.1:2": "", "redis://default@127.0.0.1:1": "main"} {
		u, _ := url.Parse(raw)
		got := redisExcess(context.Background(), u, Secret{Password: pw})
		if len(got) != 1 || !got[0].NewUser || got[0].Commands[0] != "ACL SETUSER kiyesi_ro on >CHOOSE-A-PASSWORD -@all +info +ping" {
			t.Errorf("%s: %+v", raw, got)
		}
	}
}

// Redis 7 and Valkey say maxclients in INFO, so the read-only user needs
// no CONFIG GET, which shows the main password.
func TestRedisLimitFromInfo(t *testing.T) {
	addr := fakeRedisWith(t, "# Server\r\nredis_version:7.4.1\r\n# Clients\r\nconnected_clients:3\r\nmaxclients:500\r\n")
	u, _ := url.Parse("redis://kiyesi_ro:pw@" + addr)
	var f Figures
	if err := readRedis(context.Background(), u, Secret{Password: "pw"}, &f, time.Now()); err != nil {
		t.Fatal(err)
	}
	if f.MaxConnections == nil || *f.MaxConnections != 500 {
		t.Errorf("max connections = %v, want 500 from INFO", f.MaxConnections)
	}
}

// Run by scripts/db-watch-test.sh: users made as the guide makes them have
// nothing too much (but MySQL's, made for any address in the test, as the
// agent's address there is not known); the old guide's users have what it
// gave; an app's own login and the admin are told to give Kiyesi its own.
// With KIYESI_DB_RIGHTS_FIXED, the commands it gave have been run.
func TestRealRights(t *testing.T) {
	if os.Getenv("KIYESI_DB_POSTGRES") == "" {
		t.Skip("run scripts/db-watch-test.sh")
	}
	ctx := context.Background()
	whats := func(env string) string {
		var b strings.Builder
		for _, x := range TooMuch(ctx, viaCredential(t, "db", os.Getenv(env))) {
			b.WriteString(x.What + " " + strings.Join(x.Details, " ") + " | " + strings.Join(x.Commands, " ; ") + "\n")
			if strings.Contains(strings.Join(x.Commands, " "), "ro-pw") || strings.Contains(x.What, "ro-pw") {
				t.Errorf("%s: a password in the advice", env)
			}
		}
		return b.String()
	}
	for _, env := range []string{"KIYESI_DB_POSTGRES", "KIYESI_DB_MONGO", "KIYESI_DB_REDIS"} {
		if got := whats(env); got != "" {
			t.Errorf("%s: the smallest rights are too much: %s", env, got)
		}
	}
	for _, env := range []string{"KIYESI_DB_MYSQL", "KIYESI_DB_MARIADB"} {
		if got := whats(env); !strings.Contains(got, "from any address") || strings.Count(got, "\n") != 1 {
			t.Errorf("%s: want only the address: %s", env, got)
		}
	}
	type want struct{ env, has string }
	old := []want{
		{"KIYESI_DB_POSTGRES_OLD", "REVOKE pg_monitor, pg_read_all_stats FROM kiyesi_old;"},
		{"KIYESI_DB_POSTGRES_OLD", "REVOKE SELECT ON ALL TABLES IN SCHEMA public FROM kiyesi_old;"},
		{"KIYESI_DB_MYSQL_OLD", "REVOKE PROCESS ON *.* FROM 'kiyesi_old'@'%';"},
		{"KIYESI_DB_MONGO_OLD", `updateUser("kiyesi_old", { roles: [{ role: "kiyesiStats", db: "admin" }] })`},
		{"KIYESI_DB_REDIS_OLD", "ACL SETUSER kiyesi_old -@all +info +ping"},
	}
	if os.Getenv("KIYESI_DB_RIGHTS_FIXED") != "" {
		for _, w := range old {
			if got := whats(w.env); strings.Contains(got, w.has) {
				t.Errorf("%s: still too much after its commands: %s", w.env, got)
			}
		}
		// What is left of the old MySQL user is only its address.
		if got := whats("KIYESI_DB_MYSQL_OLD"); strings.Count(got, "\n") != 1 {
			t.Errorf("old mysql user after its commands: %s", got)
		}
		return
	}
	for _, w := range old {
		if got := whats(w.env); !strings.Contains(got, w.has) {
			t.Errorf("%s: want %q in:\n%s", w.env, w.has, got)
		}
	}
	for _, env := range []string{"KIYESI_DB_POSTGRES_ADMIN", "KIYESI_DB_MYSQL_APP", "KIYESI_DB_REDIS_MAIN"} {
		x := TooMuch(ctx, viaCredential(t, "db", os.Getenv(env)))
		if len(x) != 1 || !x[0].NewUser || !strings.Contains(strings.Join(x[0].Commands, " "), "kiyesi_ro") {
			t.Errorf("%s: want a user of Kiyesi's own: %+v", env, x)
		}
		for _, c := range x[0].Commands {
			if strings.Contains(c, "REVOKE") || strings.Contains(c, "NOSUPERUSER") {
				t.Errorf("%s: takes rights from someone's own login: %s", env, c)
			}
		}
	}
}
