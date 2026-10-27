package cli

import (
	"os/exec"
	"strings"
	"testing"
)

// The SQL in the printed steps reaches the database as written: the shell
// runs nothing from a name in backquotes or with a dollar in it.
func TestSetupSQLPassesThroughTheShell(t *testing.T) {
	sql := "CREATE USER 'kiyesi_ro'@'127.0.0.1' IDENTIFIED BY '%s';\nGRANT SHOW VIEW ON `sh$op`.* TO 'kiyesi_ro'@'127.0.0.1';"
	line := `printf "` + sqlLines(sql) + `" "pw"`
	out, err := exec.Command("sh", "-c", line).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := strings.Replace(sql, "%s", "pw", 1) + "\n"
	if string(out) != want {
		t.Errorf("the shell passed\n%s\nwant\n%s", out, want)
	}
}
