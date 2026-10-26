package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kiyesi/kiyesi/agent/internal/render"
)

func TestGradeMoveReadsEvenly(t *testing.T) {
	var b bytes.Buffer
	w := render.NewWriter(&b, []string{"NO_COLOR=1"})
	for _, c := range []struct {
		bl   string
		bs   int
		al   string
		as   int
		want string
	}{
		{"F", 25, "F", 35, "GRADE  F 25 → F 35/100  +10"},
		{"B", 85, "A", 95, "GRADE  B 85 → A 95/100  +10 🎉"},
		{"A", 95, "B", 80, "GRADE  A 95 → B 80/100  −15"},
		{"A", 90, "A", 95, "GRADE  A 90 → A 95/100  +5"},
		{"A", 95, "A", 100, "GRADE  A 95 → A 100/100  +5 🎉"},
	} {
		b.Reset()
		_, _ = w.Write([]byte(render.GradeMove(c.bl, c.bs, c.al, c.as)))
		if got := b.String(); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

// No scan offers kiyesi fix: the report gives only the commands a person
// reviews and runs.
func TestScanNeverOffersKiyesiFix(t *testing.T) {
	fixServer(t)
	code, out, errOut := runFixCLI(t, "", "scan")
	if code != ExitOK && code != ExitFindings {
		t.Fatalf("%d %q", code, errOut)
	}
	if strings.Contains(out, "kiyesi fix") || strings.Contains(out, "Kiyesi can fix") {
		t.Errorf("the scan offers kiyesi fix:\n%s", out)
	}
}
