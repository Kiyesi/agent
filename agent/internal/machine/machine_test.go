package machine

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

const id = "4c4c4544004a4b1080354ac04f4e3332"

// The hash is sha256 of "kiyesi-machine-v1:" and the ID, in lowercase hex,
// as the API expects.
func TestHashOfAKnownID(t *testing.T) {
	sum := sha256.Sum256([]byte("kiyesi-machine-v1:" + id))
	want := hex.EncodeToString(sum[:])
	if got := Of(id); got != want || len(got) != 64 {
		t.Fatalf("Of = %q, want %q", got, want)
	}
	if got := HashFrom([]string{write(t, "machine-id", id+"\n")}); got != want {
		t.Fatalf("HashFrom = %q, want %q", got, want)
	}
}

// Without /etc/machine-id, the D-Bus file is used; an empty first file is
// skipped too.
func TestFallsBackToTheSecondFile(t *testing.T) {
	second := write(t, "dbus-machine-id", "  "+id+"\n")
	if got := HashFrom([]string{filepath.Join(t.TempDir(), "none"), second}); got != Of(id) {
		t.Fatalf("missing first: got %q", got)
	}
	if got := HashFrom([]string{write(t, "empty", "\n"), second}); got != Of(id) {
		t.Fatalf("empty first: got %q", got)
	}
}

// No readable file, or no valid ID, gives "", so the field is left out.
func TestEmptyWhenMissingOrNotAnID(t *testing.T) {
	for name, content := range map[string]string{
		"empty":   "",
		"spaces":  "   \n",
		"short":   "4c4c4544004a4b10",
		"long":    id + "00",
		"not hex": "zz4c4544004a4b1080354ac04f4e3332",
	} {
		if got := HashFrom([]string{write(t, "id", content)}); got != "" {
			t.Errorf("%s: got %q, want empty", name, got)
		}
	}
	if got := HashFrom([]string{filepath.Join(t.TempDir(), "none")}); got != "" {
		t.Errorf("missing: got %q", got)
	}
	if got := HashFrom(nil); got != "" {
		t.Errorf("no paths: got %q", got)
	}
}

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
