package pullcheck

import (
	"encoding/json"
	"os"
	"testing"
)

// testdata/versions.json is shared with the API's list.ts: both sides must
// give these answers. Its expected values were made by list.ts itself.
func TestVersionCasesSharedWithTheAPI(t *testing.T) {
	raw, err := os.ReadFile("testdata/versions.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases struct {
		Compare []struct {
			A, B string
			Want int
		} `json:"compare"`
		Covers []struct {
			All      bool     `json:"all"`
			Versions []string `json:"versions"`
			Ranges   []Range  `json:"ranges"`
			Version  string   `json:"version"`
			Want     bool     `json:"want"`
		} `json:"covers"`
		NameKey []struct {
			Eco, Name, Want string
		} `json:"nameKey"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases.Compare) < 30 || len(cases.Covers) < 15 || len(cases.NameKey) < 10 {
		t.Fatal("the shared cases are missing")
	}
	for _, c := range cases.Compare {
		if got := CompareVersions(c.A, c.B); got != c.Want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.A, c.B, got, c.Want)
		}
	}
	for _, c := range cases.Covers {
		e := Entry{All: c.All, Versions: c.Versions, Ranges: c.Ranges}
		if got := Covers(e, c.Version); got != c.Want {
			t.Errorf("Covers(%+v, %q) = %v, want %v", e, c.Version, got, c.Want)
		}
	}
	for _, c := range cases.NameKey {
		if got := NameKey(c.Eco, c.Name); got != c.Want {
			t.Errorf("NameKey(%s, %q) = %q, want %q", c.Eco, c.Name, got, c.Want)
		}
	}
}
