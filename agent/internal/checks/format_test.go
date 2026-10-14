package checks

import (
	"testing"
	"time"
)

func TestBytesText(t *testing.T) {
	for in, want := range map[uint64]string{
		512 << 20:  "512 MB",
		1 << 30:    "1 GB",
		3900 << 20: "3.8 GB",
		16 << 30:   "16 GB",
	} {
		if got := bytesText(in); got != want {
			t.Errorf("bytesText(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestAgeText(t *testing.T) {
	for in, want := range map[time.Duration]string{
		30 * time.Minute: "under an hour",
		time.Hour:        "1 hour",
		31 * time.Hour:   "31 hours",
		72 * time.Hour:   "3 days",
	} {
		if got := ageText(in); got != want {
			t.Errorf("ageText(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestClockText(t *testing.T) {
	now := time.Date(2026, 10, 8, 15, 0, 0, 0, time.UTC)
	if got := clockText(time.Date(2026, 10, 8, 10, 41, 0, 0, time.UTC), now); got != "10:41" {
		t.Errorf("today: %q", got)
	}
	if got := clockText(time.Date(2026, 10, 7, 23, 5, 0, 0, time.UTC), now); got != "23:05 yesterday" {
		t.Errorf("yesterday: %q", got)
	}
}
