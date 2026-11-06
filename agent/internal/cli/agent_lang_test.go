package cli

import (
	"context"
	"testing"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/system"
)

func TestReadingLanguagesNeverStopsTheAgent(t *testing.T) {
	// A system that cannot be read at all: nothing found, and no panic.
	r := readLanguages(context.Background(), &system.System{})
	if len(r.Sources) != 0 {
		t.Errorf("sources = %+v", r.Sources)
	}
	if langFirstAfter < 5*time.Minute || langEvery < time.Hour {
		t.Errorf("language packages read too soon or too often: %v, %v", langFirstAfter, langEvery)
	}
	if agentMemory > 200<<20 {
		t.Errorf("the agent's heap must stay well under its service's 256 MB: %d", agentMemory)
	}
}
