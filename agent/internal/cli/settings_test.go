package cli

import (
	"strings"
	"testing"

	"github.com/kiyesi/kiyesi/agent/internal/config"
)

func TestSettingsOnlyRootMayReadSaySudo(t *testing.T) {
	msg := settingsErr(config.ErrRootOnly, "scan").Error()
	if !strings.Contains(msg, "sudo kiyesi scan") || strings.Contains(msg, "/etc/kiyesi") || strings.Contains(msg, "move it away") {
		t.Errorf("message = %q", msg)
	}
}
