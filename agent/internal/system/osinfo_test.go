package system

import (
	"testing"
	"testing/fstest"
)

func TestReadOS(t *testing.T) {
	for _, tc := range []struct {
		release, name string
		tested        bool
	}{
		{"NAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nID=ubuntu\nPRETTY_NAME=\"Ubuntu 22.04.5 LTS\"\n", "Ubuntu 22.04", true},
		{"NAME=\"Ubuntu\"\nVERSION_ID=\"26.04\"\nID=ubuntu\n", "Ubuntu 26.04", true},
		{"PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\n", "Debian 12", false},
		{"NAME=\"Ubuntu\"\nVERSION_ID=\"20.04\"\nID=ubuntu\n", "Ubuntu 20.04", false},
	} {
		got := ReadOS(fstest.MapFS{"etc/os-release": {Data: []byte(tc.release)}})
		if got.Name != tc.name || got.Tested != tc.tested {
			t.Errorf("ReadOS = %+v, want %q tested=%v", got, tc.name, tc.tested)
		}
	}
	if got := ReadOS(fstest.MapFS{}); got.Name != "Unknown Linux" || got.Tested {
		t.Errorf("no os-release: %+v", got)
	}
}
