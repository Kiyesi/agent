package checks

import (
	"testing"
	"testing/fstest"
)

func TestParseProcNetKeepsPublicListeners(t *testing.T) {
	// 0.0.0.0:22 and 0.0.0.0:6379 listen everywhere; 127.0.0.1:5432 is local;
	// 10.0.0.5:9000 is private; the last line is an established connection.
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 00000000:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 2 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   113        0 3 1 0000000000000000 100 0 0 10 0
   3: 0500000A:2328 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4 1 0000000000000000 100 0 0 10 0
   4: 0F02000A:0016 0101A8C0:D2F0 01 00000000:00000000 02:00051A4B 00000000     0        0 5 4 0000000000000000 20 4 30 10 -1
`
	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0CEA 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 7 1 0000000000000000 100 0 0 10 0
`
	ls, err := readListeners(fstest.MapFS{"proc/net/tcp": {Data: []byte(tcp)}, "proc/net/tcp6": {Data: []byte(tcp6)}})
	if err != nil {
		t.Fatal(err)
	}
	var ports []int
	for _, l := range ls {
		ports = append(ports, l.Port)
	}
	if len(ports) != 3 || ports[0] != 22 || ports[1] != 443 || ports[2] != 6379 {
		t.Errorf("ports = %v, want [22 443 6379]", ports)
	}
}

func TestParseUFW(t *testing.T) {
	out := []byte(`Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80,443/tcp                 ALLOW IN    Anywhere
6000:6007/tcp              ALLOW IN    Anywhere
5432                       ALLOW IN    10.0.0.0/8
22/tcp (v6)                ALLOW IN    Anywhere (v6)
`)
	r := parseUFW(out)
	for port, want := range map[int]bool{22: true, 80: true, 443: true, 6003: true, 5432: false, 6379: false} {
		if got := r.allows(port); got != want {
			t.Errorf("allows(%d) = %v, want %v", port, got, want)
		}
	}
	open := parseUFW([]byte("Default: allow (incoming), allow (outgoing)\n\nTo Action From\n-- ------ ----\n6379 DENY IN Anywhere\n"))
	if open.allows(6379) || !open.allows(8080) {
		t.Error("default allow with a deny rule was misread")
	}
}

func TestSSHConfigFirstValueWinsAndIncludesFirst(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/ssh/sshd_config":                      {Data: []byte("Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM yes\nMatch User backup\n  PasswordAuthentication yes\n")},
		"etc/ssh/sshd_config.d/50-cloud-init.conf": {Data: []byte("PasswordAuthentication yes\n")},
	}
	m, ok := parseSSHDConfig(fsys)
	if !ok {
		t.Fatal("config not found")
	}
	if !passwordLogin(m) {
		t.Error("50-cloud-init.conf turns passwords on and is read first, so password login is allowed")
	}
	fsys["etc/ssh/sshd_config.d/00-kiyesi-no-password.conf"] = &fstest.MapFile{Data: []byte("PasswordAuthentication no\n")}
	m, _ = parseSSHDConfig(fsys)
	if passwordLogin(m) {
		t.Error("00-kiyesi-no-password.conf sorts first, so password login is off")
	}
}

func TestRootLogin(t *testing.T) {
	noKeys := fstest.MapFS{}
	withKeys := fstest.MapFS{"root/.ssh/authorized_keys": {Data: []byte("# comment\nssh-ed25519 AAAA test\n")}}
	cases := []struct {
		fs   fstest.MapFS
		v    string
		want bool
	}{
		{noKeys, "yes", true},
		{noKeys, "no", false},
		{noKeys, "prohibit-password", false},
		{withKeys, "prohibit-password", true},
		{withKeys, "", true},
		{withKeys, "forced-commands-only", false},
	}
	for _, c := range cases {
		if got := rootLogin(c.fs, c.v); got != c.want {
			t.Errorf("rootLogin(%q) = %v, want %v", c.v, got, c.want)
		}
	}
}
