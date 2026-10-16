package checks

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func gz(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write(data)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func tarOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for name, body := range files {
		_ = w.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))})
		_, _ = w.Write([]byte(body))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func zipOf(t *testing.T, name, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, _ := w.Create(name)
	_, _ = f.Write([]byte(body))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// randomRows is n bytes of rows that do not compress, like real data.
func randomRows(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b) + "\n"
}

const pgDump = "--\n-- PostgreSQL database dump\n--\n\nCREATE TABLE orders (id int);\nCOPY orders (id) FROM stdin;\n1\n2\n\\.\n\n--\n-- PostgreSQL database dump complete\n--\n"

func TestBackupsThatWouldRestore(t *testing.T) {
	big := strings.Repeat("row of data\n", 20000)
	for name, data := range map[string][]byte{
		"db.sql.gz":       gz(t, []byte(pgDump)),
		"site.tar.gz":     gz(t, tarOf(t, map[string]string{"index.html": big})),
		"site.tar":        tarOf(t, map[string]string{"a.txt": "hello"}),
		"uploads.zip":     zipOf(t, "a.txt", big),
		"plain.sql":       []byte(pgDump),
		"mysql.sql":       []byte("-- MySQL dump 10.13\n\nINSERT INTO t VALUES (1);\n-- Dump completed on 2026-10-08 03:00:01\n"),
		"logs.gz":         gz(t, []byte(big)),
		"custom.dump":     []byte("PGDMP\x01\x0e\x00 and the rest"),
		"notes-unknown.x": []byte("anything"),
	} {
		v := verifyBackup(fstest.MapFS{name: {Data: data}}, name, int64(len(data)))
		if !v.ok {
			t.Errorf("%s: %+v", name, v)
		}
		readThrough := name != "custom.dump" && name != "notes-unknown.x"
		if v.checked != readThrough {
			t.Errorf("%s: checked = %v, want %v", name, v.checked, readThrough)
		}
	}
}

func TestBackupsThatWouldNotRestore(t *testing.T) {
	good := gz(t, []byte(strings.Repeat("row\n", 50000)))
	flipped := append([]byte(nil), good...)
	flipped[len(flipped)-6] ^= 0xff // the checksum at the end no longer matches
	tgz := gz(t, tarOf(t, map[string]string{"a.txt": strings.Repeat("x", 4096)}))
	cut := tarOf(t, map[string]string{"a.txt": strings.Repeat("x", 4096)})
	zipped := zipOf(t, "a.txt", strings.Repeat("hello ", 1000))
	badZip := append([]byte(nil), zipped...)
	badZip[60] ^= 0xff // inside the stored file
	for name, tc := range map[string]struct {
		data   []byte
		reason string
	}{
		"empty.sql.gz":      {nil, "it is empty"},
		"cut.sql.gz":        {good[:len(good)/2], "it stops partway"},
		"flipped.gz":        {flipped, "it stops partway, or its checksum is wrong"},
		"cut.tar.gz":        {tgz[:len(tgz)-30], "stops partway"},
		"cut.tar":           {cut[:1000], "it stops partway"},
		"damaged.zip":       {badZip, "inside it is damaged"},
		"unfinished.sql":    {[]byte(strings.TrimSuffix(pgDump, "-- PostgreSQL database dump complete\n--\n")), "the pg_dump dump never finished"},
		"unfinished.sql.gz": {gz(t, []byte("-- MySQL dump 10.13\nINSERT INTO t VALUES (1);\n")), "the mysqldump dump never finished"},
		"notgzip.gz":        {[]byte{0x1f, 0x8b, 0x00}, "it is not a whole gzip file"},
	} {
		v := verifyBackup(fstest.MapFS{name: {Data: tc.data}}, name, int64(len(tc.data)))
		if v.ok || !strings.Contains(v.reason, tc.reason) {
			t.Errorf("%s: %+v, want a reason with %q", name, v, tc.reason)
		}
	}
}

// Past the limit only the start is checked, so a scan never spends minutes
// on one file; it is not called broken.
func TestHugeBackupsAreNotReadThrough(t *testing.T) {
	old := verifyLimit
	verifyLimit = 10
	defer func() { verifyLimit = old }()
	data := gz(t, []byte("cut short"))[:12]
	v := verifyBackup(fstest.MapFS{"big.gz": {Data: data}}, "big.gz", int64(len(data)))
	if !v.ok || v.checked {
		t.Fatalf("%+v", v)
	}
}

func TestBackupsCheckOpensTheNewestOnceAndNoticesShrinking(t *testing.T) {
	e := newTestEnv()
	e.cfg.Backups.Paths = []string{"/var/backups/db"}
	full := gz(t, []byte(strings.Replace(pgDump, "1\n2\n", randomRows(t, 3<<20), 1)))
	e.fs["var/backups/db/2026-10-07.sql.gz"] = &fstest.MapFile{Data: full, ModTime: now.Add(-25 * time.Hour)}
	e.fs["var/backups/db/2026-10-08.sql.gz"] = &fstest.MapFile{Data: gz(t, []byte(strings.Replace(pgDump, "1\n2\n", randomRows(t, 3<<20), 1))), ModTime: now.Add(-1 * time.Hour)}
	r := run(t, backupsCheck{}, e)
	wantStatus(t, r, StatusPass)
	if r.Vars["opens"] != ", and it opens" {
		t.Fatalf("vars = %v", r.Vars)
	}
	// Read once: a damaged copy under the same name, size and time is not read again.
	key := "backup/var/backups/db"
	if !strings.HasSuffix(strings.Split(e.state.M[key], "#")[1], "|") || !strings.HasPrefix(strings.Split(e.state.M[key], "#")[1], "ok") {
		t.Fatalf("state = %q", e.state.M[key])
	}

	// The next night's dump is a fraction of the size: shrunk.
	tiny := gz(t, []byte(pgDump))
	e.fs["var/backups/db/2026-10-09.sql.gz"] = &fstest.MapFile{Data: tiny, ModTime: now.Add(-10 * time.Minute)}
	r = run(t, backupsCheck{}, e)
	wantStatus(t, r, StatusFail, "shrank")
	if v := r.Findings[0].Vars; v["file"] != "/var/backups/db/2026-10-09.sql.gz" || v["before"] == "" || v["size"] == "" {
		t.Fatalf("vars = %v", v)
	}
	// Still said on the next scan, from what was remembered.
	wantStatus(t, run(t, backupsCheck{}, e), StatusFail, "shrank")

	// A dump that never finished is critical: it would not restore.
	e.fs["var/backups/db/2026-10-10.sql.gz"] = &fstest.MapFile{Data: gz(t, []byte("--\n-- PostgreSQL database dump\n--\nCOPY orders")), ModTime: now.Add(-5 * time.Minute)}
	r = run(t, backupsCheck{}, e)
	wantStatus(t, r, StatusFail, "unreadable")
	if !strings.Contains(r.Findings[0].Vars["reason"], "the pg_dump dump never finished") {
		t.Fatalf("vars = %v", r.Findings[0].Vars)
	}
}

func TestDamagedTarHeaderIsCaught(t *testing.T) {
	data := tarOf(t, map[string]string{"a.txt": "hello"})
	data[10] ^= 0xff // inside the first file's name: its header checksum no longer matches
	v := verifyBackup(fstest.MapFS{"site.tar": {Data: data}}, "site.tar", int64(len(data)))
	if v.ok || !strings.Contains(v.reason, "header inside it is damaged") {
		t.Fatalf("%+v", v)
	}
}
