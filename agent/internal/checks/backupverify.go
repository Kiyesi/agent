package checks

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"strings"
)

// A backup that exists is not yet a backup that restores. These read the
// newest backup through, as the tool that restores it would, and say why
// it would fail: a gzip or zip whose checksum is wrong, a tar that stops
// halfway, a database dump that never reached its last line. Only reading:
// nothing is unpacked to disk. Each backup is read once, when it is new.

// verifyLimit is the most a backup is read through. Past it, only its
// start is checked, so a scan never spends minutes on one file.
var verifyLimit int64 = 1 << 30

// unpackedLimit is the most read out of a compressed backup. A backup that
// expands past it (a compression bomb, or simply huge) is not called broken:
// it is checked as far as this, and no further.
var unpackedLimit int64 = 16 << 30

// drain reads r to its end, or to the limit; reaching the limit is not an error.
func drain(r io.Reader) error {
	_, err := io.Copy(io.Discard, io.LimitReader(r, unpackedLimit))
	return err
}

// verdict is what reading a backup found.
type verdict struct {
	ok      bool
	checked bool   // false when this kind of file cannot be read through here
	reason  string // why it would not restore, when !ok
}

// verifyBackup reads one backup file and says whether it would restore.
func verifyBackup(fsys fs.FS, name string, size int64) verdict {
	f, err := fsys.Open(name)
	if err != nil {
		return verdict{ok: false, checked: true, reason: "it cannot be read: " + plainErr(err)}
	}
	defer f.Close()
	if size == 0 {
		return verdict{ok: false, checked: true, reason: "it is empty"}
	}
	br := bufio.NewReaderSize(f, 64<<10)
	head, _ := br.Peek(512)
	deep := size <= verifyLimit
	lower := strings.ToLower(name)
	switch {
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		if !deep {
			return verdict{ok: true, checked: false}
		}
		zr, err := gzip.NewReader(br)
		if err != nil {
			return verdict{ok: false, checked: true, reason: "it is not a whole gzip file"}
		}
		zr.Multistream(true)
		inner := bufio.NewReaderSize(zr, 64<<10)
		innerHead, _ := inner.Peek(512)
		switch {
		case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || isTar(innerHead):
			return readTar(inner)
		case isDump(innerHead):
			return readDump(inner)
		}
		if err := drain(inner); err != nil {
			return verdict{ok: false, checked: true, reason: "it stops partway, or its checksum is wrong (" + plainErr(err) + ")"}
		}
		return verdict{ok: true, checked: true}
	case bytes.HasPrefix(head, []byte("PK\x03\x04")):
		if !deep {
			return verdict{ok: true, checked: false}
		}
		return readZip(br)
	case isTar(head):
		if !deep {
			return verdict{ok: true, checked: false}
		}
		return readTar(br)
	case bytes.HasPrefix(head, []byte("PGDMP")):
		// PostgreSQL's own format: only pg_restore reads it through. Its
		// header is right, which is as far as reading alone can go.
		return verdict{ok: true, checked: false}
	case isDump(head):
		if !deep {
			return verdict{ok: true, checked: false}
		}
		return readDump(br)
	}
	return verdict{ok: true, checked: false}
}

func isTar(head []byte) bool {
	return len(head) >= 262 && bytes.Equal(head[257:262], []byte("ustar"))
}

// dumps are the text dumps that write a last line when they finish.
var dumps = []struct{ start, end, name string }{
	{"-- PostgreSQL database dump", "-- PostgreSQL database dump complete", "pg_dump"},
	{"-- PostgreSQL database cluster dump", "-- PostgreSQL database cluster dump complete", "pg_dumpall"},
	{"-- MySQL dump", "-- Dump completed", "mysqldump"},
	{"-- MariaDB dump", "-- Dump completed", "mariadb-dump"},
}

func isDump(head []byte) bool {
	for _, d := range dumps {
		if bytes.Contains(head, []byte(d.start)) {
			return true
		}
	}
	return false
}

// readDump reads a text dump through and checks it reached its last line:
// a dump cut short by a full disk or a lost connection never writes it.
func readDump(r io.Reader) verdict {
	br := bufio.NewReaderSize(r, 64<<10)
	head, _ := br.Peek(512)
	var want *struct{ start, end, name string }
	for i := range dumps {
		if bytes.Contains(head, []byte(dumps[i].start)) {
			want = &dumps[i]
			break
		}
	}
	tail := make([]byte, 0, 8<<10)
	buf := make([]byte, 64<<10)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			tail = append(tail, buf[:n]...)
			if len(tail) > 8<<10 {
				tail = append(tail[:0], tail[len(tail)-(8<<10):]...)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return verdict{ok: false, checked: true, reason: "it stops partway, or its checksum is wrong (" + plainErr(err) + ")"}
		}
	}
	if want != nil && !bytes.Contains(tail, []byte(want.end)) {
		return verdict{ok: false, checked: true, reason: "the " + want.name + " dump never finished: its last line is missing"}
	}
	return verdict{ok: true, checked: true}
}

func plainErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && i < len(s)-2 {
		s = s[i+2:]
	}
	return s
}
