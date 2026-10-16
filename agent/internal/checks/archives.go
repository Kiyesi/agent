package checks

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strconv"
	"strings"
)

// Small readers for tar and zip, only as far as checking a backup needs:
// every header whole, every file's bytes there, every checksum right. Go's
// own archive packages would do it too, at 127 KB more in the agent, which
// must stay under 20 MB.

// readTar walks a tar's headers and skips each file's bytes, checking each
// header's checksum, to the two empty blocks that end a whole archive.
func readTar(r io.Reader) verdict {
	block := make([]byte, 512)
	files := 0
	for {
		if _, err := io.ReadFull(r, block); err != nil {
			return verdict{ok: false, checked: true, reason: "it stops partway (" + plainErr(err) + ")"}
		}
		if allZero(block) {
			break
		}
		want, err := octal(block[148:156])
		if err != nil || int64(headerSum(block)) != want {
			return verdict{ok: false, checked: true, reason: "a file's header inside it is damaged"}
		}
		size, err := tarSize(block[124:136])
		if err != nil {
			return verdict{ok: false, checked: true, reason: "a file's header inside it is damaged"}
		}
		if t := block[156]; t == '0' || t == 0 || t == '7' {
			files++
		}
		skip := (size + 511) &^ 511
		if n, err := io.Copy(io.Discard, io.LimitReader(r, min(skip, unpackedLimit))); err != nil || n < min(skip, unpackedLimit) {
			return verdict{ok: false, checked: true, reason: "it stops partway, in the middle of a file"}
		}
		if skip > unpackedLimit {
			return verdict{ok: true, checked: false}
		}
	}
	if files == 0 {
		return verdict{ok: false, checked: true, reason: "it holds no files"}
	}
	return verdict{ok: true, checked: true}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// headerSum is the tar checksum: every byte, the checksum field as spaces.
func headerSum(b []byte) int {
	sum := 0
	for i, c := range b {
		if i >= 148 && i < 156 {
			c = ' '
		}
		sum += int(c)
	}
	return sum
}

func octal(b []byte) (int64, error) {
	s := strings.Trim(string(b), " \x00")
	if s == "" {
		return 0, nil
	}
	return strconv.ParseInt(s, 8, 64)
}

// tarSize reads a size in octal, or in base-256 for files over 8 GB.
func tarSize(b []byte) (int64, error) {
	if len(b) > 0 && b[0]&0x80 != 0 {
		var n int64
		for i, c := range b {
			if i == 0 {
				c &= 0x7f
			}
			if n > (1<<55)-1 {
				return 0, errors.New("size too large")
			}
			n = n<<8 | int64(c)
		}
		return n, nil
	}
	return octal(b)
}

// readZip reads a zip from the start: each file's local header, its bytes
// unpacked and checked against their CRC, up to the central directory.
func readZip(r *bufio.Reader) verdict {
	files := 0
	hdr := make([]byte, 30)
	for {
		sig, err := r.Peek(4)
		if err != nil {
			return verdict{ok: false, checked: true, reason: "it stops partway"}
		}
		switch {
		case bytes.Equal(sig, []byte("PK\x01\x02")), bytes.Equal(sig, []byte("PK\x05\x06")):
			if files == 0 {
				return verdict{ok: false, checked: true, reason: "it holds no files"}
			}
			return verdict{ok: true, checked: true}
		case !bytes.Equal(sig, []byte("PK\x03\x04")):
			return verdict{ok: false, checked: true, reason: "it is not a whole zip file"}
		}
		if _, err := io.ReadFull(r, hdr); err != nil {
			return verdict{ok: false, checked: true, reason: "it stops partway"}
		}
		le := binary.LittleEndian
		flags, method := le.Uint16(hdr[6:]), le.Uint16(hdr[8:])
		crc, csize := le.Uint32(hdr[14:]), int64(le.Uint32(hdr[18:]))
		nameLen, extraLen := int64(le.Uint16(hdr[26:])), int64(le.Uint16(hdr[28:]))
		name := make([]byte, nameLen)
		if _, err := io.ReadFull(r, name); err != nil {
			return verdict{ok: false, checked: true, reason: "it stops partway"}
		}
		if _, err := io.CopyN(io.Discard, r, extraLen); err != nil {
			return verdict{ok: false, checked: true, reason: "it stops partway"}
		}
		descriptor := flags&0x8 != 0
		// Zip64 sizes, encryption, or stored data whose size comes only after
		// it: past what a simple read can check. Not broken; not checked.
		if csize == 0xffffffff || flags&0x1 != 0 || (descriptor && method == 0) || (method != 0 && method != 8) {
			return verdict{ok: true, checked: false}
		}
		var data io.Reader
		var counted *countingReader
		if method == 0 {
			data = io.LimitReader(r, csize)
		} else {
			if descriptor {
				counted = &countingReader{r: r}
				data = flate.NewReader(counted)
			} else {
				data = flate.NewReader(io.LimitReader(r, csize))
			}
		}
		h := crc32.NewIEEE()
		if _, err := io.Copy(h, io.LimitReader(data, unpackedLimit)); err != nil {
			return verdict{ok: false, checked: true, reason: fmt.Sprintf("%s inside it is damaged (%s)", name, plainErr(err))}
		}
		if descriptor {
			// The CRC follows the data, with or without its own signature.
			d := make([]byte, 16)
			if _, err := io.ReadFull(r, d[:4]); err != nil {
				return verdict{ok: false, checked: true, reason: "it stops partway"}
			}
			if bytes.Equal(d[:4], []byte("PK\x07\x08")) {
				if _, err := io.ReadFull(r, d[:4]); err != nil {
					return verdict{ok: false, checked: true, reason: "it stops partway"}
				}
			}
			crc = le.Uint32(d[:4])
			if _, err := io.CopyN(io.Discard, r, 8); err != nil {
				return verdict{ok: false, checked: true, reason: "it stops partway"}
			}
		}
		if h.Sum32() != crc {
			return verdict{ok: false, checked: true, reason: fmt.Sprintf("%s inside it is damaged (its checksum is wrong)", name)}
		}
		files++
	}
}

// countingReader passes reads through; flate reads only what it needs from
// a bufio.Reader, so the descriptor after the data is left to read.
type countingReader struct{ r *bufio.Reader }

func (c *countingReader) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *countingReader) ReadByte() (byte, error)    { return c.r.ReadByte() }
