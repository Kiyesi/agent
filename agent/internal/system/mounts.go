package system

import (
	"bufio"
	"bytes"
	"io/fs"
	"strings"
)

// diskTypes are the file systems that hold data. Memory-backed, virtual and
// read-only image file systems (tmpfs, overlay, squashfs) are left out.
var diskTypes = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true,
	"f2fs": true, "jfs": true, "reiserfs": true, "vfat": true, "exfat": true,
}

// Mount is one mounted file system that holds data.
type Mount struct{ Device, Point string }

// DataMounts lists the mounted file systems that hold data, one per device.
func DataMounts(fsys fs.FS) ([]Mount, error) {
	data, err := fs.ReadFile(fsys, "proc/self/mounts")
	if err != nil {
		data, err = fs.ReadFile(fsys, "proc/mounts")
	}
	if err != nil {
		return nil, err
	}
	var out []Mount
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || !diskTypes[f[2]] || seen[f[0]] {
			continue
		}
		point := unescapeMount(f[1])
		if strings.HasPrefix(point, "/snap/") {
			continue
		}
		seen[f[0]] = true
		out = append(out, Mount{Device: f[0], Point: point})
	}
	return out, nil
}

// unescapeMount turns /proc/mounts escapes such as \040 back into characters.
func unescapeMount(s string) string {
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}
