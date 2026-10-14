package system

import (
	"bufio"
	"bytes"
	"io/fs"
	"strings"
)

// tested lists the systems the pipeline runs the whole scan on.
var tested = map[string]bool{"ubuntu 22.04": true, "ubuntu 24.04": true, "ubuntu 26.04": true}

// ReadOS reads etc/os-release from fsys.
func ReadOS(fsys fs.FS) OSInfo {
	data, err := fs.ReadFile(fsys, "etc/os-release")
	if err != nil {
		data, err = fs.ReadFile(fsys, "usr/lib/os-release")
	}
	if err != nil {
		return OSInfo{Name: "Unknown Linux"}
	}
	vals := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		vals[k] = strings.Trim(v, `"'`)
	}
	info := OSInfo{ID: vals["ID"], VersionID: vals["VERSION_ID"]}
	name := vals["NAME"]
	switch {
	case name != "" && info.VersionID != "":
		// "Ubuntu" + "22.04" reads better than PRETTY_NAME's "Ubuntu 22.04.5 LTS".
		info.Name = strings.TrimSuffix(name, " GNU/Linux") + " " + info.VersionID
	case vals["PRETTY_NAME"] != "":
		info.Name = vals["PRETTY_NAME"]
	default:
		info.Name = "Unknown Linux"
	}
	info.Tested = tested[strings.ToLower(info.ID)+" "+info.VersionID]
	return info
}
