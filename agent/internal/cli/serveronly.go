package cli

import (
	"runtime"

	"github.com/spf13/cobra"
)

// hostOS is the system kiyesi runs on. Tests replace it.
var hostOS = runtime.GOOS

// serverOnly are the commands that read or change the server they run on.
// They run on a Linux server; every other command asks the service and
// runs on any computer.
var serverOnly = map[string]bool{
	"kiyesi agent": true, "kiyesi breach-check": true, "kiyesi connect": true,
	"kiyesi databases check": true, "kiyesi databases encrypt": true, "kiyesi databases setup": true, "kiyesi fix": true, "kiyesi fix undo": true,
	"kiyesi guard": true, "kiyesi guard list": true, "kiyesi guard undo": true,
	"kiyesi keys": true, "kiyesi keys remove": true, "kiyesi job done": true, "kiyesi job start": true,
	"kiyesi scan": true, "kiyesi uninstall": true,
}

// serverOnlyHere refuses a server command on Windows, where there is no
// Linux server for it to read, and says what to run instead.
func serverOnlyHere(cmd *cobra.Command) error {
	path := cmd.CommandPath()
	if hostOS != "windows" || !serverOnly[path] {
		return nil
	}
	return &exitError{code: ExitUsage, msg: path + " runs on a Linux server, as it reads the server it runs on.\n" +
		"Run it there, over SSH. From this computer, ask the service instead: kiyesi servers, kiyesi server <name>, kiyesi findings."}
}
