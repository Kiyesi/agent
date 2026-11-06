//go:build !linux

package system

import "os"

// dropCache is Linux's alone; elsewhere the system's cache is left as it is.
func dropCache(*os.File) {}
