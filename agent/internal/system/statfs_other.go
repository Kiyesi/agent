//go:build !linux

package system

import "errors"

// Statfs is only available on Linux.
func Statfs(string) (Usage, error) { return Usage{}, errors.New("disk usage is read only on Linux") }
