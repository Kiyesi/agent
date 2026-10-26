//go:build !windows

package cli

import "errors"

var errNotWindows = errors.New("only Windows has Credential Manager")

func winCredAvailable() bool            { return false }
func winCredSet(string, string) error   { return errNotWindows }
func winCredGet(string) (string, error) { return "", errNotWindows }
func winCredRemove(string) error        { return errNotWindows }
