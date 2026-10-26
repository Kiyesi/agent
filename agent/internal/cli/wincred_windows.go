//go:build windows

package cli

import (
	"errors"
	"syscall"
	"unsafe"
)

// Windows Credential Manager, through advapi32's own calls: the token is
// kept for this Windows user only, never in a file or a process list.
var (
	advapi32       = syscall.NewLazyDLL("advapi32.dll")
	procCredWrite  = advapi32.NewProc("CredWriteW")
	procCredRead   = advapi32.NewProc("CredReadW")
	procCredDelete = advapi32.NewProc("CredDeleteW")
	procCredFree   = advapi32.NewProc("CredFree")
)

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
	errorNotFound           = syscall.Errno(1168)
)

// winCredential is CREDENTIALW, field for field.
type winCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

func credTarget(account string) (*uint16, error) {
	return syscall.UTF16PtrFromString(keychainService + ":" + account)
}

func winCredAvailable() bool { return advapi32.Load() == nil && procCredWrite.Find() == nil }

func winCredSet(account, token string) error {
	target, err := credTarget(account)
	if err != nil {
		return err
	}
	user, err := syscall.UTF16PtrFromString(account)
	if err != nil {
		return err
	}
	blob := []byte(token)
	if len(blob) == 0 {
		return errors.New("an empty token is not kept")
	}
	c := winCredential{
		Type:               credTypeGeneric,
		TargetName:         target,
		CredentialBlobSize: uint32(len(blob)), // #nosec G115 -- a token is a few hundred bytes
		CredentialBlob:     &blob[0],
		Persist:            credPersistLocalMachine,
		UserName:           user,
	}
	if r, _, err := procCredWrite.Call(uintptr(unsafe.Pointer(&c)), 0); r == 0 {
		return err
	}
	return nil
}

func winCredGet(account string) (string, error) {
	target, err := credTarget(account)
	if err != nil {
		return "", err
	}
	var c *winCredential
	if r, _, err := procCredRead.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&c))); r == 0 {
		return "", err
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(c))) //nolint:errcheck // frees memory Windows gave
	if c.CredentialBlobSize == 0 || c.CredentialBlob == nil {
		return "", nil
	}
	return string(unsafe.Slice(c.CredentialBlob, c.CredentialBlobSize)), nil
}

func winCredRemove(account string) error {
	target, err := credTarget(account)
	if err != nil {
		return err
	}
	if r, _, err := procCredDelete.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0); r == 0 && !errors.Is(err, errorNotFound) {
		return err
	}
	return nil
}
