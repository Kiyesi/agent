// Package update replaces the kiyesi program with the newest release from
// get.kiyesi.dev, only after checking the release's signature with the key
// built into the program, and the file's checksum, as install.sh does.
package update

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"hash"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ReleaseKey is the public half of the key every release is signed with
// (OpenSSH ed25519). The private half stays with whoever runs Kiyesi.
//
//go:embed release.pub
var ReleaseKey string

// Namespace is the purpose the signature was made for, so a signature for
// anything else cannot pass as a release's.
const Namespace = "kiyesi-release"

var errBadSignature = errors.New("the release's signature does not match")

// Verify checks an OpenSSH signature (ssh-keygen -Y sign) over message,
// made by the key in trusted for namespace.
func Verify(trusted string, namespace string, message, armored []byte) error {
	want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(trusted)))
	if err != nil {
		return errors.New("the release key built into kiyesi cannot be read")
	}
	block, _ := pem.Decode(armored)
	if block == nil || block.Type != "SSH SIGNATURE" {
		return errBadSignature
	}
	var sig struct {
		Magic     [6]byte
		Version   uint32
		PublicKey []byte
		Namespace string
		Reserved  string
		HashAlg   string
		Signature []byte
	}
	if err := ssh.Unmarshal(block.Bytes, &sig); err != nil || string(sig.Magic[:]) != "SSHSIG" || sig.Version != 1 {
		return errBadSignature
	}
	if !bytes.Equal(sig.PublicKey, want.Marshal()) || sig.Namespace != namespace {
		return errBadSignature
	}
	var h hash.Hash
	switch sig.HashAlg {
	case "sha512":
		h = sha512.New()
	case "sha256":
		h = sha256.New()
	default:
		return errBadSignature
	}
	h.Write(message)
	signed := ssh.Marshal(struct {
		Magic     [6]byte
		Namespace string
		Reserved  string
		HashAlg   string
		Hash      []byte
	}{sig.Magic, namespace, sig.Reserved, sig.HashAlg, h.Sum(nil)})
	var s ssh.Signature
	if err := ssh.Unmarshal(sig.Signature, &s); err != nil {
		return errBadSignature
	}
	if err := want.Verify(signed, &s); err != nil {
		return errBadSignature
	}
	return nil
}

// armor wraps a signature blob the way ssh-keygen writes it; for tests.
func armor(blob []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(blob)
	var out strings.Builder
	out.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for len(b64) > 70 {
		out.WriteString(b64[:70] + "\n")
		b64 = b64[70:]
	}
	out.WriteString(b64 + "\n-----END SSH SIGNATURE-----\n")
	return []byte(out.String())
}
