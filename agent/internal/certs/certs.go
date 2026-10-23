// Package certs checks Kiyesi's health certificates: a server's grade, the
// checks it passed and its break-in check, signed by the Kiyesi service
// with Ed25519. The service's public key is built into kiyesi, so a
// certificate file can be checked with no network at all.
package certs

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// signingKey is the service's public key, raw, in base64. It is set before
// a release; empty, kiyesi checks with the key the service publishes.
//
//go:embed signing.pub
var signingKey string

// Body is what a certificate says, as the service signed it.
type Body struct {
	V      int    `json:"v"`
	ID     string `json:"id"`
	Issuer string `json:"issuer"`
	Team   string `json:"team"`
	Server string `json:"server"`
	OS     string `json:"os"`
	Grade  struct {
		Letter string `json:"letter"`
		Score  int    `json:"score"`
	} `json:"grade"`
	Checks struct {
		Passed  int `json:"passed"`
		BasedOn int `json:"basedOn"`
		Total   int `json:"total"`
	} `json:"checks"`
	Critical  int       `json:"critical"`
	Warnings  int       `json:"warnings"`
	BreakIn   string    `json:"breakIn"`
	ScannedAt time.Time `json:"scannedAt"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// File is a certificate as downloaded: the signed text and its signature.
type File struct {
	Certificate string `json:"certificate"`
	Signature   string `json:"signature"`
	// From the service only, when checked by link.
	Status    string `json:"status,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
}

// BuiltInKey is the key built into this kiyesi, or "".
func BuiltInKey() string { return strings.TrimSpace(signingKey) }

// ErrBadSignature means the certificate was changed, or not made by Kiyesi.
var ErrBadSignature = errors.New("the signature does not match: this certificate was changed, or was not made by Kiyesi")

// Check verifies the signature with the key, raw base64, and reads the body.
func Check(f File, key string) (Body, error) {
	var b Body
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return b, errors.New("no key to check the signature with")
	}
	sig, err := base64.StdEncoding.DecodeString(f.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), []byte(f.Certificate), sig) {
		return b, ErrBadSignature
	}
	if err := json.Unmarshal([]byte(f.Certificate), &b); err != nil {
		return b, errors.New("the signed text is not a certificate")
	}
	if b.V != 1 || b.Issuer != "Kiyesi" {
		return b, errors.New("this is not a certificate this kiyesi can read; update it with sudo kiyesi update")
	}
	return b, nil
}

// IDFrom reads a certificate's id from its link or the id itself.
func IDFrom(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "id="); i >= 0 {
		s = s[i+3:]
		if j := strings.IndexAny(s, "&#"); j >= 0 {
			s = s[:j]
		}
	}
	if len(s) != 24 || strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") != "" {
		return "", false
	}
	return s, true
}
