// Package cloudlogin signs in to a database with the server's own cloud
// identity or a vault, so no password is stored on the server: AWS (RDS
// IAM tokens, Secrets Manager, and the signed request Vault's AWS sign-in
// checks), Google Cloud and Azure (tokens from the instance's metadata
// service), and HashiCorp Vault. It talks to each over plain HTTPS with the
// standard library, so the agent stays small; AWS's signing is written here
// and checked against AWS's own library in the tests.
package cloudlogin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AWSCredentials are the server role's short-lived keys, held only in memory.
type AWSCredentials struct {
	AccessKeyID, SecretAccessKey, SessionToken string
	// Expires is when the keys stop working; zero for keys that do not.
	Expires time.Time
}

const sigAlgorithm = "AWS4-HMAC-SHA256"

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// uriEncode is AWS's encoding: everything but A-Z a-z 0-9 - _ . ~ escaped,
// and "/" kept in a path.
func uriEncode(s string, path bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' || (path && c == '/') {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return b.String()
}

// canonicalQuery is the query sorted by name, then value, each encoded.
func canonicalQuery(q url.Values) string {
	var pairs []string
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, uriEncode(k, false)+"="+uriEncode(v, false))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

func signingKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

// signRequest adds AWS Signature Version 4 to a request whose body is
// body: X-Amz-Date, the session token, and Authorization over every header
// set on it and host.
func signRequest(r *http.Request, body []byte, c AWSCredentials, region, service string, now time.Time) {
	stamp := now.UTC().Format("20060102T150405Z")
	date := stamp[:8]
	r.Header.Set("X-Amz-Date", stamp)
	if c.SessionToken != "" {
		r.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	headers := map[string]string{"host": r.URL.Host}
	for k, vs := range r.Header {
		headers[strings.ToLower(k)] = strings.Join(vs, ",")
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + strings.Join(strings.Fields(headers[k]), " ") + "\n")
	}
	signed := strings.Join(names, ";")
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{r.Method, uriEncode(path, true), canonicalQuery(r.URL.Query()),
		canonHeaders.String(), signed, sha256Hex(body)}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	toSign := strings.Join([]string{sigAlgorithm, stamp, scope, sha256Hex([]byte(canonical))}, "\n")
	sig := hex.EncodeToString(hmacSHA256(signingKey(c.SecretAccessKey, date, region, service), toSign))
	r.Header.Set("Authorization", sigAlgorithm+" Credential="+c.AccessKeyID+"/"+scope+
		", SignedHeaders="+signed+", Signature="+sig)
}

// presign signs a GET address in its query, as an RDS IAM token is: only
// host is signed, and the body is empty.
func presign(u *url.URL, c AWSCredentials, region, service string, expires time.Duration, now time.Time) string {
	stamp := now.UTC().Format("20060102T150405Z")
	date := stamp[:8]
	scope := date + "/" + region + "/" + service + "/aws4_request"
	q := u.Query()
	q.Set("X-Amz-Algorithm", sigAlgorithm)
	q.Set("X-Amz-Credential", c.AccessKeyID+"/"+scope)
	q.Set("X-Amz-Date", stamp)
	q.Set("X-Amz-Expires", strconv.Itoa(int(expires/time.Second)))
	q.Set("X-Amz-SignedHeaders", "host")
	if c.SessionToken != "" {
		q.Set("X-Amz-Security-Token", c.SessionToken)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	cq := canonicalQuery(q)
	canonical := strings.Join([]string{"GET", uriEncode(path, true), cq, "host:" + u.Host + "\n", "host", sha256Hex(nil)}, "\n")
	toSign := strings.Join([]string{sigAlgorithm, stamp, scope, sha256Hex([]byte(canonical))}, "\n")
	sig := hex.EncodeToString(hmacSHA256(signingKey(c.SecretAccessKey, date, region, service), toSign))
	return u.Host + path + "?" + cq + "&X-Amz-Signature=" + sig
}
