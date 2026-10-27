package cloudlogin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Where the AWS services are. Tests point them at fakes.
var (
	awsMetadataURL = "http://169.254.169.254"
	// secretsURL is Secrets Manager's address for a region.
	secretsURL = func(region string) string { return "https://secretsmanager." + region + ".amazonaws.com/" }
	stsURL     = "https://sts.amazonaws.com/"
	// clock is the time signatures are made at.
	clock = time.Now
)

// client is for the cloud APIs, through the server's proxy if it has one;
// metaClient is for the metadata services, which are on the machine's own
// network and must never be asked through a proxy.
var (
	client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}}
	metaClient = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		ResponseHeaderTimeout: 5 * time.Second,
	}}
)

// read reads a small answer, refusing a large one.
func read(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return b, &httpError{status: resp.StatusCode, body: b}
	}
	return b, nil
}

type httpError struct {
	status int
	body   []byte
}

// Error never repeats the answer's body, which may hold a secret.
func (e *httpError) Error() string { return fmt.Sprintf("it answered %d", e.status) }

// AWSCredentialsFor finds the server's AWS keys: the AWS_ environment
// variables when set, else the instance role's keys from the instance
// metadata service (IMDSv2, with its session token).
func AWSCredentialsFor(ctx context.Context) (AWSCredentials, error) {
	if id, secret := os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"); id != "" && secret != "" {
		return AWSCredentials{AccessKeyID: id, SecretAccessKey: secret, SessionToken: os.Getenv("AWS_SESSION_TOKEN")}, nil
	}
	token, err := imdsToken(ctx)
	if err != nil {
		return AWSCredentials{}, errors.New("this server has no AWS role: the instance metadata service did not answer. Attach an IAM role to the instance (the steps from sudo kiyesi databases setup)")
	}
	role, err := imdsGet(ctx, token, "/latest/meta-data/iam/security-credentials/")
	if err != nil || strings.TrimSpace(string(role)) == "" {
		return AWSCredentials{}, errors.New("this server has no AWS role attached. Attach the IAM role from sudo kiyesi databases setup to the instance")
	}
	name := strings.TrimSpace(strings.SplitN(string(role), "\n", 2)[0])
	b, err := imdsGet(ctx, token, "/latest/meta-data/iam/security-credentials/"+url.PathEscape(name))
	if err != nil {
		return AWSCredentials{}, fmt.Errorf("the keys of the server's AWS role %s could not be read", name)
	}
	var c struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
		Expiration      time.Time
	}
	if err := json.Unmarshal(b, &c); err != nil || c.AccessKeyID == "" {
		return AWSCredentials{}, fmt.Errorf("the keys of the server's AWS role %s could not be read", name)
	}
	return AWSCredentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.Token, Expires: c.Expiration}, nil
}

func imdsToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, awsMetadataURL+"/latest/api/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "300")
	resp, err := metaClient.Do(req)
	if err != nil {
		return "", err
	}
	b, err := read(resp)
	return string(b), err
}

func imdsGet(ctx context.Context, token, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, awsMetadataURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)
	resp, err := metaClient.Do(req)
	if err != nil {
		return nil, err
	}
	return read(resp)
}

// AWSRegion is the region the server runs in, from AWS_REGION or the
// instance metadata service.
func AWSRegion(ctx context.Context) string {
	if r := os.Getenv("AWS_REGION"); r != "" {
		return r
	}
	if r := os.Getenv("AWS_DEFAULT_REGION"); r != "" {
		return r
	}
	token, err := imdsToken(ctx)
	if err != nil {
		return ""
	}
	b, err := imdsGet(ctx, token, "/latest/meta-data/placement/region")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

var rdsHost = regexp.MustCompile(`\.([a-z]{2}(?:-gov)?-[a-z]+-\d)\.rds\.amazonaws\.com(?:\.cn)?$`)

// RDSRegion is the region in an RDS or Aurora host name, such as eu-west-1
// in orders.c9x.eu-west-1.rds.amazonaws.com.
func RDSRegion(host string) string {
	if m := rdsHost.FindStringSubmatch(strings.ToLower(host)); m != nil {
		return m[1]
	}
	return ""
}

// RDSToken makes an RDS IAM token: a 15-minute password that AWS checks
// against the server role's right to connect as this one database user.
// It is made on the server; nothing is asked of AWS for it.
func RDSToken(c AWSCredentials, host, port, user, region string) string {
	u := &url.URL{Scheme: "https", Host: net.JoinHostPort(host, port), Path: "/"}
	q := url.Values{}
	q.Set("Action", "connect")
	q.Set("DBUser", user)
	u.RawQuery = q.Encode()
	return presign(u, c, region, "rds-db", 15*time.Minute, clock())
}

var secretARN = regexp.MustCompile(`^arn:aws[a-z-]*:secretsmanager:([a-z0-9-]+):`)

// AWSSecret reads one secret from AWS Secrets Manager with the server's
// role: the password itself, or the "password" field of an RDS-style JSON
// secret. The region is the ARN's, else fallback's.
func AWSSecret(ctx context.Context, c AWSCredentials, id, fallbackRegion string) (string, error) {
	region := fallbackRegion
	if m := secretARN.FindStringSubmatch(id); m != nil {
		region = m[1]
	}
	if region == "" {
		return "", errors.New("the secret's region is not known: give its whole ARN (arn:aws:secretsmanager:region:…)")
	}
	body, _ := json.Marshal(map[string]string{"SecretId": id})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, secretsURL(region), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	signRequest(req, body, c, region, "secretsmanager", clock())
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("AWS Secrets Manager could not be reached")
	}
	b, err := read(resp)
	if err != nil {
		if h, ok := err.(*httpError); ok && h.status == http.StatusBadRequest && bytes.Contains(h.body, []byte("AccessDenied")) {
			return "", errors.New("the server's AWS role may not read this secret: give it secretsmanager:GetSecretValue on the secret (the policy from sudo kiyesi databases setup)")
		}
		return "", fmt.Errorf("AWS Secrets Manager refused: %v", err)
	}
	var out struct {
		SecretString string `json:"SecretString"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.SecretString == "" {
		return "", errors.New("the secret holds no text: store the password as text, or as JSON with a password field")
	}
	var fields struct {
		Password string `json:"password"`
	}
	if strings.HasPrefix(strings.TrimSpace(out.SecretString), "{") {
		if json.Unmarshal([]byte(out.SecretString), &fields) == nil && fields.Password != "" {
			return fields.Password, nil
		}
		return "", errors.New("the secret is JSON with no password field")
	}
	return out.SecretString, nil
}

// VaultAWSLogin is the body Vault's AWS sign-in takes: an STS
// GetCallerIdentity request signed with the server role's keys, which
// Vault sends on to AWS to learn who is asking. serverID, when set, is
// Vault's own name in the request, so it cannot be replayed to another.
func VaultAWSLogin(c AWSCredentials, role, serverID string) (map[string]string, error) {
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	req, err := http.NewRequest(http.MethodPost, stsURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	if serverID != "" {
		req.Header.Set("X-Vault-AWS-IAM-Server-ID", serverID)
	}
	signRequest(req, body, c, "us-east-1", "sts", clock())
	headers, err := json.Marshal(req.Header)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"role":                    role,
		"iam_http_request_method": http.MethodPost,
		"iam_request_url":         base64.StdEncoding.EncodeToString([]byte(stsURL)),
		"iam_request_body":        base64.StdEncoding.EncodeToString(body),
		"iam_request_headers":     base64.StdEncoding.EncodeToString(headers),
	}, nil
}

// AWSInstance is what this server is on AWS, for filling in the setup
// steps: its instance, account, region and the role attached, if any.
// Each is empty when the instance metadata service does not say.
type AWSInstance struct {
	ID, Account, Region, Role string
}

// ThisAWSInstance reads it from the instance metadata service, quickly:
// off AWS it gives an empty one.
func ThisAWSInstance(ctx context.Context) AWSInstance {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var a AWSInstance
	token, err := imdsToken(ctx)
	if err != nil {
		return a
	}
	if b, err := imdsGet(ctx, token, "/latest/dynamic/instance-identity/document"); err == nil {
		var doc struct {
			InstanceID string `json:"instanceId"`
			AccountID  string `json:"accountId"`
			Region     string `json:"region"`
		}
		if json.Unmarshal(b, &doc) == nil {
			a.ID, a.Account, a.Region = doc.InstanceID, doc.AccountID, doc.Region
		}
	}
	if b, err := imdsGet(ctx, token, "/latest/meta-data/iam/security-credentials/"); err == nil {
		a.Role = strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
	}
	return a
}
