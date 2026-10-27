package cloudlogin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Where Google Cloud's and Azure's metadata services are. Tests point them
// at fakes.
var (
	gcpMetadataURL   = "http://metadata.google.internal"
	azureMetadataURL = "http://169.254.169.254"
)

// The token audiences: Cloud SQL's sign-in scope, and Azure's resource for
// its PostgreSQL and MySQL servers.
const (
	gcpSQLScope   = "https://www.googleapis.com/auth/sqlservice.login"
	azureDBTarget = "https://ossrdbms-aad.database.windows.net"
)

// GCPToken is a token for Cloud SQL's IAM sign-in, from the instance's own
// service account: the password for a user named after that account.
func GCPToken(ctx context.Context) (string, error) {
	b, err := gcpMetadata(ctx, "/computeMetadata/v1/instance/service-accounts/default/token?scopes="+url.QueryEscape(gcpSQLScope))
	if err != nil {
		return "", errors.New("this server has no Google Cloud service account: the metadata service did not give a token. Give the VM a service account (the steps from sudo kiyesi databases setup)")
	}
	var t struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &t); err != nil || t.AccessToken == "" {
		return "", errors.New("the metadata service of Google Cloud gave no token")
	}
	return t.AccessToken, nil
}

// GCPIdentityJWT is the instance's signed identity for an audience, which
// Vault's Google Cloud sign-in checks.
func GCPIdentityJWT(ctx context.Context, audience string) (string, error) {
	b, err := gcpMetadata(ctx, "/computeMetadata/v1/instance/service-accounts/default/identity?format=full&audience="+url.QueryEscape(audience))
	if err != nil {
		return "", errors.New("this server has no Google Cloud service account: the metadata service gave no identity")
	}
	return strings.TrimSpace(string(b)), nil
}

func gcpMetadata(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gcpMetadataURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := metaClient.Do(req)
	if err != nil {
		return nil, err
	}
	return read(resp)
}

// AzureToken is a token from the VM's managed identity for a resource:
// Azure Database for PostgreSQL and MySQL take it as the password.
// clientID picks a user-assigned identity; empty is the VM's own.
func AzureToken(ctx context.Context, resource, clientID string) (string, error) {
	if resource == "" {
		resource = azureDBTarget
	}
	q := url.Values{"api-version": {"2018-02-01"}, "resource": {resource}}
	if clientID != "" {
		q.Set("client_id", clientID)
	}
	b, err := azureMetadata(ctx, "/metadata/identity/oauth2/token?"+q.Encode())
	if err != nil {
		return "", errors.New("this server has no Azure managed identity: the metadata service gave no token. Turn on the VM's managed identity (the steps from sudo kiyesi databases setup)")
	}
	var t struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &t); err != nil || t.AccessToken == "" {
		return "", errors.New("the metadata service of Azure gave no token")
	}
	return t.AccessToken, nil
}

// AzureVM is where the VM sits, which Vault's Azure sign-in asks for
// alongside the token.
func AzureVM(ctx context.Context) (subscription, group, name string, err error) {
	b, err := azureMetadata(ctx, "/metadata/instance/compute?api-version=2021-02-01")
	if err != nil {
		return "", "", "", errors.New("the metadata service of Azure did not say which VM this is")
	}
	var c struct {
		SubscriptionID    string `json:"subscriptionId"`
		ResourceGroupName string `json:"resourceGroupName"`
		Name              string `json:"name"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return "", "", "", errors.New("the metadata service of Azure did not say which VM this is")
	}
	return c.SubscriptionID, c.ResourceGroupName, c.Name, nil
}

func azureMetadata(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, azureMetadataURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata", "true")
	resp, err := metaClient.Do(req)
	if err != nil {
		return nil, err
	}
	return read(resp)
}
