package cli

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/kiyesi/kiyesi/agent/internal/cloudlogin"
)

func onAWS(t *testing.T, a cloudlogin.AWSInstance) {
	t.Helper()
	thisAWS = func() cloudlogin.AWSInstance { return a }
}

func wantAll(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}

// Every printed command is one line a shell can read.
func shellParses(t *testing.T, out string) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		cmd := strings.TrimSpace(line)
		for _, lead := range []string{"aws ", "sudo ", "psql ", "mysql ", "gcloud ", "az ", "vault ", "printf ", "PGPASSWORD=", "rid=", "account=", "curl "} {
			if strings.HasPrefix(cmd, lead) {
				if b, err := exec.Command("sh", "-n", "-c", cmd).CombinedOutput(); err != nil {
					t.Errorf("not one shell line: %s\n%s", cmd, b)
				}
			}
		}
	}
}

// AWS RDS is IAM by default: the role may connect as the one user, the user
// signs in only with tokens, the address checks AWS's certificate.
func TestSetupRDSWithIAM(t *testing.T) {
	fakeServer(t, nil, nil, nil, nil)
	onAWS(t, cloudlogin.AWSInstance{ID: "i-0abc", Account: "123456789012", Region: "eu-west-1", Role: "app-server"})
	_, out, _ := runCLI(t, "databases", "setup", "postgres", "orders", "--host", "orders.c9x.eu-west-1.rds.amazonaws.com")
	wantAll(t, out,
		"read-only, with a 15-minute token from this server's AWS role: no password anywhere",
		"aws rds modify-db-instance --db-instance-identifier orders --enable-iam-database-authentication --apply-immediately",
		"This server's AWS role is app-server.",
		`rid="$(aws rds describe-db-instances --db-instance-identifier orders --query 'DBInstances[0].DbiResourceId' --output text)"`,
		`\"Action\":\"rds-db:connect\",\"Resource\":\"arn:aws:rds-db:eu-west-1:123456789012:dbuser:$rid/kiyesi_ro\"`,
		"https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem",
		"GRANT rds_iam TO kiyesi_ro",
		"url: postgres://kiyesi_ro@orders.c9x.eu-west-1.rds.amazonaws.com:5432/orders?sslmode=verify-full&sslrootcert=/etc/kiyesi/ca/aws-rds.pem",
		"password: aws-iam")
	if strings.Contains(out, "systemd-creds") || strings.Contains(out, "openssl rand") {
		t.Errorf("a password for IAM sign-in:\n%s", out)
	}
	shellParses(t, out)

	// Aurora MySQL, on a server with no role yet: the role is made and attached.
	onAWS(t, cloudlogin.AWSInstance{ID: "i-0abc", Account: "123456789012"})
	_, out, _ = runCLI(t, "databases", "setup", "mysql", "shop", "--host", "shop.cluster-ro-c9x.eu-west-1.rds.amazonaws.com")
	wantAll(t, out,
		"aws rds modify-db-cluster --db-cluster-identifier shop --enable-iam-database-authentication",
		"DBClusters[0].DbClusterResourceId",
		"aws ec2 associate-iam-instance-profile --instance-id i-0abc --iam-instance-profile Name=kiyesi-agent",
		"--role-name kiyesi-agent --policy-name kiyesi-rds-shop",
		"IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS' REQUIRE SSL",
		"url: mysql://kiyesi_ro@shop.cluster-ro-c9x.eu-west-1.rds.amazonaws.com:3306/shop?tls=true&ca=/etc/kiyesi/ca/aws-rds.pem")
	shellParses(t, out)

	// A password, when asked for, on RDS too.
	_, out, _ = runCLI(t, "databases", "setup", "postgres", "orders", "--host", "orders.c9x.eu-west-1.rds.amazonaws.com", "--login", "password")
	wantAll(t, out, "with a random password kept encrypted", "password: credential")
}

func TestSetupAzureWithItsIdentity(t *testing.T) {
	fakeServer(t, nil, nil, nil, nil)
	_, out, _ := runCLI(t, "databases", "setup", "postgres", "orders", "--host", "orders.postgres.database.azure.com")
	wantAll(t, out,
		"with a token from this VM's managed identity: no password anywhere",
		`az vm identity assign --resource-group "<group>" --name "<this VM>"`,
		"pgaadauth_create_principal_with_oid('kiyesi_ro', '<its principal ID>', 'service', false, false)",
		"--resource-type oss-rdbms",
		"url: postgres://kiyesi_ro@orders.postgres.database.azure.com:5432/orders?sslmode=verify-full",
		"password: azure-identity")
	shellParses(t, out)
	_, out, _ = runCLI(t, "databases", "setup", "mysql", "shop", "--host", "shop.mysql.database.azure.com")
	wantAll(t, out, "CREATE AADUSER 'kiyesi_ro' IDENTIFIED BY '<its application ID>'", "url: mysql://kiyesi_ro@shop.mysql.database.azure.com:3306/shop?tls=true")
	shellParses(t, out)
}

func TestSetupCloudSQLWithIAM(t *testing.T) {
	fakeServer(t, nil, nil, nil, nil)
	_, out, _ := runCLI(t, "databases", "setup", "postgres", "orders", "--host", "10.20.0.3", "--login", "gcp-iam")
	wantAll(t, out,
		"with a token from this VM's service account: no password anywhere",
		"cloudsql.iam_authentication=on",
		"--role=roles/cloudsql.instanceUser --condition=",
		"--type=cloud_iam_service_account",
		"url: postgres://<service account name>%40<project>.iam@10.20.0.3:5432/orders?sslmode=verify-ca&sslrootcert=/etc/kiyesi/ca/cloudsql-orders.pem",
		"password: gcp-iam",
		"Put the value each <…> names in its place")
	shellParses(t, out)
	if code, _, _ := runCLI(t, "databases", "setup", "mysql", "shop", "--host", "10.20.0.3", "--login", "gcp-iam"); code == 0 {
		t.Error("Cloud SQL for MySQL with IAM should say it is for PostgreSQL")
	}
}

// Atlas: a certificate by default, the server's AWS role when asked.
func TestSetupAtlasCertificateAndAWS(t *testing.T) {
	fakeServer(t, nil, nil, nil, nil)
	_, out, _ := runCLI(t, "databases", "setup", "mongodb", "shop", "--host", "cluster0.abcde.mongodb.net")
	wantAll(t, out,
		"read-only, with a certificate: no password anywhere",
		"Authentication Method:  Certificate",
		"atlas dbusers create --username kiyesi_ro --x509Type MANAGED --role kiyesiStats@admin --scope cluster0",
		"sudo install -m 600 /dev/null /etc/kiyesi/credentials/shop.pem",
		"url: mongodb+srv://cluster0.abcde.mongodb.net/shop?authSource=%24external&authMechanism=MONGODB-X509&tlsCertificateKeyFile=/etc/kiyesi/credentials/shop.pem")
	if strings.Contains(out, "password: ") || strings.Contains(out, "systemd-ask-password") {
		t.Errorf("a password for a certificate sign-in:\n%s", out)
	}
	shellParses(t, out)
	onAWS(t, cloudlogin.AWSInstance{ID: "i-0abc", Account: "123456789012", Role: "app-server"})
	_, out, _ = runCLI(t, "databases", "setup", "mongodb", "shop", "--host", "cluster0.abcde.mongodb.net", "--login", "aws-iam")
	wantAll(t, out, "AWS IAM Role ARN:       arn:aws:iam::123456789012:role/app-server",
		"url: mongodb+srv://cluster0.abcde.mongodb.net/shop?authSource=%24external&authMechanism=MONGODB-AWS")
}

func TestSetupAWSSecret(t *testing.T) {
	fakeServer(t, nil, nil, nil, nil)
	onAWS(t, cloudlogin.AWSInstance{ID: "i-0abc", Account: "123456789012", Role: "app-server"})
	_, out, _ := runCLI(t, "databases", "setup", "postgres", "orders", "--host", "db.internal", "--login", "aws-secret")
	wantAll(t, out,
		`aws secretsmanager create-secret --name kiyesi/orders --secret-string "$pw" --query ARN --output text`,
		`"Action":"secretsmanager:GetSecretValue","Resource":"<the ARN it printed>"`,
		"password: aws-secret:<the ARN it printed>")
	if strings.Contains(out, "systemd-creds") {
		t.Errorf("kept on the server as well:\n%s", out)
	}
	shellParses(t, out)
}

func TestSetupVault(t *testing.T) {
	fakeServer(t, nil, nil, nil, nil)
	_, out, _ := runCLI(t, "databases", "setup", "postgres", "orders", "--host", "db.internal", "--login", "vault", "--vault", "https://vault.example.com:8200")
	wantAll(t, out,
		"a short-lived user from your Vault for each lease",
		"vault write database/config/orders plugin_name=postgresql-database-plugin allowed_roles=kiyesi-ro",
		"connection_url='postgresql://{{username}}:{{password}}@db.internal:5432/orders?sslmode=verify-full'",
		"default_ttl=1h max_ttl=24h",
		`NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; ALTER ROLE \"{{name}}\" SET default_transaction_read_only = on`,
		`'path "database/creds/kiyesi-ro" { capabilities = ["read"] }' 'path "sys/leases/renew" { capabilities = ["update"] }'`,
		"secret_id_bound_cidrs=203.0.113.24/32",
		"systemd-creds encrypt - /etc/credstore.encrypted/kiyesi.db.vault",
		"'vault:' '  address: https://vault.example.com:8200' '  auth: approle' '  role: <the role ID>'",
		"password: vault:database/creds/kiyesi-ro")
	shellParses(t, out)
	onAWS(t, cloudlogin.AWSInstance{ID: "i-0abc", Account: "123456789012", Role: "app-server"})
	_, out, _ = runCLI(t, "databases", "setup", "mysql", "shop", "--host", "db.internal", "--login", "vault")
	wantAll(t, out, "auth_type=iam bound_iam_principal_arn=arn:aws:iam::123456789012:role/app-server", "'  auth: aws'", "plugin_name=mysql-database-plugin")
	shellParses(t, out)
	for _, args := range [][]string{
		{"postgres", "orders", "--login", "vault"},
		{"postgres", "orders", "--host", "db.internal", "--login", "vault", "--vault", "http://vault.example.com"},
		{"postgres", "orders", "--login", "magic"},
		{"mongodb", "shop", "--host", "cluster0.abcde.mongodb.net", "--login", "vault"},
		{"redis", "cache", "--host", "c.example.com", "--login", "aws-iam"},
	} {
		if code, _, _ := runCLI(t, append([]string{"databases", "setup"}, args...)...); code == 0 {
			t.Errorf("%v: no error", args)
		}
	}
}

// Moving a database set up with a password to its certificate: the steps
// say what its entry must become, keep the role made before, and remove
// the old password once the new way works.
func TestSetupSwitchesFromAPassword(t *testing.T) {
	fakeServer(t, nil, nil, nil, nil)
	old := "databases:\n  - name: test\n    url: mongodb+srv://kiyesi_ro@cluster0.ab1cd.mongodb.net/test\n    password: credential\n    limit: 512MB\n"
	if err := os.WriteFile(setupSettingsPath, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, _ := runCLI(t, "databases", "setup", "mongodb", "test", "--host", "cluster0.ab1cd.mongodb.net")
	wantAll(t, out,
		"If kiyesiStats is there already, from an earlier setup, keep it and go to the next step.",
		"set another way. Open the file (sudo nano "+setupSettingsPath+") and make its entry read exactly as below",
		"url: mongodb+srv://cluster0.ab1cd.mongodb.net/test?authSource=%24external&authMechanism=MONGODB-X509&tlsCertificateKeyFile=/etc/kiyesi/credentials/test.pem",
		"delete the kiyesi_ro user whose method is Password",
		"sudo rm -f /etc/credstore.encrypted/kiyesi.db.test /etc/kiyesi/credentials/test.enc")
	if strings.Contains(out, "check its url says") {
		t.Errorf("asks to check instead of saying what to change:\n%s", out)
	}
	// Set up this way already: nothing to change, nothing to remove.
	now := "databases:\n  - name: test\n    url: mongodb+srv://cluster0.ab1cd.mongodb.net/test?authSource=%24external&authMechanism=MONGODB-X509&tlsCertificateKeyFile=/etc/kiyesi/credentials/test.pem\n"
	if err := os.WriteFile(setupSettingsPath, []byte(now), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, _ = runCLI(t, "databases", "setup", "mongodb", "test", "--host", "cluster0.ab1cd.mongodb.net")
	wantAll(t, out, "It is already in "+setupSettingsPath+" as test, set this way.")
	if strings.Contains(out, "sudo rm -f") {
		t.Errorf("removes a password that is not there:\n%s", out)
	}
}
