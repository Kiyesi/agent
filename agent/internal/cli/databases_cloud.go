package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/kiyesi/kiyesi/agent/internal/cloudlogin"
	"github.com/kiyesi/kiyesi/agent/internal/dbwatch"
)

// thisAWS is what this server is on AWS, for filling in the steps. Tests
// replace it.
var thisAWS = func() cloudlogin.AWSInstance { return cloudlogin.ThisAWSInstance(context.Background()) }

// The ways setup can have Kiyesi sign in.
var setupLogins = map[string]bool{"password": true, "aws-iam": true, "gcp-iam": true, "azure-identity": true,
	"certificate": true, "aws-secret": true, "vault": true}

func validLogin(l string) bool { return l == "" || setupLogins[l] }

// bestLogin is the safest way to sign in where the database is: a token
// from the server's cloud identity on AWS RDS and Azure, a certificate on
// MongoDB Atlas, else the socket or a password kept encrypted ("password").
// Google Cloud SQL has no host name of its own: --login gcp-iam names it.
func (s *setupFor) bestLogin(engine string) string {
	name, _ := provider(s.host)
	switch {
	case name == "AWS RDS" && (engine == "postgres" || engine == "postgresql" || engine == "mysql"):
		return "aws-iam"
	case name == "Azure Database" && (engine == "postgres" || engine == "postgresql" || engine == "mysql"):
		return "azure-identity"
	case name == "MongoDB Atlas":
		return "certificate"
	}
	return "password"
}

// cloud prints the steps for a login with no password kept on the server,
// or a vault's. It says whether it did; "password" is the engine's own steps.
func (s *setupFor) cloud(engine string) (bool, error) {
	pg := engine == "postgres" || engine == "postgresql"
	my := engine == "mysql"
	mongo := engine == "mongodb" || engine == "mongo"
	atlas := strings.HasSuffix(strings.ToLower(s.host), ".mongodb.net")
	need := func(ok bool, what string) error {
		if !ok {
			return usageErr("%s", what)
		}
		return nil
	}
	switch s.login {
	case "password":
		return false, nil
	case "aws-iam":
		if mongo && atlas {
			s.atlasAWS()
			return true, nil
		}
		name, _ := provider(s.host)
		if err := need((pg || my) && name == "AWS RDS", "--login aws-iam is for AWS RDS and Aurora PostgreSQL and MySQL (--host ….rds.amazonaws.com), and MongoDB Atlas"); err != nil {
			return true, err
		}
		s.rdsIAM(pg)
	case "azure-identity":
		name, _ := provider(s.host)
		if err := need((pg || my) && name == "Azure Database", "--login azure-identity is for Azure Database for PostgreSQL and MySQL (--host ….database.azure.com)"); err != nil {
			return true, err
		}
		s.azureIdentity(pg)
	case "gcp-iam":
		if err := need(pg && s.host != "", "--login gcp-iam is for Google Cloud SQL for PostgreSQL: give its address with --host"); err != nil {
			return true, err
		}
		s.cloudSQL()
	case "certificate":
		if err := need(mongo && atlas, "--login certificate is for MongoDB Atlas (--host ….mongodb.net)"); err != nil {
			return true, err
		}
		s.atlasCertificate()
	case "aws-secret", "vault":
		if err := need(s.host != "" || s.login == "aws-secret", "--login vault is for a database your Vault can reach: give its --host"); err != nil {
			return true, err
		}
		if atlas {
			return true, usageErr("MongoDB Atlas signs in with --login certificate or aws-iam, with no password at all")
		}
		if s.login == "vault" {
			return true, s.vault(engine)
		}
		// aws-secret: the engine's own steps, with the password kept in
		// Secrets Manager instead of on this server.
		return false, nil
	}
	return true, nil
}

// passwordSetting is what the settings say about where the password is.
func (s *setupFor) passwordSetting() string {
	if s.login == "aws-secret" {
		return "aws-secret:<the ARN it printed>"
	}
	return "credential"
}

// keep is the step that keeps the new password in $pw: encrypted on this
// server, or in AWS Secrets Manager with the server's role allowed to read
// only that secret.
func (s *setupFor) keep() {
	if s.login != "aws-secret" {
		s.say(s.storeWords(), s.store())
		return
	}
	s.say("Keep it in AWS Secrets Manager, from the same shell (where the AWS CLI is signed in as an admin). It prints the secret's ARN:",
		`aws secretsmanager create-secret --name kiyesi/`+s.db+` --secret-string "$pw" --query ARN --output text`,
		"unset pw")
	role := s.awsRole()
	s.say("Let this server's AWS role read that one secret, and nothing else:",
		`aws iam put-role-policy --role-name `+role+` --policy-name kiyesi-secret-`+s.db+` --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"<the ARN it printed>"}]}'`)
}

// awsRole is the step, when this server has no AWS role yet, that makes one
// and attaches it to the instance; it gives the role's name.
func (s *setupFor) awsRole() string {
	a := thisAWS()
	if a.Role != "" {
		fmt.Fprintf(s.out, "   This server's AWS role is %s.\n", a.Role)
		return a.Role
	}
	id := a.ID
	if id == "" {
		id = `"<this instance ID>"`
		fmt.Fprintln(s.out, "   This server did not answer as an EC2 instance. The agent signs in with the role of the instance it runs on: run it on EC2, with the role below attached.")
	}
	s.say("Admin: give this server an AWS role of its own. It has no rights until the next step:",
		`aws iam create-role --role-name kiyesi-agent --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'`,
		"aws iam create-instance-profile --instance-profile-name kiyesi-agent",
		"aws iam add-role-to-instance-profile --instance-profile-name kiyesi-agent --role-name kiyesi-agent",
		"aws ec2 associate-iam-instance-profile --instance-id "+id+" --iam-instance-profile Name=kiyesi-agent")
	return "kiyesi-agent"
}

// rdsIAM is AWS RDS and Aurora with IAM: a user that signs in only with a
// 15-minute token, which the agent makes from the server's role; the role
// may connect as that one user of that one database, nothing else.
func (s *setupFor) rdsIAM(pg bool) {
	engine, port := "MySQL", 3306
	if pg {
		engine, port = "PostgreSQL", 5432
	}
	labels := strings.Split(strings.ToLower(s.host), ".")
	id := labels[0]
	aurora := len(labels) > 1 && strings.HasPrefix(labels[1], "cluster-")
	region := cloudlogin.RDSRegion(s.host)
	s.intro("the " + engine + " database " + s.db + " on " + s.host + ", read-only, with a 15-minute token from this server's AWS role: no password anywhere")
	fmt.Fprintln(s.out, "Steps marked \"admin\" run on a computer where the AWS CLI is signed in as an admin; the rest on this server.")
	turnOn := "aws rds modify-db-instance --db-instance-identifier " + id + " --enable-iam-database-authentication --apply-immediately"
	resource := "aws rds describe-db-instances --db-instance-identifier " + id + " --query 'DBInstances[0].DbiResourceId' --output text"
	if aurora {
		turnOn = "aws rds modify-db-cluster --db-cluster-identifier " + id + " --enable-iam-database-authentication --apply-immediately"
		resource = "aws rds describe-db-clusters --db-cluster-identifier " + id + " --query 'DBClusters[0].DbClusterResourceId' --output text"
	}
	s.say("Admin: turn on IAM sign-in for the database. It applies without a restart:", turnOn)
	role := s.awsRole()
	a := thisAWS()
	account := a.Account
	accountCmd := ""
	if account == "" {
		account = "$account"
		accountCmd = "account=\"$(aws sts get-caller-identity --query Account --output text)\""
	}
	cmds := []string{}
	if accountCmd != "" {
		cmds = append(cmds, accountCmd)
	}
	cmds = append(cmds, `rid="$(`+resource+`)"`,
		`aws iam put-role-policy --role-name `+role+` --policy-name kiyesi-rds-`+s.db+` --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"rds-db:connect\",\"Resource\":\"arn:aws:rds-db:`+region+`:`+account+`:dbuser:$rid/kiyesi_ro\"}]}"`)
	s.say("Admin: let this server's role sign in as kiyesi_ro on this one database, and nothing else:", cmds...)
	ca := s.caStep()
	hostPort := s.hostPort(port)
	p := strings.Split(hostPort, ":")[1]
	if pg {
		readOnly := "GRANT rds_iam TO kiyesi_ro; ALTER ROLE kiyesi_ro SET default_transaction_read_only = on; GRANT CONNECT ON DATABASE \"" + s.db + "\" TO kiyesi_ro;"
		s.say("Make Kiyesi's user, which signs in only with IAM tokens. It may connect and read sizes and counts, never a row, and every session is read-only. Run it as the database's master user:",
			`psql -v ON_ERROR_STOP=1 "host=`+s.host+` port=`+p+` dbname=`+s.db+` user=<admin> sslmode=verify-full sslrootcert=`+ca+`" -c 'CREATE ROLE `+pgRole+`' -c '`+readOnly+`'`)
		s.config("postgres://kiyesi_ro@"+hostPort+"/"+s.db+"?sslmode=verify-full&sslrootcert="+ca, "aws-iam")
		return
	}
	sql := "CREATE USER 'kiyesi_ro'@'%' IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS' REQUIRE SSL WITH MAX_USER_CONNECTIONS 3; GRANT SHOW VIEW ON `" + s.db + "`.* TO 'kiyesi_ro'@'%';"
	s.say("Make Kiyesi's user, which signs in only with IAM tokens, over TLS. SHOW VIEW on the one database lets it see its tables' sizes, never their rows. Run it as the database's master user:",
		"mysql -h "+s.host+" -P "+p+" -u <admin> -p --ssl-mode=VERIFY_IDENTITY --ssl-ca="+ca+" -e \""+shellDQ(sql)+"\"")
	s.config("mysql://kiyesi_ro@"+hostPort+"/"+s.db+"?tls=true&ca="+ca, "aws-iam")
}

// azureIdentity is Azure Database with Microsoft Entra: the VM's managed
// identity is the database user, and its token the password.
func (s *setupFor) azureIdentity(pg bool) {
	engine, port := "MySQL", 3306
	if pg {
		engine, port = "PostgreSQL", 5432
	}
	hostPort := s.hostPort(port)
	p := strings.Split(hostPort, ":")[1]
	s.intro("the Azure Database for " + engine + " database " + s.db + " on " + s.host + ", read-only, with a token from this VM's managed identity: no password anywhere")
	fmt.Fprintln(s.out, "Steps marked \"admin\" run on a computer where the Azure CLI (az) is signed in as an admin; the rest on this server.")
	s.say("Admin: turn on this VM's own identity (system-assigned managed identity), and note its IDs:",
		`az vm identity assign --resource-group "<group>" --name "<this VM>"`,
		`az vm show --resource-group "<group>" --name "<this VM>" --query identity.principalId --output tsv`,
		`az ad sp show --id "<the ID it printed>" --query appId --output tsv`)
	s.say("In the Azure portal, on the database server: Security, Authentication. Choose " + engine + " and Microsoft Entra authentication, add yourself as a Microsoft Entra admin, then Save.")
	// The admin's own sign-in token, asked of az when the command runs.
	adminToken := `"$(az account get-access-token --resource-type oss-rdbms --query accessToken --output tsv)"` // #nosec G101 -- a shell command that asks az for a token, not a credential
	if pg {
		sql := "SELECT * FROM pgaadauth_create_principal_with_oid('kiyesi_ro', '<its principal ID>', 'service', false, false); ALTER ROLE kiyesi_ro CONNECTION LIMIT 3; ALTER ROLE kiyesi_ro SET default_transaction_read_only = on; GRANT CONNECT ON DATABASE \"" + s.db + "\" TO kiyesi_ro;"
		s.say("Admin: make Kiyesi's user for this VM's identity, signed in as the Entra admin. It may connect and read sizes and counts, never a row, and every session is read-only:",
			`PGPASSWORD=`+adminToken+` psql -v ON_ERROR_STOP=1 "host=`+s.host+` port=`+p+` dbname=postgres user=<your Entra admin name> sslmode=verify-full" -c "`+shellDQ(sql)+`"`)
		s.config("postgres://kiyesi_ro@"+hostPort+"/"+s.db+"?sslmode=verify-full", "azure-identity")
		return
	}
	sql := "SET aad_auth_validate_oids_in_tenant = OFF; CREATE AADUSER 'kiyesi_ro' IDENTIFIED BY '<its application ID>'; GRANT SHOW VIEW ON `" + s.db + "`.* TO 'kiyesi_ro'@'%';"
	s.say("Admin: make Kiyesi's user for this VM's identity, signed in as the Entra admin. SHOW VIEW on the one database lets it see its tables' sizes, never their rows:",
		`mysql -h `+s.host+` -P `+p+` -u "<your Entra admin name>" --enable-cleartext-plugin --ssl-mode=VERIFY_IDENTITY --password=`+adminToken+` -e "`+shellDQ(sql)+`"`)
	s.config("mysql://kiyesi_ro@"+hostPort+"/"+s.db+"?tls=true", "azure-identity")
}

// cloudSQL is Google Cloud SQL for PostgreSQL with IAM: the VM's service
// account is the database user, and its token the password.
func (s *setupFor) cloudSQL() {
	hostPort := s.hostPort(5432)
	ca := caDir + "/cloudsql-" + s.db + ".pem"
	user := "<service account name>@<project>.iam"
	s.intro("the Cloud SQL for PostgreSQL database " + s.db + " on " + s.host + ", read-only, with a token from this VM's service account: no password anywhere")
	fmt.Fprintln(s.out, "Steps marked \"admin\" run on a computer where gcloud is signed in as an admin; the rest on this server.")
	s.say("This VM's service account, and whether its access scopes allow Cloud SQL sign-in (cloud-platform or sqlservice.login):",
		"curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email; echo",
		"curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes")
	fmt.Fprintln(s.out, "   If neither scope is listed, stop the VM and add https://www.googleapis.com/auth/sqlservice.login to its scopes (gcloud compute instances set-service-account), keeping the others.")
	s.say("Admin: turn on IAM sign-in for the instance. The list given replaces the instance's flags, so include any it already has (gcloud sql instances describe <instance> --format='value(settings.databaseFlags)'):",
		`gcloud sql instances patch "<instance>" --database-flags=cloudsql.iam_authentication=on`)
	s.say("Admin: let the service account sign in to this one instance, and make its database user:",
		`gcloud projects add-iam-policy-binding "<project>" --member="serviceAccount:<service account email>" --role=roles/cloudsql.instanceUser --condition='expression=resource.name=="projects/<project>/instances/<instance>",title=kiyesi-one-instance'`,
		`gcloud sql users create "<service account email, without .gserviceaccount.com>" --instance="<instance>" --type=cloud_iam_service_account`)
	s.say("Cloud SQL signs its certificate with the instance's own authority. Admin: gcloud sql instances describe <instance> --format='value(serverCaCert.cert)'. Copy what it prints, run this here, paste it, then press Ctrl-D:",
		"sudo install -d -m 755 "+caDir, "sudo tee "+ca+" >/dev/null")
	fmt.Fprintln(s.out, "   Its certificate names the instance, not its address, so the address checks it against that authority (verify-ca), which only this instance's certificate has.")
	readOnly := `ALTER ROLE "` + user + `" CONNECTION LIMIT 3; ALTER ROLE "` + user + `" SET default_transaction_read_only = on; GRANT CONNECT ON DATABASE "` + s.db + `" TO "` + user + `";`
	s.say("Give it the smallest rights, as the database's admin (postgres), from here: it may connect and read sizes and counts, never a row, and every session is read-only:",
		`psql -v ON_ERROR_STOP=1 "host=`+s.host+` port=`+strings.Split(hostPort, ":")[1]+` dbname=`+s.db+` user=postgres sslmode=verify-ca sslrootcert=`+ca+`" -c '`+readOnly+`'`)
	s.config("postgres://<service account name>%40<project>.iam@"+hostPort+"/"+s.db+"?sslmode=verify-ca&sslrootcert="+ca, "gcp-iam")
}

// atlasRole is the custom role that may only read the database's size and
// the cluster's status, made in Atlas's website.
func (s *setupFor) atlasRole() {
	s.say("At cloud.mongodb.com, open this cluster's project, then in the sidebar Security, Database & Network Access, and the Custom Roles tab. Add New Custom Role:",
		"Name:     kiyesiStats",
		"Actions:  dbStats, on the database "+s.db,
		"          serverStatus, a global action (for the whole cluster)",
		"Save it. Nothing else: it cannot read a document.")
	fmt.Fprintln(s.out, "   With the Atlas CLI instead: atlas customDbRoles create kiyesiStats --privilege DB_STATS@"+s.db+",SERVER_STATUS")
}

// atlasAccess is the step that lists this server's address in Atlas.
func (s *setupFor) atlasAccess() {
	ip := publicIPv4()
	where := "this server's public address (curl -4s https://checkip.amazonaws.com shows it)"
	if ip != "" {
		where = "this server's public address, " + ip + ","
	}
	s.say("In Atlas, on the IP Access List tab, " + where + " must be listed; if it is not, Add IP Address with it alone, then Confirm. When an app on this server already uses this cluster, it is there already.")
}

// atlasCertificate is MongoDB Atlas with an X.509 certificate Atlas makes:
// no password exists, and the certificate stays on this server, root only.
func (s *setupFor) atlasCertificate() {
	cluster := strings.Split(strings.ToLower(s.host), ".")[0]
	pem := dbwatch.OwnCredentialsDir + "/" + s.db + ".pem"
	s.intro("the MongoDB Atlas database " + s.db + " on " + s.host + ", read-only, with a certificate: no password anywhere")
	fmt.Fprintln(s.out, "Steps 1 and 2 are in Atlas's website: Atlas undoes a user made any other way. The rest are on this server.")
	s.atlasRole()
	s.say("On the Database Users tab, Add New Database User:",
		"Authentication Method:  Certificate",
		"Username:               kiyesi_ro",
		"Certificate Expiration: 12 months",
		"Download certificate when user is added: on",
		"Privileges:             under Custom Roles, only kiyesiStats",
		"Restrict Access to Specific Clusters: on, with only "+cluster,
		"Then Add User. Atlas downloads the certificate (a .pem file) this once.")
	fmt.Fprintln(s.out, "   With the Atlas CLI instead: atlas dbusers create --username kiyesi_ro --x509Type MANAGED --role kiyesiStats@admin --scope "+cluster+", then atlas dbusers certs create --username kiyesi_ro --monthsUntilExpiration 12 > kiyesi_ro.pem")
	s.say("Keep the certificate on this server, readable by root only. Open the downloaded file, copy all of it, run this, paste it, then press Ctrl-D:",
		"sudo install -d -m 700 "+dbwatch.OwnCredentialsDir,
		"sudo install -m 600 /dev/null "+pem,
		"sudo tee "+pem+" >/dev/null")
	fmt.Fprintln(s.out, "   Then delete the downloaded file from your computer.")
	s.atlasAccess()
	s.config("mongodb+srv://"+s.host+"/"+s.db+"?authSource=%24external&authMechanism=MONGODB-X509&tlsCertificateKeyFile="+pem, "")
	fmt.Fprintln(s.out, "Before the certificate's 12 months end, download a new one for kiyesi_ro in Atlas and repeat step 3.")
}

// atlasAWS is MongoDB Atlas signed in with the server's AWS role: the
// MongoDB driver asks the instance for the role's keys itself.
func (s *setupFor) atlasAWS() {
	cluster := strings.Split(strings.ToLower(s.host), ".")[0]
	s.intro("the MongoDB Atlas database " + s.db + " on " + s.host + ", read-only, with this server's AWS role: no password anywhere")
	s.atlasRole()
	role := s.awsRole()
	account := thisAWS().Account
	if account == "" {
		account = "<your AWS account ID>"
	}
	s.say("In Atlas, on the Database Users tab, Add New Database User:",
		"Authentication Method:  AWS IAM",
		"AWS IAM Type:           IAM Role",
		"AWS IAM Role ARN:       arn:aws:iam::"+account+":role/"+role,
		"Privileges:             under Custom Roles, only kiyesiStats",
		"Restrict Access to Specific Clusters: on, with only "+cluster,
		"Then Add User.")
	s.atlasAccess()
	s.config("mongodb+srv://"+s.host+"/"+s.db+"?authSource=%24external&authMechanism=MONGODB-AWS", "")
}

// vaultCreation is the statements Vault's database engine runs to make each
// short-lived user, with the rights the guide gives kiyesi_ro, and the
// plugin and address Vault reaches the database with.
func (s *setupFor) vaultCreation(engine, host string) (plugin, addr, statements string, err error) {
	switch engine {
	case "postgres", "postgresql":
		return "postgresql-database-plugin", "postgresql://{{username}}:{{password}}@" + host + "/" + s.db + "?sslmode=verify-full",
			`CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' CONNECTION LIMIT 3 NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; ALTER ROLE "{{name}}" SET default_transaction_read_only = on; GRANT CONNECT ON DATABASE "` + s.db + `" TO "{{name}}";`, nil
	case "mysql", "mariadb":
		return "mysql-database-plugin", "{{username}}:{{password}}@tcp(" + host + ")/",
			"CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}' WITH MAX_USER_CONNECTIONS 3; GRANT SHOW VIEW ON `" + s.db + "`.* TO '{{name}}'@'%';", nil
	case "mongodb", "mongo":
		return "mongodb-database-plugin", "mongodb://{{username}}:{{password}}@" + host + "/admin?tls=true",
			`{"db":"admin","roles":[{"role":"kiyesiStats","db":"admin"}]}`, nil
	case "redis", "valkey":
		return "redis-database-plugin", "", `["-@all","+info","+ping"]`, nil
	}
	return "", "", "", usageErr("%q is not an engine Kiyesi watches: postgres, mysql, mariadb, mongodb or redis", engine)
}

// vault is a short-lived read-only user from Vault's database engine for
// each lease: Vault makes it, the agent renews it and takes a new one when
// it ends. The server signs in to Vault with its cloud identity, or AppRole.
func (s *setupFor) vault(engine string) error {
	def := map[string]int{"postgres": 5432, "postgresql": 5432, "mysql": 3306, "mariadb": 3306, "mongodb": 27017, "mongo": 27017, "redis": 6379, "valkey": 6379}[engine]
	host := s.hostPort(def)
	if s.host == "" && s.addr != "" {
		host = s.addr
	}
	plugin, conn, creation, err := s.vaultCreation(engine, host)
	if err != nil {
		return err
	}
	a := thisAWS()
	auth := s.vaultAuth
	if auth == "" {
		auth = "approle"
		if a.ID != "" {
			auth = "aws"
		}
	}
	addr := s.vaultAddr
	if addr == "" {
		addr = "https://<your Vault address>:8200"
	}
	s.intro("the " + engine + " database " + s.db + ", read-only, with a short-lived user from your Vault for each lease: no password kept on this server")
	fmt.Fprintln(s.out, "Steps marked \"Vault admin\" run where the vault command is signed in with rights to set up secrets engines, policies and sign-in methods.")
	cfg := "vault write database/config/" + s.db + " plugin_name=" + plugin + ` allowed_roles=kiyesi-ro username="<Vault admin user for this database>" password="<its password>"`
	if conn != "" {
		cfg += " connection_url='" + conn + "'"
	} else {
		cfg += " host=" + strings.Split(host, ":")[0] + " port=" + strings.Split(host, ":")[1] + " tls=true"
	}
	if engine == "mongodb" || engine == "mongo" {
		s.say("Make the role Kiyesi's users get, which may only read the database's size and the server's status, as the database's admin:",
			`mongosh "mongodb://`+host+`/admin?tls=true" -u <admin> --eval 'db.getSiblingDB("admin").createRole({ role: "kiyesiStats", privileges: [ { resource: { db: "`+s.db+`", collection: "" }, actions: ["dbStats"] }, { resource: { cluster: true }, actions: ["serverStatus"] } ], roles: [] })'`)
	}
	s.say("Vault admin: let Vault make users on this database (once; skip the first line if the database engine is on already):",
		"vault secrets enable database", cfg)
	s.say("Vault admin: the role Kiyesi's users come from: each lives an hour, renewable up to a day, with the rights the guide gives kiyesi_ro and no more:",
		`vault write database/roles/kiyesi-ro db_name=`+s.db+` default_ttl=1h max_ttl=24h creation_statements="`+shellDQ(creation)+`"`)
	s.say("Vault admin: a policy that may only take such a user and renew it:",
		`printf '%s\n' 'path "database/creds/kiyesi-ro" { capabilities = ["read"] }' 'path "sys/leases/renew" { capabilities = ["update"] }' | vault policy write kiyesi -`)
	settings := []string{"vault:", "  address: " + addr, "  auth: " + auth, "  role: kiyesi"}
	switch auth {
	case "aws":
		role := a.Role
		account := a.Account
		if role == "" {
			role = s.awsRole()
		}
		if account == "" {
			account = `"<your AWS account ID>"`
		}
		s.say("Vault admin: let this server sign in with its AWS role (skip the first line if AWS sign-in is on already):",
			"vault auth enable aws",
			"vault write auth/aws/role/kiyesi auth_type=iam bound_iam_principal_arn=arn:aws:iam::"+account+":role/"+role+" token_policies=kiyesi token_ttl=1h")
	case "gcp":
		s.say("Vault admin: let this server sign in with its Google Cloud service account (skip the first line if Google Cloud sign-in is on already):",
			"vault auth enable gcp",
			`vault write auth/gcp/role/kiyesi type=gce bound_service_accounts="<this VM service account email>" token_policies=kiyesi token_ttl=1h`)
	case "azure":
		s.say("Vault admin: let this server sign in with its Azure managed identity (skip the first line if Azure sign-in is on already):",
			"vault auth enable azure",
			`vault write auth/azure/role/kiyesi bound_service_principal_ids="<this VM principal ID>" token_policies=kiyesi token_ttl=1h`)
	case "approle":
		ip := publicIPv4()
		if ip == "" {
			ip = "<this server address>"
		}
		s.say("Vault admin: an AppRole for this server, usable only from its address (skip the first line if AppRole is on already). The second command prints the role ID, the third a secret ID:",
			"vault auth enable approle",
			"vault write auth/approle/role/kiyesi token_policies=kiyesi token_ttl=1h secret_id_bound_cidrs="+ip+"/32 token_bound_cidrs="+ip+"/32",
			"vault read -field=role_id auth/approle/role/kiyesi/role-id",
			"vault write -f -field=secret_id auth/approle/role/kiyesi/secret-id")
		settings[3] = "  role: <the role ID>"
		v := *s
		v.db = "vault"
		s.say("Keep the secret ID encrypted on this server; paste it when asked, it is not shown or kept in your history:", v.storeTyped())
	}
	s.say("Add your Vault to Kiyesi's settings, "+setupSettingsPath+" (it names no secret):",
		printfLines(settings...)+" | sudo tee -a "+setupSettingsPath+" >/dev/null")
	scheme := map[string]string{"postgres": "postgres", "postgresql": "postgres", "mysql": "mysql", "mariadb": "mysql", "mongodb": "mongodb", "mongo": "mongodb", "redis": "rediss", "valkey": "rediss"}[engine]
	url := scheme + "://kiyesi_ro@" + host + "/" + s.db
	switch scheme {
	case "postgres":
		url += "?sslmode=verify-full"
	case "mysql":
		url += "?tls=true"
	case "mongodb":
		url += "?authSource=admin&tls=true"
	case "rediss":
		url = scheme + "://kiyesi_ro@" + host
	}
	s.config(url, "vault:database/creds/kiyesi-ro")
	return nil
}
